"""
Project Mycelium – Canary Token Server (Phase 4)

Exposes two endpoints:
  POST /token/register  – called by Spores to register a new token
  GET  /c/<token>       – the trigger URL embedded in fake data

When an attacker retrieves /c/<token>, the server:
  1. Logs the hit (IP, User-Agent, Referer, timestamp)
  2. Fires a NATS canary.hit event
  3. Optionally sends a webhook / email alert
"""
import asyncio
import json
import os
import time
import smtplib
import structlog
import nats
import asyncpg
import httpx
from aiohttp import web
from email.message import EmailMessage

log = structlog.get_logger()

DB_URL       = os.getenv("DB_URL",       "postgresql://mycelium:mycelium_secret@postgres:5432/mycelium")
NATS_URL     = os.getenv("NATS_URL",     "nats://nats:4222")
NATS_TOKEN   = os.getenv("NATS_TOKEN",   "mycelium_rhizome_token_2025")
WEBHOOK_URL  = os.getenv("WEBHOOK_URL",  "")
ALERT_EMAIL  = os.getenv("ALERT_EMAIL",  "")
PUBLIC_HOST  = os.getenv("PUBLIC_HOST",  "localhost")
PORT         = int(os.getenv("PORT",     "9999"))

# In-memory token cache for fast lookup (populated on startup)
_token_cache: dict[str, dict] = {}


class CanaryServer:
    def __init__(self):
        self._pool = None
        self._nc   = None

    async def start(self):
        self._pool = await asyncpg.create_pool(DB_URL, min_size=2, max_size=5)
        self._nc   = await nats.connect(NATS_URL, token=NATS_TOKEN,
                                         name="canary_server",
                                         max_reconnect_attempts=-1)

        # Pre-load existing tokens into memory
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT token_value, token_id::text, spore_id, token_type FROM canary_tokens"
            )
            for row in rows:
                _token_cache[row["token_value"]] = dict(row)

        log.info("canary_server.started", tokens_loaded=len(_token_cache), port=PORT)

        app = web.Application()
        app.router.add_post("/token/register", self.handle_register)
        app.router.add_get("/c/{token}",        self.handle_token_hit)
        app.router.add_get("/health",           self.handle_health)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "0.0.0.0", PORT)
        await site.start()

        # Keep alive
        while True:
            await asyncio.sleep(3600)

    # ── Register endpoint ─────────────────────────────────────────────────────

    async def handle_register(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "invalid json"}, status=400)

        token_value = body.get("token_value")
        token_type  = body.get("token_type",  "url")
        spore_id    = body.get("spore_id",    "unknown")
        embedded_in = body.get("embedded_in", "payload")

        if not token_value:
            return web.json_response({"error": "token_value required"}, status=400)

        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO canary_tokens
                  (token_value, token_type, spore_id, embedded_in)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (token_value) DO NOTHING
                RETURNING token_id::text
                """,
                token_value, token_type, spore_id, embedded_in,
            )

        if row:
            _token_cache[token_value] = {
                "token_value": token_value,
                "token_id":    row["token_id"],
                "spore_id":    spore_id,
                "token_type":  token_type,
            }

        trigger_url = f"http://{PUBLIC_HOST}:{PORT}/c/{token_value}"
        return web.json_response({"status": "ok", "trigger_url": trigger_url})

    # ── Token hit endpoint ────────────────────────────────────────────────────

    async def handle_token_hit(self, request: web.Request) -> web.Response:
        token_value = request.match_info["token"]
        source_ip   = request.remote or "0.0.0.0"
        user_agent  = request.headers.get("User-Agent",  "")
        referer     = request.headers.get("Referer",     "")

        token_meta = _token_cache.get(token_value)

        if not token_meta:
            # Unknown token – still log it (may be a repeat hit)
            log.warning("canary.unknown_token", token=token_value, ip=source_ip)
            return web.Response(status=404, text="Not Found")

        log.warning("canary.HIT",
                     token=token_value[:8] + "...",
                     ip=source_ip,
                     ua=user_agent[:80],
                     spore=token_meta.get("spore_id"))

        # Persist hit
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO canary_hits
                  (token_id, source_ip, user_agent, referer)
                VALUES ($1::uuid, $2::inet, $3, $4)
                """,
                token_meta["token_id"], source_ip, user_agent, referer,
            )
            await conn.execute(
                """
                UPDATE canary_tokens
                SET triggered = TRUE, triggered_at = NOW()
                WHERE token_value = $1
                """,
                token_value,
            )

        # Publish NATS event
        await self._nc.publish("canary.hit", json.dumps({
            "token_value":  token_value,
            "token_id":     token_meta["token_id"],
            "spore_id":     token_meta.get("spore_id"),
            "source_ip":    source_ip,
            "user_agent":   user_agent,
            "timestamp":    time.time(),
        }).encode())

        # Fire alerts in background
        asyncio.create_task(self._fire_alerts(source_ip, user_agent, token_meta))

        # Return a convincing 200 to avoid tipping off the attacker
        return web.Response(
            status=200,
            content_type="application/json",
            text=json.dumps({"status": "ok", "version": "1.0.0"}),
        )

    async def handle_health(self, _request: web.Request) -> web.Response:
        return web.json_response({"status": "healthy",
                                   "tokens": len(_token_cache)})

    # ── Alerting ──────────────────────────────────────────────────────────────

    async def _fire_alerts(self, source_ip: str, user_agent: str, meta: dict):
        msg_body = (
            f"🚨 Canary Token Triggered!\n\n"
            f"Attacker IP : {source_ip}\n"
            f"User-Agent  : {user_agent}\n"
            f"Spore       : {meta.get('spore_id', 'unknown')}\n"
            f"Token ID    : {meta.get('token_id', '')}\n"
            f"Time        : {__import__('datetime').datetime.utcnow().isoformat()}Z\n"
        )

        if WEBHOOK_URL:
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    await client.post(WEBHOOK_URL, json={
                        "text":       msg_body,
                        "source_ip":  source_ip,
                        "spore_id":   meta.get("spore_id"),
                    })
                log.info("canary.webhook_sent")
            except Exception as e:
                log.warning("canary.webhook_failed", error=str(e))

        if ALERT_EMAIL:
            try:
                em = EmailMessage()
                em["Subject"] = f"[Mycelium] Canary Hit from {source_ip}"
                em["From"]    = "mycelium@localhost"
                em["To"]      = ALERT_EMAIL
                em.set_content(msg_body)
                with smtplib.SMTP("localhost") as smtp:
                    smtp.send_message(em)
                log.info("canary.email_sent")
            except Exception as e:
                log.warning("canary.email_failed", error=str(e))


async def main():
    structlog.configure(processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(),
    ])
    server = CanaryServer()
    await server.start()


if __name__ == "__main__":
    asyncio.run(main())
