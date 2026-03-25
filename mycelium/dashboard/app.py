"""
Project Mycelium – Dashboard Backend (Phase 5)
FastAPI server that streams real-time data to the React frontend via SSE.
"""
import asyncio
import json
import os
import time
import structlog
import asyncpg
import nats
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, StreamingResponse
from contextlib import asynccontextmanager

log = structlog.get_logger()

DB_URL   = os.getenv("DB_URL",   "postgresql://mycelium:mycelium_secret@postgres:5432/mycelium")
NATS_URL = os.getenv("NATS_URL", "nats://nats:4222")
NATS_TOKEN = "mycelium_rhizome_token_2025"

# Global state
_pool: asyncpg.Pool = None
_nc   = None
_sse_subscribers: list[asyncio.Queue] = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _pool, _nc
    _pool = await asyncpg.create_pool(DB_URL, min_size=2, max_size=10)
    _nc   = await nats.connect(NATS_URL, token=NATS_TOKEN, name="dashboard")

    # Subscribe to all Mycelium subjects and forward to SSE
    async def forward(msg):
        subject = msg.subject
        try:
            data = json.loads(msg.data.decode())
        except Exception:
            data = {}
        event = {"subject": subject, "data": data, "ts": time.time()}
        dead  = []
        for q in _sse_subscribers:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            _sse_subscribers.remove(q)

    await _nc.subscribe("threat.alert",   cb=forward)
    await _nc.subscribe("threat.level",   cb=forward)
    await _nc.subscribe("canary.hit",     cb=forward)
    await _nc.subscribe("command.>",      cb=forward)
    await _nc.subscribe("metrics.spore.>", cb=forward)

    log.info("dashboard.started")
    yield

    await _nc.drain()
    await _pool.close()


app = FastAPI(title="Project Mycelium Dashboard", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])


# ── REST endpoints ────────────────────────────────────────────────────────────

@app.get("/api/spores")
async def get_spores():
    async with _pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT spore_id, spore_type, ip_address::text, protocols,
                      banner, status, spawned_at, last_heartbeat, is_dynamic
               FROM spores ORDER BY spawned_at DESC"""
        )
    return [dict(r) for r in rows]


@app.get("/api/threats/recent")
async def get_recent_threats(limit: int = 100):
    async with _pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT id::text, source_ip::text, detector_spore, threat_type,
                      severity, confidence, timestamp
               FROM threat_alerts
               ORDER BY timestamp DESC LIMIT $1""",
            limit,
        )
    return [dict(r) for r in rows]


@app.get("/api/connections/recent")
async def get_recent_connections(limit: int = 200):
    async with _pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT spore_id, protocol, source_ip::text, uri, timestamp
               FROM connections ORDER BY timestamp DESC LIMIT $1""",
            limit,
        )
    return [dict(r) for r in rows]


@app.get("/api/canary/hits")
async def get_canary_hits(limit: int = 50):
    async with _pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT ch.id::text, ct.token_value, ct.spore_id,
                      ch.source_ip::text, ch.user_agent, ch.timestamp
               FROM canary_hits ch
               JOIN canary_tokens ct ON ch.token_id = ct.token_id
               ORDER BY ch.timestamp DESC LIMIT $1""",
            limit,
        )
    return [dict(r) for r in rows]


@app.get("/api/deception_score")
async def get_deception_score():
    async with _pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM deception_score")
    return dict(row) if row else {}


@app.get("/api/threat_level")
async def get_threat_level():
    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT level, changed_at FROM threat_level ORDER BY changed_at DESC LIMIT 1"
        )
    return dict(row) if row else {"level": "low"}


@app.get("/api/timeline")
async def get_timeline(hours: int = 24):
    async with _pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT date_trunc('minute', timestamp) AS bucket,
                   COUNT(*) AS events,
                   AVG(severity) AS avg_severity
            FROM threat_alerts
            WHERE timestamp > NOW() - ($1 || ' hours')::INTERVAL
            GROUP BY bucket ORDER BY bucket
            """,
            str(hours),
        )
    return [dict(r) for r in rows]


@app.get("/api/attacker_ips")
async def get_attacker_ips():
    async with _pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT source_ip::text,
                      COUNT(*) AS event_count,
                      MAX(severity) AS max_severity,
                      MAX(timestamp) AS last_seen,
                      array_agg(DISTINCT threat_type) AS threat_types
               FROM threat_alerts
               GROUP BY source_ip
               ORDER BY event_count DESC LIMIT 50"""
        )
    return [dict(r) for r in rows]


# ── Server-Sent Events stream ─────────────────────────────────────────────────

@app.get("/api/stream")
async def sse_stream(request: Request):
    queue: asyncio.Queue = asyncio.Queue(maxsize=200)
    _sse_subscribers.append(queue)

    async def event_generator():
        try:
            # Send initial connection confirmation
            yield "data: " + json.dumps({"type": "connected"}) + "\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15)
                    yield "data: " + json.dumps(event, default=str) + "\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            if queue in _sse_subscribers:
                _sse_subscribers.remove(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":  "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ── Serve frontend ────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    with open("/app/static/index.html") as f:
        return f.read()


if __name__ == "__main__":
    import uvicorn
    structlog.configure(processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(),
    ])
    uvicorn.run(app, host="0.0.0.0", port=3000, log_level="warning")
