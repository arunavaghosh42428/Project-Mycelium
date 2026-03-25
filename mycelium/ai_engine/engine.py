"""
Project Mycelium – Enzymatic AI Engine (Phase 3)

Consumes threat alerts from the Rhizome, computes a confidence score,
and orchestrates adaptive responses:
  Low    → log only
  Medium → change Spore banners, slow-feed fake data
  High   → spawn 5-10 new Spore containers, rotate fingerprints aggressively
"""
import asyncio
import json
import os
import time
import structlog
import nats
import asyncpg
import docker

from classifier import ThreatClassifier
from spawner import SporeSpawner

log = structlog.get_logger()

NATS_URL     = os.getenv("NATS_URL",     "nats://nats:4222")
NATS_TOKEN   = os.getenv("NATS_TOKEN",   "mycelium_rhizome_token_2025")
DB_URL       = os.getenv("DB_URL",       "postgresql://mycelium:mycelium_secret@postgres:5432/mycelium")

# Per-IP state
class IPState:
    def __init__(self):
        self.events:    list  = []   # (timestamp, severity)
        self.score:     float = 0.0
        self.level:     str   = "low"
        self.responded: dict  = {}   # action -> last_triggered_ts


class AIEngine:
    def __init__(self):
        self.classifier = ThreatClassifier()
        self.spawner    = SporeSpawner()
        self._ip_state: dict[str, IPState] = {}
        self._global_level = "low"
        self._nc   = None
        self._pool = None

    # ── Startup ───────────────────────────────────────────────────────────────

    async def start(self):
        self._pool = await asyncpg.create_pool(DB_URL, min_size=2, max_size=5)
        self._nc   = await nats.connect(NATS_URL, token=NATS_TOKEN,
                                         name="ai_engine",
                                         max_reconnect_attempts=-1)
        log.info("ai_engine.started")

        await self._nc.subscribe("threat.alert", cb=self._on_threat_alert)
        await self._nc.subscribe("metrics.spore.*", cb=self._on_heartbeat)

        await asyncio.gather(
            self._decay_loop(),
            self._watchdog_loop(),
        )

    # ── Event Handlers ────────────────────────────────────────────────────────

    async def _on_threat_alert(self, msg):
        try:
            data = json.loads(msg.data.decode())
        except Exception:
            return

        source_ip   = data.get("source_ip", "0.0.0.0")
        threat_type = data.get("threat_type", "unknown")
        raw_severity = float(data.get("severity", 0.5))

        # Feed into classifier
        confidence, adjusted_severity = self.classifier.classify(
            source_ip, threat_type, raw_severity, data
        )

        # Update per-IP state
        state = self._ip_state.setdefault(source_ip, IPState())
        state.events.append((time.time(), adjusted_severity))
        state.score = self._compute_score(state)
        new_level   = self._score_to_level(state.score)

        log.info("ai_engine.alert_processed",
                 ip=source_ip, type=threat_type,
                 score=round(state.score, 3), level=new_level,
                 confidence=round(confidence, 3))

        # Log to DB
        await self._log_alert_update(source_ip, threat_type, adjusted_severity,
                                      confidence, new_level)

        # Trigger response if level escalated
        if new_level != state.level:
            state.level = new_level
            await self._escalate_global_level(new_level)

        await self._trigger_response(source_ip, new_level, state)

    async def _on_heartbeat(self, msg):
        """Update last-seen for a Spore."""
        try:
            data = json.loads(msg.data.decode())
            spore_id = data.get("spore_id")
            if spore_id and self._pool:
                async with self._pool.acquire() as conn:
                    await conn.execute(
                        "UPDATE spores SET last_heartbeat = NOW() WHERE spore_id = $1",
                        spore_id,
                    )
        except Exception:
            pass

    # ── Response Orchestration ────────────────────────────────────────────────

    async def _trigger_response(self, source_ip: str, level: str, state: IPState):
        now = time.time()

        if level == "low":
            return  # log only

        if level == "medium":
            if now - state.responded.get("banner_change", 0) > 60:
                await self._cmd_banner_change("all")
                state.responded["banner_change"] = now
                await self._log_action("banner_change", source_ip,
                                        {"target": "all", "reason": "medium_threat"})

        if level == "high":
            if now - state.responded.get("spawn", 0) > 120:
                count = 5
                log.warning("ai_engine.spawning_decoys",
                             count=count, trigger_ip=source_ip)
                await self.spawner.spawn_batch(count, source_ip)
                state.responded["spawn"] = now
                await self._log_action("spawn_spore", source_ip,
                                        {"count": count, "trigger": "high_threat"})

            if now - state.responded.get("fingerprint_rotate", 0) > 30:
                await self._cmd_rotate_fingerprints()
                state.responded["fingerprint_rotate"] = now

    async def _escalate_global_level(self, new_level: str):
        # Only escalate (never auto-downgrade here – decay loop handles that)
        levels = ["low", "medium", "high"]
        if levels.index(new_level) > levels.index(self._global_level):
            self._global_level = new_level
            await self._publish("threat.level", {"level": new_level,
                                                   "ts": time.time()})
            log.warning("ai_engine.global_level_escalated", level=new_level)
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "INSERT INTO threat_level (level, changed_by) VALUES ($1, 'ai_engine')",
                    new_level,
                )

    # ── NATS Commands ─────────────────────────────────────────────────────────

    async def _cmd_banner_change(self, target: str = "all"):
        import random
        banners = [
            "OpenWRT 23.05.0",
            "MikroTik RouterOS 7.12",
            "Cisco IOS 15.7",
            "Siemens SCALANCE W780",
            "Honeywell IP-Audio Controller v4",
        ]
        await self._publish("command.banner_change", {
            "target_spore": target,
            "new_banner":   random.choice(banners),
            "ts":           time.time(),
        })

    async def _cmd_rotate_fingerprints(self):
        await self._cmd_banner_change("all")

    async def _publish(self, subject: str, payload: dict):
        if self._nc and self._nc.is_connected:
            await self._nc.publish(subject, json.dumps(payload).encode())

    # ── Scoring Helpers ───────────────────────────────────────────────────────

    def _compute_score(self, state: IPState) -> float:
        """Exponentially weighted recent severity."""
        now  = time.time()
        score = 0.0
        for ts, sev in state.events[-50:]:
            age    = now - ts
            weight = max(0, 1 - age / 300)   # decay over 5 min
            score  = min(1.0, score + sev * weight * 0.15)
        return score

    def _score_to_level(self, score: float) -> str:
        if score >= 0.65:
            return "high"
        if score >= 0.30:
            return "medium"
        return "low"

    # ── Background Loops ──────────────────────────────────────────────────────

    async def _decay_loop(self):
        """Gradually lower per-IP scores; downgrade global level if quiet."""
        while True:
            await asyncio.sleep(60)
            now   = time.time()
            alive = False
            for ip, state in list(self._ip_state.items()):
                state.events = [(t, s) for t, s in state.events if now - t < 600]
                state.score  = self._compute_score(state)
                state.level  = self._score_to_level(state.score)
                if state.level != "low":
                    alive = True
            if not alive and self._global_level != "low":
                self._global_level = "low"
                await self._publish("threat.level", {"level": "low", "ts": now})
                log.info("ai_engine.level_decayed_to_low")

    async def _watchdog_loop(self):
        """Detect Spores that stopped heartbeating."""
        while True:
            await asyncio.sleep(30)
            if not self._pool:
                continue
            try:
                async with self._pool.acquire() as conn:
                    dead = await conn.fetch(
                        """SELECT spore_id FROM spores
                           WHERE status = 'active'
                           AND last_heartbeat < NOW() - INTERVAL '60 seconds'"""
                    )
                    for row in dead:
                        log.warning("ai_engine.spore_dead",
                                     spore_id=row["spore_id"])
                        await conn.execute(
                            "UPDATE spores SET status = 'sleeping' WHERE spore_id = $1",
                            row["spore_id"],
                        )
            except Exception as e:
                log.error("ai_engine.watchdog_error", error=str(e))

    # ── DB Helpers ────────────────────────────────────────────────────────────

    async def _log_alert_update(self, source_ip, threat_type, severity,
                                  confidence, level):
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """UPDATE threat_alerts SET confidence = $1
                       WHERE source_ip = $2::inet
                       AND threat_type = $3
                       ORDER BY timestamp DESC LIMIT 1""",
                    confidence, source_ip, threat_type,
                )
        except Exception:
            pass

    async def _log_action(self, action, triggered_by, details):
        async with self._pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO response_actions (action, triggered_by, details)
                   VALUES ($1, $2, $3::jsonb)""",
                action, triggered_by, json.dumps(details),
            )


async def main():
    import structlog
    structlog.configure(processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(),
    ])
    engine = AIEngine()
    await engine.start()


if __name__ == "__main__":
    asyncio.run(main())
