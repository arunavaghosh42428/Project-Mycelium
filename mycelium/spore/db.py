"""Async PostgreSQL wrapper used by Spore components."""
import asyncpg
import structlog
from datetime import datetime, timezone
from typing import Optional, Dict, Any

log = structlog.get_logger()


class Database:
    def __init__(self, dsn: str):
        self.dsn = dsn
        self._pool: Optional[asyncpg.Pool] = None

    async def connect(self):
        self._pool = await asyncpg.create_pool(self.dsn, min_size=2, max_size=10)
        log.info("db.connected")

    async def disconnect(self):
        if self._pool:
            await self._pool.close()

    async def register_spore(self, config):
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO spores (spore_id, spore_type, protocols, banner, status)
                VALUES ($1, $2, $3, $4, 'active')
                ON CONFLICT (spore_id) DO UPDATE
                  SET status = 'active', last_heartbeat = NOW()
                """,
                config.spore_id,
                config.spore_type,
                [p for p in ["mqtt", "modbus", "http"]
                 if getattr(config, f"enable_{p}", False)],
                config.default_banner(),
            )

    async def deregister_spore(self, spore_id: str):
        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE spores SET status = 'sleeping' WHERE spore_id = $1",
                spore_id,
            )

    async def update_heartbeat(self, spore_id: str):
        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE spores SET last_heartbeat = NOW() WHERE spore_id = $1",
                spore_id,
            )

    async def log_connection(self, spore_id: str, protocol: str,
                              source_ip: str, source_port: Optional[int],
                              uri: Optional[str], payload: Optional[Dict]):
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO connections (spore_id, protocol, source_ip, source_port, uri, payload)
                VALUES ($1, $2, $3::inet, $4, $5, $6::jsonb)
                """,
                spore_id, protocol, source_ip, source_port, uri,
                __import__("json").dumps(payload) if payload else None,
            )

    async def log_threat(self, spore_id: str, source_ip: str,
                          threat_type: str, severity: float,
                          raw: Optional[Dict] = None) -> str:
        import json
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO threat_alerts
                  (source_ip, detector_spore, threat_type, severity, raw_payload)
                VALUES ($1::inet, $2, $3, $4, $5::jsonb)
                RETURNING id::text
                """,
                source_ip, spore_id, threat_type, severity,
                json.dumps(raw) if raw else None,
            )
            return row["id"]

    async def log_action(self, action: str, triggered_by: str, details: Dict):
        import json
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO response_actions (action, triggered_by, details)
                VALUES ($1, $2, $3::jsonb)
                """,
                action, triggered_by, json.dumps(details),
            )
