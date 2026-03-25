"""
Rhizome Client – wraps NATS pub/sub for inter-Spore communication.
Each Spore holds one RhizomeClient instance.
"""
import json
import asyncio
import structlog
import nats
from nats.aio.client import Client as NATS
from typing import Callable, Optional

log = structlog.get_logger()

THREAT_ALERT_SUBJECT    = "threat.alert"
THREAT_LEVEL_SUBJECT    = "threat.level"
CMD_BANNER_SUBJECT      = "command.banner_change"
CMD_SPAWN_SUBJECT       = "command.spawn"
CANARY_HIT_SUBJECT      = "canary.hit"


class RhizomeClient:
    def __init__(self, config, db):
        self.config = config
        self.db = db
        self._nc: Optional[NATS] = None
        self._threat_level = "low"
        self._banner = config.default_banner()
        self._on_banner_change: Optional[Callable] = None

    def set_banner_change_callback(self, cb: Callable):
        self._on_banner_change = cb

    @property
    def banner(self) -> str:
        return self._banner

    @property
    def threat_level(self) -> str:
        return self._threat_level

    async def connect(self):
        self._nc = await nats.connect(
            self.config.nats_url,
            token=self.config.nats_token,
            reconnect_time_wait=2,
            max_reconnect_attempts=-1,
            name=self.config.spore_id,
        )
        log.info("rhizome.connected", spore=self.config.spore_id)

    async def disconnect(self):
        if self._nc:
            await self._nc.drain()

    async def publish_threat(self, source_ip: str, threat_type: str,
                              severity: float, extra: dict = None):
        """Broadcast a threat alert to all Spores and the AI Engine."""
        msg = {
            "source_ip":        source_ip,
            "threat_type":      threat_type,
            "severity":         severity,
            "detector_spore_id": self.config.spore_id,
            "timestamp":        __import__("time").time(),
            **(extra or {}),
        }
        await self.publish(THREAT_ALERT_SUBJECT, msg)
        log.info("rhizome.threat_published", **msg)

    async def publish(self, subject: str, payload: dict):
        if self._nc and self._nc.is_connected:
            await self._nc.publish(subject, json.dumps(payload).encode())

    async def listen(self):
        """Subscribe to all relevant subjects and dispatch handlers."""
        async def handle_threat_level(msg):
            data = json.loads(msg.data.decode())
            self._threat_level = data.get("level", "low")
            log.info("rhizome.threat_level_changed",
                     level=self._threat_level, spore=self.config.spore_id)

        async def handle_banner_change(msg):
            data = json.loads(msg.data.decode())
            target = data.get("target_spore")
            if target and target != self.config.spore_id and target != "all":
                return
            new_banner = data.get("new_banner", self._banner)
            old = self._banner
            self._banner = new_banner
            log.info("rhizome.banner_changed",
                     spore=self.config.spore_id, old=old, new=new_banner)
            await self.db.log_action(
                "banner_change", "rhizome",
                {"spore_id": self.config.spore_id, "new_banner": new_banner},
            )
            if self._on_banner_change:
                await self._on_banner_change(new_banner)

        await self._nc.subscribe(THREAT_LEVEL_SUBJECT,  cb=handle_threat_level)
        await self._nc.subscribe(CMD_BANNER_SUBJECT,    cb=handle_banner_change)

        log.info("rhizome.subscribed", spore=self.config.spore_id)

        # Keep alive
        while True:
            await asyncio.sleep(1)
