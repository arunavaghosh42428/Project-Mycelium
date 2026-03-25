"""
Canary Token utilities – generate unique tokens and embed them
into fake data payloads served by Spore protocol emulators.
"""
import uuid
import httpx
import structlog
from typing import Optional

log = structlog.get_logger()


class CanaryManager:
    def __init__(self, canary_server_url: str, spore_id: str, db):
        self.base_url = canary_server_url
        self.spore_id = spore_id
        self.db = db

    async def create_token(self, token_type: str = "url",
                            embedded_in: str = "payload") -> str:
        """Register a new canary token and return the trigger value."""
        token_value = str(uuid.uuid4()).replace("-", "")
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.post(
                    f"{self.base_url}/token/register",
                    json={
                        "token_value": token_value,
                        "token_type":  token_type,
                        "spore_id":    self.spore_id,
                        "embedded_in": embedded_in,
                    },
                )
                resp.raise_for_status()
        except Exception as e:
            log.warning("canary.registration_failed", error=str(e))

        if token_type == "url":
            return f"{self.base_url}/c/{token_value}"
        elif token_type == "dns":
            return f"{token_value}.canary.mycelium.local"
        else:
            return f"canary+{token_value}@mycelium.local"

    async def embed_in_config(self, base_config: dict) -> dict:
        """Inject a canary URL into a fake device config dict."""
        url = await self.create_token("url", "config_file")
        base_config["_update_url"] = url
        base_config["_firmware_check"] = url + "/firmware"
        return base_config

    async def embed_in_text(self, text: str) -> str:
        """Replace placeholder {{CANARY}} with a live token URL."""
        if "{{CANARY}}" not in text:
            return text
        url = await self.create_token("url", "text_payload")
        return text.replace("{{CANARY}}", url)
