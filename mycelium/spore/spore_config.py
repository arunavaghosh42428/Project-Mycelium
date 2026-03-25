"""Spore configuration loaded from environment variables."""
from pydantic_settings import BaseSettings
from typing import Optional


class SporeConfig(BaseSettings):
    spore_id: str = "spore_default"
    spore_type: str = "smart_light"  # smart_light | thermostat | ip_camera | plc | router

    nats_url: str = "nats://localhost:4222"
    nats_token: str = "mycelium_rhizome_token_2025"

    db_url: str = "postgresql://mycelium:mycelium_secret@localhost:5432/mycelium"
    canary_server: str = "http://localhost:9999"

    enable_mqtt: bool = True
    enable_modbus: bool = True
    enable_http: bool = True

    mqtt_port: int = 1883
    modbus_port: int = 502
    http_port: int = 8080

    # Current banner (can be changed by Rhizome command)
    banner: str = ""

    class Config:
        env_file = ".env"

    def default_banner(self) -> str:
        banners = {
            "smart_light":  "Philips Hue Bridge 1.0",
            "thermostat":   "Nest Thermostat E (v5.9.3)",
            "ip_camera":    "Hikvision DS-2CD2T47G2-L",
            "plc":          "Allen-Bradley MicroLogix 1100",
            "router":       "TP-Link Archer AX55 (OpenWRT)",
        }
        return banners.get(self.spore_type, "Generic IoT Device v1.0")
