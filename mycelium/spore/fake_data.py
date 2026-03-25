"""
Fake Data Generator – produces realistic IoT sensor payloads.
Uses templates + light randomization. Optionally calls an LLM API
for more varied outputs when OPENAI_API_KEY or OLLAMA_URL is set.
"""
import random
import time
import json
import os
from datetime import datetime, timezone
from typing import Dict, Any


class FakeDataGenerator:
    """Generate plausible IoT device data for a given spore type."""

    def __init__(self, spore_type: str, spore_id: str):
        self.spore_type = spore_type
        self.spore_id = spore_id

    # ── Public API ────────────────────────────────────────────────────────────

    def sensor_reading(self) -> Dict[str, Any]:
        generators = {
            "smart_light":  self._light_data,
            "thermostat":   self._thermostat_data,
            "ip_camera":    self._camera_data,
            "plc":          self._plc_data,
            "router":       self._router_data,
        }
        gen = generators.get(self.spore_type, self._generic_data)
        return gen()

    def device_config(self) -> Dict[str, Any]:
        return {
            "device_id":      self.spore_id,
            "device_type":    self.spore_type,
            "firmware":       f"v{random.randint(1,5)}.{random.randint(0,9)}.{random.randint(0,99)}",
            "manufacturer":   self._manufacturer(),
            "network": {
                "dhcp":       True,
                "hostname":   self.spore_id.replace("_", "-"),
                "dns":        ["8.8.8.8", "1.1.1.1"],
            },
            "credentials": {
                "username":   "admin",
                "password":   self._fake_password(),   # bait credential
            },
            "ntp_server":  "pool.ntp.org",
            "_update_url": "{{CANARY}}",               # filled in by CanaryManager
        }

    def credentials_file(self) -> str:
        return json.dumps({
            "users": [
                {"user": "admin",    "pass": self._fake_password(), "role": "admin"},
                {"user": "operator", "pass": self._fake_password(), "role": "read"},
            ],
            "api_key": self._fake_api_key(),
            "callback": "{{CANARY}}",
        }, indent=2)

    def modbus_registers(self) -> Dict[int, int]:
        """Return a dict of Modbus register address → value."""
        base = {
            0:   int(random.uniform(18, 28) * 10),   # temperature ×10
            1:   random.randint(30, 80),              # humidity %
            2:   random.randint(0, 1),                # on/off
            100: random.randint(200, 240),            # voltage
            101: random.randint(0, 15),               # current (A)
        }
        return base

    # ── Private helpers ───────────────────────────────────────────────────────

    def _light_data(self):
        return {
            "id":         self.spore_id,
            "state":      random.choice(["on", "on", "off"]),
            "brightness": random.randint(10, 100),
            "color_temp": random.randint(2700, 6500),
            "hue":        random.randint(0, 360),
            "saturation": random.randint(0, 100),
            "timestamp":  datetime.now(timezone.utc).isoformat(),
        }

    def _thermostat_data(self):
        target = round(random.uniform(19.0, 24.0), 1)
        current = round(target + random.uniform(-2, 2), 1)
        return {
            "id":               self.spore_id,
            "current_temp_c":   current,
            "target_temp_c":    target,
            "mode":             random.choice(["heat", "cool", "auto"]),
            "humidity_pct":     random.randint(35, 65),
            "hvac_state":       random.choice(["heating", "cooling", "idle"]),
            "schedule_enabled": True,
            "timestamp":        datetime.now(timezone.utc).isoformat(),
        }

    def _camera_data(self):
        return {
            "id":          self.spore_id,
            "stream_url":  f"rtsp://{self.spore_id}.local:554/live",
            "resolution":  random.choice(["1080p", "4K", "720p"]),
            "fps":         random.choice([15, 25, 30]),
            "motion":      random.random() < 0.1,
            "night_mode":  random.random() < 0.3,
            "storage_gb":  round(random.uniform(0, 32), 1),
            "timestamp":   datetime.now(timezone.utc).isoformat(),
        }

    def _plc_data(self):
        return {
            "id":      self.spore_id,
            "inputs":  [random.randint(0, 1) for _ in range(8)],
            "outputs": [random.randint(0, 1) for _ in range(8)],
            "holding_registers": [random.randint(0, 65535) for _ in range(8)],
            "faults":  [],
            "uptime_s": random.randint(3600, 86400 * 30),
        }

    def _router_data(self):
        return {
            "id":           self.spore_id,
            "wan_ip":       f"203.0.113.{random.randint(1,254)}",
            "clients":      random.randint(1, 25),
            "uptime_s":     random.randint(3600, 86400 * 90),
            "rx_bytes":     random.randint(10**8, 10**12),
            "tx_bytes":     random.randint(10**7, 10**11),
            "ssid":         f"HomeNetwork_{random.randint(1000,9999)}",
            "channel_2ghz": random.choice([1, 6, 11]),
            "channel_5ghz": random.choice([36, 40, 44, 48]),
        }

    def _generic_data(self):
        return {
            "id":        self.spore_id,
            "type":      self.spore_type,
            "value":     round(random.uniform(0, 100), 2),
            "unit":      "units",
            "online":    True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def _manufacturer(self):
        return random.choice([
            "Philips", "Honeywell", "Siemens", "Schneider Electric",
            "Bosch", "Samsung SmartThings", "TP-Link", "Hikvision",
        ])

    def _fake_password(self):
        words = ["summer", "winter", "secure", "admin", "device", "home"]
        return random.choice(words) + str(random.randint(100, 9999)) + "!"

    def _fake_api_key(self):
        import secrets
        return "sk-" + secrets.token_hex(24)
