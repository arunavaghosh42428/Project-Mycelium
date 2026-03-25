"""
HTTP Emulator – presents a convincing IoT REST API.
Detects scanning behaviour (rapid requests, path traversal, known exploit paths).
"""
import asyncio
import json
import time
import structlog
from aiohttp import web
from collections import defaultdict
from typing import Dict, List
from fake_data import FakeDataGenerator
from canary import CanaryManager

log = structlog.get_logger()

# Known attacker probe paths – if hit, immediately raise threat severity
EXPLOIT_PATHS = {
    "/shell", "/cgi-bin/", "/.env", "/admin/config",
    "/api/v1/exploit", "/setup.cgi", "/goform/",
    "/HNAP1/", "/.git/config", "/wp-admin",
}

SCAN_WINDOW_SECS = 10
SCAN_THRESHOLD   = 15   # >15 requests in 10 s = likely scan


class HTTPEmulator:
    def __init__(self, config, db, rhizome):
        self.config  = config
        self.db      = db
        self.rhizome = rhizome
        self.gen     = FakeDataGenerator(config.spore_type, config.spore_id)
        self.canary  = CanaryManager(config.canary_server, config.spore_id, db)

        # Per-IP request timestamps for scan detection
        self._ip_hits: Dict[str, List[float]] = defaultdict(list)

    async def start(self):
        app = web.Application(middlewares=[self._logging_middleware])
        app.router.add_route("*", "/{path_info:.*}", self._catch_all)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "0.0.0.0", self.config.http_port)
        await site.start()
        log.info("http_emulator.started", port=self.config.http_port,
                 spore=self.config.spore_id)
        # Keep alive
        while True:
            await asyncio.sleep(3600)

    @web.middleware
    async def _logging_middleware(self, request: web.Request, handler):
        source_ip = request.remote or "0.0.0.0"
        await self.db.log_connection(
            self.config.spore_id, "http", source_ip, None,
            str(request.rel_url),
            {"method": request.method, "ua": request.headers.get("User-Agent", "")},
        )
        return await handler(request)

    async def _catch_all(self, request: web.Request) -> web.Response:
        source_ip = request.remote or "0.0.0.0"
        path      = request.path
        now       = time.time()

        # ── Scan detection ────────────────────────────────────────────────────
        hits = self._ip_hits[source_ip]
        hits.append(now)
        # Trim old entries
        self._ip_hits[source_ip] = [t for t in hits if now - t < SCAN_WINDOW_SECS]

        if len(self._ip_hits[source_ip]) > SCAN_THRESHOLD:
            await self._raise_threat(source_ip, "port_scan", 0.7)

        if any(path.startswith(p) or p in path for p in EXPLOIT_PATHS):
            await self._raise_threat(source_ip, "exploit_attempt", 0.9)
            return web.Response(status=403, text="Forbidden")

        # ── Route emulation ───────────────────────────────────────────────────
        if path in ("/", "/index.html"):
            return self._device_home()

        if path == "/api/status":
            return web.json_response(self.gen.sensor_reading())

        if path == "/api/config":
            cfg = self.gen.device_config()
            cfg = await self.canary.embed_in_config(cfg)
            return web.json_response(cfg)

        if path == "/api/credentials":
            await self._raise_threat(source_ip, "credential_harvest", 0.85)
            body = self.gen.credentials_file()
            body = await self.canary.embed_in_text(body)
            return web.Response(text=body, content_type="application/json")

        if path == "/api/logs":
            return web.json_response(self._fake_logs())

        # Catch-all 404 with banner
        return web.Response(
            status=404,
            text=f"404 Not Found\nServer: {self.rhizome.banner}\n",
        )

    def _device_home(self) -> web.Response:
        html = f"""<!DOCTYPE html>
<html><head><title>{self.config.spore_id}</title></head>
<body>
<h2>Device Management Portal</h2>
<p>Model: {self.rhizome.banner}</p>
<p>Status: <span style="color:green">ONLINE</span></p>
<ul>
  <li><a href="/api/status">Status</a></li>
  <li><a href="/api/config">Configuration</a></li>
  <li><a href="/api/logs">System Logs</a></li>
</ul>
</body></html>"""
        return web.Response(text=html, content_type="text/html")

    def _fake_logs(self):
        import random
        events = ["System startup", "Config saved", "Firmware check",
                  "Connection from 10.0.0.1", "Scheduled reboot skipped"]
        return [{"ts": time.time() - i * 300, "msg": random.choice(events)}
                for i in range(10)]

    async def _raise_threat(self, source_ip: str, threat_type: str, severity: float):
        alert_id = await self.db.log_threat(
            self.config.spore_id, source_ip, threat_type, severity)
        await self.rhizome.publish_threat(source_ip, threat_type, severity,
                                           {"alert_id": alert_id, "proto": "http"})
        log.warning("http_emulator.threat", ip=source_ip,
                    type=threat_type, severity=severity)
