"""
Spore Spawner – uses the Docker SDK to spin up new Spore containers
on demand when the AI Engine detects a high-severity threat.
"""
import os
import random
import time
import structlog
import docker
from docker.errors import DockerException

log = structlog.get_logger()

SPORE_IMAGE    = os.getenv("SPORE_IMAGE",    "mycelium-spore")
NETWORK_NAME   = os.getenv("NETWORK_NAME",   "mycelium_mycelium_net")
DB_URL         = os.getenv("DB_URL",         "postgresql://mycelium:mycelium_secret@postgres:5432/mycelium")
NATS_URL       = os.getenv("NATS_URL",       "nats://nats:4222")
CANARY_SERVER  = os.getenv("CANARY_SERVER",  "http://canary_server:9999")

SPORE_TYPES = ["smart_light", "thermostat", "ip_camera", "plc", "router"]

# Port ranges for dynamically spawned spores (avoid conflict with static ones)
HTTP_PORT_START   = 8090
MQTT_PORT_START   = 1890
MODBUS_PORT_START = 5020


class SporeSpawner:
    def __init__(self):
        try:
            self._client = docker.from_env()
            log.info("spawner.docker_connected")
        except DockerException as e:
            log.warning("spawner.docker_unavailable", error=str(e))
            self._client = None

        self._spawned: list = []   # track dynamic containers for cleanup
        self._port_offset = 0

    async def spawn_batch(self, count: int, trigger_ip: str):
        """Spawn `count` new Spore containers with varied types/ports."""
        if not self._client:
            log.error("spawner.docker_not_available")
            return

        for i in range(count):
            spore_type = random.choice(SPORE_TYPES)
            spore_id   = f"dyn_{spore_type}_{int(time.time())}_{i}"
            offset     = self._port_offset + i

            http_port   = HTTP_PORT_START   + offset
            mqtt_port   = MQTT_PORT_START   + offset
            modbus_port = MODBUS_PORT_START + offset

            env = {
                "SPORE_ID":      spore_id,
                "SPORE_TYPE":    spore_type,
                "NATS_URL":      NATS_URL,
                "DB_URL":        DB_URL,
                "CANARY_SERVER": CANARY_SERVER,
                "ENABLE_MQTT":   "true",
                "ENABLE_MODBUS": "true",
                "ENABLE_HTTP":   "true",
            }

            try:
                container = self._client.containers.run(
                    SPORE_IMAGE,
                    detach=True,
                    name=f"mycelium_{spore_id}",
                    environment=env,
                    network=NETWORK_NAME,
                    ports={
                        "1883/tcp": mqtt_port,
                        "502/tcp":  modbus_port,
                        "8080/tcp": http_port,
                    },
                    labels={
                        "mycelium.dynamic":    "true",
                        "mycelium.trigger_ip": trigger_ip,
                        "mycelium.spore_id":   spore_id,
                    },
                    mem_limit="100m",
                    restart_policy={"Name": "unless-stopped"},
                )
                self._spawned.append(container.id)
                log.info("spawner.spawned",
                          spore_id=spore_id, container=container.short_id,
                          http=http_port, mqtt=mqtt_port)
            except Exception as e:
                log.error("spawner.spawn_failed", spore_id=spore_id, error=str(e))

        self._port_offset += count

    async def cleanup_dynamic_spores(self):
        """Remove all dynamically spawned containers."""
        if not self._client:
            return
        for cid in self._spawned:
            try:
                c = self._client.containers.get(cid)
                c.stop(timeout=5)
                c.remove()
                log.info("spawner.removed", container=cid[:12])
            except Exception as e:
                log.warning("spawner.cleanup_error", container=cid[:12], error=str(e))
        self._spawned.clear()
