"""
MQTT Emulator – runs a minimal MQTT broker that accepts connections
and publishes fake sensor data. Detects brute-force and mass-subscribe patterns.
"""
import asyncio
import json
import time
import struct
import structlog
from collections import defaultdict

log = structlog.get_logger()

# MQTT packet types
CONNECT     = 1
CONNACK     = 2
PUBLISH     = 3
SUBSCRIBE   = 8
SUBACK      = 9
PINGREQ     = 12
PINGRESP    = 13
DISCONNECT  = 14


class MQTTEmulator:
    def __init__(self, config, db, rhizome):
        self.config  = config
        self.db      = db
        self.rhizome = rhizome
        self._clients: dict = {}
        self._connect_attempts: dict = defaultdict(int)

    async def start(self):
        server = await asyncio.start_server(
            self._handle_client, "0.0.0.0", self.config.mqtt_port
        )
        log.info("mqtt_emulator.started", port=self.config.mqtt_port,
                 spore=self.config.spore_id)
        async with server:
            await server.serve_forever()

    async def _handle_client(self, reader: asyncio.StreamReader,
                               writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        source_ip = peer[0] if peer else "0.0.0.0"
        log.info("mqtt.client_connected", ip=source_ip)

        await self.db.log_connection(
            self.config.spore_id, "mqtt", source_ip, peer[1] if peer else None,
            "MQTT_CONNECT", None,
        )

        try:
            while True:
                # Read fixed header
                header_byte = await asyncio.wait_for(reader.read(1), timeout=60)
                if not header_byte:
                    break

                pkt_type = (header_byte[0] >> 4) & 0xF

                # Read remaining length (simplified: single byte)
                rem_len_byte = await reader.read(1)
                if not rem_len_byte:
                    break
                rem_len = rem_len_byte[0]
                payload = await reader.read(rem_len) if rem_len else b""

                if pkt_type == CONNECT:
                    await self._handle_connect(reader, writer, source_ip, payload)
                elif pkt_type == SUBSCRIBE:
                    await self._handle_subscribe(writer, source_ip, payload)
                elif pkt_type == PUBLISH:
                    await self._handle_publish(source_ip, payload)
                elif pkt_type == PINGREQ:
                    writer.write(bytes([PINGRESP << 4, 0]))
                    await writer.drain()
                elif pkt_type == DISCONNECT:
                    break

        except asyncio.TimeoutError:
            pass
        except Exception as e:
            log.warning("mqtt.client_error", ip=source_ip, error=str(e))
        finally:
            writer.close()
            log.info("mqtt.client_disconnected", ip=source_ip)

    async def _handle_connect(self, reader, writer, source_ip: str, payload: bytes):
        # Brute-force detection
        self._connect_attempts[source_ip] += 1
        if self._connect_attempts[source_ip] > 5:
            await self._raise_threat(source_ip, "brute_force", 0.75)

        # CONNACK – return code 0 = accepted (we accept everything to collect data)
        connack = bytes([CONNACK << 4, 2, 0, 0])
        writer.write(connack)
        await writer.drain()

        # Immediately publish some fake device data
        from fake_data import FakeDataGenerator
        gen = FakeDataGenerator(self.config.spore_type, self.config.spore_id)
        topic = f"devices/{self.config.spore_id}/state"
        msg   = json.dumps(gen.sensor_reading()).encode()
        await self._publish_to_client(writer, topic, msg)

        log.info("mqtt.connect_accepted", ip=source_ip)

    async def _handle_subscribe(self, writer, source_ip: str, payload: bytes):
        # Mass-subscribe detection (trying to subscribe to #)
        if b"#" in payload or b"$SYS" in payload:
            await self._raise_threat(source_ip, "recon", 0.6)

        # SUBACK with QoS 0 for all requested topics
        if len(payload) >= 2:
            msg_id = payload[:2]
            # Count topics and send SUBACK
            suback = bytes([SUBACK << 4, 3]) + msg_id + bytes([0])
            writer.write(suback)
            await writer.drain()

    async def _handle_publish(self, source_ip: str, payload: bytes):
        await self.db.log_connection(
            self.config.spore_id, "mqtt", source_ip, None,
            "PUBLISH", {"raw": payload.hex()[:64]},
        )

    async def _publish_to_client(self, writer, topic: str, message: bytes):
        """Send a PUBLISH packet to a connected client."""
        topic_bytes = topic.encode()
        topic_len   = len(topic_bytes).to_bytes(2, "big")
        rem_len     = 2 + len(topic_bytes) + len(message)
        pkt = bytes([PUBLISH << 4, rem_len]) + topic_len + topic_bytes + message
        writer.write(pkt)
        await writer.drain()

    async def _raise_threat(self, source_ip: str, threat_type: str, severity: float):
        await self.db.log_threat(
            self.config.spore_id, source_ip, threat_type, severity)
        await self.rhizome.publish_threat(source_ip, threat_type, severity,
                                           {"proto": "mqtt"})
