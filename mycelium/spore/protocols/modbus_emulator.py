"""
Modbus TCP Emulator – listens on port 502 and responds to
Read Holding Registers / Read Coils / Write requests.
Rapid polling or write-flooding triggers a threat alert.
"""
import asyncio
import struct
import time
import structlog
from collections import defaultdict
from fake_data import FakeDataGenerator

log = structlog.get_logger()

# Modbus function codes
FC_READ_COILS       = 0x01
FC_READ_HOLDING     = 0x03
FC_READ_INPUT       = 0x04
FC_WRITE_SINGLE     = 0x06
FC_WRITE_MULTIPLE   = 0x10

POLL_WINDOW  = 10    # seconds
POLL_THRESH  = 50    # > 50 requests in 10s = suspicious


class ModbusEmulator:
    def __init__(self, config, db, rhizome):
        self.config  = config
        self.db      = db
        self.rhizome = rhizome
        self.gen     = FakeDataGenerator(config.spore_type, config.spore_id)
        self._poll_times: dict = defaultdict(list)

    async def start(self):
        server = await asyncio.start_server(
            self._handle_client, "0.0.0.0", self.config.modbus_port
        )
        log.info("modbus_emulator.started", port=self.config.modbus_port,
                 spore=self.config.spore_id)
        async with server:
            await server.serve_forever()

    async def _handle_client(self, reader: asyncio.StreamReader,
                               writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        source_ip = peer[0] if peer else "0.0.0.0"

        await self.db.log_connection(
            self.config.spore_id, "modbus", source_ip, peer[1] if peer else None,
            "MODBUS_CONNECT", None,
        )

        try:
            while True:
                # Modbus MBAP header: 6 bytes
                header = await asyncio.wait_for(reader.readexactly(6), timeout=30)
                if not header:
                    break

                transaction_id, protocol_id, length = struct.unpack(">HHH", header)
                if protocol_id != 0:
                    break

                data = await reader.readexactly(length)
                if not data:
                    break

                unit_id = data[0]
                fc      = data[1]

                # Rate-check
                now = time.time()
                times = self._poll_times[source_ip]
                times.append(now)
                self._poll_times[source_ip] = [t for t in times if now - t < POLL_WINDOW]
                if len(self._poll_times[source_ip]) > POLL_THRESH:
                    await self._raise_threat(source_ip, "recon", 0.65)

                await self.db.log_connection(
                    self.config.spore_id, "modbus", source_ip, None,
                    f"FC_{fc:#04x}", {"unit": unit_id, "fc": fc},
                )

                response = self._build_response(transaction_id, unit_id, fc, data[2:])
                writer.write(response)
                await writer.drain()

        except asyncio.IncompleteReadError:
            pass
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            log.warning("modbus.error", ip=source_ip, error=str(e))
        finally:
            writer.close()

    def _build_response(self, tid: int, uid: int, fc: int, req_data: bytes) -> bytes:
        registers = self.gen.modbus_registers()

        if fc == FC_READ_HOLDING or fc == FC_READ_INPUT:
            start = int.from_bytes(req_data[0:2], "big")
            count = int.from_bytes(req_data[2:4], "big")
            values = [registers.get(start + i, 0) for i in range(count)]
            byte_count = count * 2
            payload = bytes([uid, fc, byte_count])
            for v in values:
                payload += v.to_bytes(2, "big")

        elif fc == FC_READ_COILS:
            count = int.from_bytes(req_data[2:4], "big")
            coil_byte = 0b10101010 & ((1 << count) - 1)
            payload = bytes([uid, fc, 1, coil_byte])

        elif fc in (FC_WRITE_SINGLE, FC_WRITE_MULTIPLE):
            # Echo back the request (standard Modbus write response)
            payload = bytes([uid, fc]) + req_data[:4]

        else:
            # Exception response
            payload = bytes([uid, fc | 0x80, 0x01])

        mbap = struct.pack(">HHH", tid, 0, len(payload))
        return mbap + payload

    async def _raise_threat(self, source_ip: str, threat_type: str, severity: float):
        await self.db.log_threat(
            self.config.spore_id, source_ip, threat_type, severity)
        await self.rhizome.publish_threat(source_ip, threat_type, severity,
                                           {"proto": "modbus"})
