"""
Project Mycelium – Spore Node
Entry point that starts all protocol emulators and the Rhizome client.
"""
import asyncio
import os
import signal
import structlog

from protocols.mqtt_emulator import MQTTEmulator
from protocols.modbus_emulator import ModbusEmulator
from protocols.http_emulator import HTTPEmulator
from rhizome_client import RhizomeClient
from spore_config import SporeConfig
from db import Database

log = structlog.get_logger()


async def main():
    config = SporeConfig()
    log.info("spore.starting", spore_id=config.spore_id, spore_type=config.spore_type)

    db = Database(config.db_url)
    await db.connect()
    await db.register_spore(config)

    rhizome = RhizomeClient(config, db)
    await rhizome.connect()

    tasks = [asyncio.create_task(rhizome.listen())]

    if config.enable_mqtt:
        mqtt = MQTTEmulator(config, db, rhizome)
        tasks.append(asyncio.create_task(mqtt.start()))

    if config.enable_modbus:
        modbus = ModbusEmulator(config, db, rhizome)
        tasks.append(asyncio.create_task(modbus.start()))

    if config.enable_http:
        http = HTTPEmulator(config, db, rhizome)
        tasks.append(asyncio.create_task(http.start()))

    # Heartbeat publisher
    tasks.append(asyncio.create_task(heartbeat_loop(config, db, rhizome)))

    log.info("spore.running", spore_id=config.spore_id, tasks=len(tasks))

    # Graceful shutdown
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: [t.cancel() for t in tasks])

    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        log.info("spore.shutting_down", spore_id=config.spore_id)
    finally:
        await db.deregister_spore(config.spore_id)
        await db.disconnect()
        await rhizome.disconnect()


async def heartbeat_loop(config: "SporeConfig", db: "Database", rhizome: "RhizomeClient"):
    """Publish a heartbeat every 10 seconds so the AI Engine can detect dead Spores."""
    import time
    while True:
        await asyncio.sleep(10)
        await rhizome.publish("metrics.spore." + config.spore_id, {
            "spore_id": config.spore_id,
            "status": "alive",
            "ts": time.time(),
        })
        await db.update_heartbeat(config.spore_id)


if __name__ == "__main__":
    import structlog
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ]
    )
    asyncio.run(main())
