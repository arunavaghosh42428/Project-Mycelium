# 🍄 Project Mycelium

A decentralized, adaptive honeypot network that mimics biological mycelial communication. It detects IoT network scans, shares threat intelligence among decoys in real time, and dynamically changes topology to waste attacker resources and collect forensic data.

> **Lab use only.** Deploy in an isolated network environment. Do not expose to the public internet without a firewall.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                         Mycelium Network                             │
│                                                                      │
│   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐              │
│   │ Spore: Light│   │Spore: Therm │   │Spore: Camera│  + dynamic   │
│   │ MQTT/Modbus │   │  MQTT/HTTP  │   │    HTTP     │    spores    │
│   │    /HTTP    │   └──────┬──────┘   └──────┬──────┘              │
│   └──────┬──────┘          │                 │                      │
│          └─────────────────┼─────────────────┘                      │
│                            │                                         │
│                   ┌────────▼────────┐                               │
│                   │  NATS Rhizome   │  ◄── pub/sub backbone         │
│                   │  (threat.alert  │                                │
│                   │   threat.level  │                                │
│                   │   command.*)    │                                │
│                   └────────┬────────┘                               │
│                            │                                         │
│          ┌─────────────────┼──────────────────┐                     │
│          │                 │                  │                      │
│   ┌──────▼──────┐  ┌───────▼──────┐  ┌───────▼──────┐             │
│   │ Enzymatic AI│  │Canary Server │  │  Dashboard   │             │
│   │   Engine    │  │  (token hits)│  │  (FastAPI +  │             │
│   │(classifier/ │  │  + alerting  │  │   React UI)  │             │
│   │  spawner)   │  └──────────────┘  └──────────────┘             │
│   └─────────────┘                                                   │
│                                                                      │
│   ┌──────────────────────────────────────────────────────────┐      │
│   │  PostgreSQL + TimescaleDB  (connections, threats, canary)│      │
│   └──────────────────────────────────────────────────────────┘      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- Docker Engine 24+ and Docker Compose v2
- 4 GB RAM minimum
- Linux (Ubuntu 20.04+ recommended)

### 1. Clone and configure

```bash
git clone <repo>
cd mycelium
cp .env.example .env
# Edit .env — at minimum change DB_PASSWORD
```

### 2. Build and start all services

```bash
docker compose up --build -d
```

All six SRS phases come up automatically:

| Service | Phase | URL / Port |
|---|---|---|
| Spore (smart light) | 1 | HTTP :8081 · MQTT :1883 · Modbus :502 |
| Spore (thermostat)  | 1 | HTTP :8082 · MQTT :1884 |
| Spore (IP camera)   | 1 | HTTP :8083 |
| NATS Rhizome        | 2 | :4222 (clients) · :8222 (monitor) |
| AI Engine           | 3 | (internal) |
| Canary Server       | 4 | :9999 |
| Dashboard           | 5 | **http://localhost:3000** |
| Grafana             | 5 | http://localhost:3001 (admin / see .env) |

### 3. Verify everything is running

```bash
docker compose ps
docker compose logs -f ai_engine
```

---

## Phases Reference

### Phase 1 – Spore Nodes

Three containerized decoys emulating real IoT protocols:

- **MQTT** (port 1883/1884) — accepts connections, publishes fake sensor data, detects brute-force
- **Modbus TCP** (port 502) — responds to register reads with realistic fake values, detects sweep scans
- **HTTP API** (port 8080–8083) — full REST API with `/api/status`, `/api/config`, `/api/credentials`, `/api/logs`; detects path traversal and exploit probes

All interactions are logged to PostgreSQL with source IP, timestamp, and payload.

### Phase 2 – Rhizome Communication Layer

NATS message broker connects all Spores and the AI Engine:

| Subject | Direction | Purpose |
|---|---|---|
| `threat.alert` | Spore → all | New threat detected |
| `threat.level` | AI → all | Global level changed |
| `command.banner_change` | AI → Spores | Rotate device fingerprint |
| `command.spawn` | AI → Spawner | Create new decoys |
| `canary.hit` | Canary → all | Token was accessed |
| `metrics.spore.*` | Spore → AI | Heartbeat / liveness |

### Phase 3 – Enzymatic AI Engine

Rule-based threat classifier with adaptive response:

| Score | Level | Action |
|---|---|---|
| < 0.30 | **Low** | Log only |
| 0.30–0.65 | **Medium** | Rotate all Spore banners |
| ≥ 0.65 | **High** | Spawn 5 new decoy containers + rotate fingerprints |

The classifier weights events by type, burst rate, and recency. Scores decay over 5 minutes of inactivity.

### Phase 4 – Canary Tokens

Every fake config, credentials file, and log response contains embedded canary URLs. When an attacker fetches one:

1. Hit logged to DB with source IP, User-Agent, Referer
2. `canary.hit` published to NATS
3. Optional webhook (Slack/Discord) or email alert fired

Set `WEBHOOK_URL` and/or `ALERT_EMAIL` in `.env` to enable alerting.

### Phase 5 – Dashboard

- **http://localhost:3000** — Custom React dashboard with:
  - Live network topology graph (spores + attacker movements)
  - Event timeline chart (colour-coded by severity)
  - Real-time event stream via SSE
  - Canary hit log
  - Deception score metrics (interactions, IPs, time wasted)
- **http://localhost:3001** — Grafana with TimescaleDB for time-series queries

### Phase 6 – Testing & Hardening

```bash
# Run all attack simulations against the local lab
python scripts/simulate_attacks.py --target 127.0.0.1 --scenario all

# Individual scenarios
python scripts/simulate_attacks.py --target 127.0.0.1 --scenario portscan
python scripts/simulate_attacks.py --target 127.0.0.1 --scenario brute
python scripts/simulate_attacks.py --target 127.0.0.1 --scenario modbus
python scripts/simulate_attacks.py --target 127.0.0.1 --scenario canary
python scripts/simulate_attacks.py --target 127.0.0.1 --scenario flood
```

You can also use standard tools against the lab:

```bash
# nmap scan — should trigger port_scan threat alerts
nmap -sV -p 1-9999 127.0.0.1

# Modbus scanner
nmap --script modbus-discover -p 502 127.0.0.1
```

---

## Enabling TLS for the Rhizome

```bash
chmod +x scripts/gen_certs.sh
./scripts/gen_certs.sh
```

Then uncomment the `tls { }` block in `rhizome/nats.conf` and rebuild:

```bash
docker compose up --build -d nats
```

---

## Spawning Additional Decoys Manually

```bash
docker compose run --rm ai_engine python -c "
import asyncio
from spawner import SporeSpawner
async def main():
    s = SporeSpawner()
    await s.spawn_batch(3, trigger_ip='manual')
asyncio.run(main())
"
```

---

## Directory Structure

```
mycelium/
├── docker-compose.yml
├── .env.example
├── rhizome/
│   ├── nats.conf
│   └── certs/          ← generated by gen_certs.sh
├── spore/
│   ├── spore_main.py   ← entry point
│   ├── spore_config.py
│   ├── rhizome_client.py
│   ├── fake_data.py
│   ├── canary.py
│   ├── db.py
│   └── protocols/
│       ├── http_emulator.py
│       ├── mqtt_emulator.py
│       └── modbus_emulator.py
├── ai_engine/
│   ├── engine.py       ← main AI loop
│   ├── classifier.py
│   └── spawner.py
├── canary_server/
│   └── server.py
├── dashboard/
│   ├── app.py          ← FastAPI backend
│   └── static/
│       └── index.html  ← React frontend
├── shared/
│   ├── init.sql        ← TimescaleDB schema
│   └── grafana/
│       └── provisioning/
└── scripts/
    ├── simulate_attacks.py
    └── gen_certs.sh
```

---

## Stopping and Cleanup

```bash
# Stop all containers
docker compose down

# Remove volumes (wipes all logs and data)
docker compose down -v
```
