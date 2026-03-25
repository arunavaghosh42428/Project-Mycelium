#!/usr/bin/env python3
"""
Project Mycelium – Attack Simulation Suite (Phase 6)
Simulates real attacker techniques against the decoy grid for testing.

Usage:
  python simulate_attacks.py --target 127.0.0.1 --scenario all
  python simulate_attacks.py --target 127.0.0.1 --scenario portscan
  python simulate_attacks.py --target 127.0.0.1 --scenario brute
  python simulate_attacks.py --target 127.0.0.1 --scenario modbus
  python simulate_attacks.py --target 127.0.0.1 --scenario canary

WARNING: Run only against your own lab environment.
"""
import argparse
import asyncio
import random
import socket
import struct
import time
import httpx
import sys


TARGET = "127.0.0.1"

# ── Scenario 1: TCP Port Scan ─────────────────────────────────────────────────

async def scenario_portscan(target: str):
    print(f"\n[*] Scenario: TCP Port Scan → {target}")
    ports = list(range(1, 1025)) + [1883, 1884, 4222, 5020, 8080, 8081, 8082, 8083, 9999]
    open_ports = []
    for port in ports:
        try:
            conn = asyncio.open_connection(target, port)
            r, w = await asyncio.wait_for(conn, timeout=0.3)
            open_ports.append(port)
            w.close()
            await w.wait_closed()
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            pass
    print(f"[+] Open ports found: {open_ports}")
    return open_ports


# ── Scenario 2: HTTP Enumeration ──────────────────────────────────────────────

async def scenario_http_enum(target: str, port: int = 8081):
    print(f"\n[*] Scenario: HTTP Enumeration → {target}:{port}")
    paths = [
        "/", "/api/status", "/api/config", "/api/logs", "/api/credentials",
        "/.env", "/admin", "/setup.cgi", "/HNAP1/", "/cgi-bin/admin.cgi",
        "/wp-admin/", "/.git/config", "/api/v1/users", "/backup.zip",
        "/etc/passwd", "/shell", "/goform/formLogin",
    ]
    async with httpx.AsyncClient(timeout=5) as client:
        for path in paths:
            try:
                r = await client.get(f"http://{target}:{port}{path}")
                status = r.status_code
                marker = "✓" if status == 200 else "·"
                print(f"  {marker} {status} {path}")
                if status == 200 and "canary" in r.text.lower():
                    print(f"      ^^^ CANARY TOKEN DETECTED in response!")
                await asyncio.sleep(0.05)
            except Exception as e:
                print(f"  ✗ ERR {path}: {e}")


# ── Scenario 3: MQTT Brute Force ──────────────────────────────────────────────

async def scenario_mqtt_brute(target: str, port: int = 1883):
    print(f"\n[*] Scenario: MQTT Brute-Force → {target}:{port}")
    creds = [("admin","admin"), ("admin","1234"), ("root","root"),
             ("user","password"), ("mqtt","mqtt"), ("admin","password123")]

    def make_connect(client_id: str, user: str, pw: str) -> bytes:
        # Minimal MQTT CONNECT packet
        cid     = client_id.encode()
        usr     = user.encode()
        pwd     = pw.encode()
        proto   = b"\x00\x04MQTT\x04"  # protocol name + level
        flags   = bytes([0b11000010])   # clean session + user+pass flags
        ka      = b"\x00\x3c"           # keepalive 60s
        payload = (
            len(cid).to_bytes(2,"big") + cid +
            len(usr).to_bytes(2,"big") + usr +
            len(pwd).to_bytes(2,"big") + pwd
        )
        var_header = proto + flags + ka
        rem_len    = len(var_header) + len(payload)
        return bytes([0x10, rem_len]) + var_header + payload

    for user, pw in creds:
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=3)
            w.write(make_connect(f"hacker_{random.randint(1000,9999)}", user, pw))
            await w.drain()
            resp = await asyncio.wait_for(r.read(4), timeout=2)
            rc   = resp[3] if len(resp) >= 4 else -1
            print(f"  [{user}:{pw}] → CONNACK return_code={rc} {'(accepted!)' if rc==0 else ''}")
            w.close()
            await w.wait_closed()
        except Exception as e:
            print(f"  [{user}:{pw}] → error: {e}")
        await asyncio.sleep(0.1)


# ── Scenario 4: Modbus Read Sweep ─────────────────────────────────────────────

async def scenario_modbus_sweep(target: str, port: int = 502):
    print(f"\n[*] Scenario: Modbus Register Sweep → {target}:{port}")
    try:
        r, w = await asyncio.wait_for(
            asyncio.open_connection(target, port), timeout=5)
    except Exception as e:
        print(f"  Cannot connect: {e}"); return

    for reg_start in range(0, 200, 10):
        tid = random.randint(0, 65535)
        # Read Holding Registers: FC=3, start, count=10
        pdu    = struct.pack(">BBHH", 1, 0x03, reg_start, 10)
        mbap   = struct.pack(">HHH", tid, 0, len(pdu))
        w.write(mbap + pdu)
        await w.drain()
        try:
            resp = await asyncio.wait_for(r.read(256), timeout=2)
            if len(resp) > 8:
                n_bytes = resp[8]
                vals    = []
                for i in range(0, n_bytes, 2):
                    vals.append(int.from_bytes(resp[9+i:11+i], "big"))
                print(f"  Regs {reg_start:03d}-{reg_start+9:03d}: {vals}")
        except asyncio.TimeoutError:
            print(f"  Regs {reg_start:03d}: timeout")
        await asyncio.sleep(0.05)
    w.close()
    await w.wait_closed()


# ── Scenario 5: Canary Token Exfiltration ────────────────────────────────────

async def scenario_canary_exfil(target: str, canary_port: int = 9999):
    print(f"\n[*] Scenario: Simulating attacker exfiltrating canary token")
    # 1. Fetch a device config to grab the canary URL
    port = 8081
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            cfg_resp = await client.get(f"http://{target}:{port}/api/config")
            cfg      = cfg_resp.json()
            canary_url = cfg.get("_update_url", "")
            if not canary_url:
                print("  No canary URL found in config – trying credentials endpoint")
                cred_resp = await client.get(f"http://{target}:{port}/api/credentials")
                import json, re
                m = re.search(r"http://[^\"'\s]+/c/([a-f0-9]+)", cred_resp.text)
                if m:
                    canary_url = m.group(0)

            if canary_url:
                print(f"  Found canary: {canary_url}")
                # Simulate attacker fetching the canary
                hit = await client.get(canary_url, headers={
                    "User-Agent": "curl/7.88.1",
                    "Referer":    f"http://{target}:{port}/api/config",
                })
                print(f"  Token hit response: {hit.status_code} – ALERT SHOULD FIRE!")
            else:
                print("  No canary URL found in any endpoint")
        except Exception as e:
            print(f"  Error: {e}")


# ── Scenario 6: Rapid HTTP Flood (scan detection) ────────────────────────────

async def scenario_http_flood(target: str, port: int = 8081):
    print(f"\n[*] Scenario: HTTP Flood (trigger scan detection) → {target}:{port}")
    async with httpx.AsyncClient(timeout=5) as client:
        tasks = [
            client.get(f"http://{target}:{port}/api/status")
            for _ in range(30)
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        ok = sum(1 for r in results if isinstance(r, httpx.Response))
        print(f"  Sent 30 rapid requests → {ok} OK (threat alert should trigger)")


# ── Runner ────────────────────────────────────────────────────────────────────

SCENARIOS = {
    "portscan": lambda t: scenario_portscan(t),
    "http":     lambda t: scenario_http_enum(t),
    "brute":    lambda t: scenario_mqtt_brute(t),
    "modbus":   lambda t: scenario_modbus_sweep(t),
    "canary":   lambda t: scenario_canary_exfil(t),
    "flood":    lambda t: scenario_http_flood(t),
}

async def run(target: str, scenario: str):
    print(f"{'='*60}")
    print(f"  Project Mycelium – Attack Simulator")
    print(f"  Target   : {target}")
    print(f"  Scenario : {scenario}")
    print(f"{'='*60}")

    if scenario == "all":
        for name, fn in SCENARIOS.items():
            await fn(target)
            await asyncio.sleep(1)
    elif scenario in SCENARIOS:
        await SCENARIOS[scenario](target)
    else:
        print(f"Unknown scenario '{scenario}'. Choices: {list(SCENARIOS)} | all")
        sys.exit(1)

    print(f"\n[✓] Simulation complete. Check the Mycelium dashboard for alerts.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mycelium Attack Simulator")
    parser.add_argument("--target",   default="127.0.0.1", help="Target IP")
    parser.add_argument("--scenario", default="all",       help="Scenario to run")
    args = parser.parse_args()
    asyncio.run(run(args.target, args.scenario))
