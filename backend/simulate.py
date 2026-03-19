#!/usr/bin/env python3
"""
Threat Simulation Script for NO TIME TO HACK
=============================================
Simulates realistic network attack traffic by posting fake packet feature
dictionaries directly into the event bus — no Scapy or root required.

Usage (development):
    cd backend
    pip install -r requirements.txt
    python simulate.py --scenario port_scan
    python simulate.py --scenario syn_flood
    python simulate.py --scenario brute_force
    python simulate.py --scenario mixed --count 200

The backend must be running:
    uvicorn app.main:app --reload --port 8000
"""
from __future__ import annotations

import argparse
import asyncio
import random
from datetime import datetime


# ── Fake packet generators ────────────────────────────────────────────────────

_ATTACKER_IPS = [
    "1.2.3.4",
    "5.6.7.8",
    "91.108.56.100",
    "185.220.101.50",
    "198.51.100.25",
]

_AUTH_PORTS = [22, 23, 3389, 5900, 21]
_HIGH_PORTS = list(range(20, 10000))


def _base_packet(src_ip: str) -> dict:
    return {
        "src_ip": src_ip,
        "dst_ip": "192.168.1.1",
        "pkt_len": random.randint(40, 1500),
        "protocol": "tcp",
        "dst_port": None,
        "src_port": random.randint(1024, 65535),
        "flags": "S",
        "is_syn": True,
        "is_ack": False,
        "is_rst": False,
        "timestamp": datetime.utcnow().isoformat(),
    }


def gen_port_scan(count: int) -> list[dict]:
    ip = random.choice(_ATTACKER_IPS)
    return [
        {**_base_packet(ip), "dst_port": p}
        for p in random.sample(_HIGH_PORTS, min(count, len(_HIGH_PORTS)))
    ]


def gen_syn_flood(count: int) -> list[dict]:
    ip = random.choice(_ATTACKER_IPS)
    return [
        {**_base_packet(ip), "dst_port": 80, "is_syn": True}
        for _ in range(count)
    ]


def gen_brute_force(count: int) -> list[dict]:
    ip = random.choice(_ATTACKER_IPS)
    port = random.choice(_AUTH_PORTS)
    pkts = []
    for _ in range(count):
        p = _base_packet(ip)
        p["dst_port"] = port
        p["is_syn"] = False
        p["is_ack"] = True
        p["flags"] = "A"
        pkts.append(p)
    return pkts


def gen_mixed(count: int) -> list[dict]:
    pkts = []
    for _ in range(count):
        scenario = random.choice(["port_scan", "syn_flood", "brute_force"])
        ip = random.choice(_ATTACKER_IPS)
        p = _base_packet(ip)
        if scenario == "port_scan":
            p["dst_port"] = random.randint(1, 9999)
        elif scenario == "syn_flood":
            p["dst_port"] = 80
        else:
            p["dst_port"] = random.choice(_AUTH_PORTS)
            p["is_syn"] = False
            p["is_ack"] = True
        pkts.append(p)
    return pkts


# ── Main ──────────────────────────────────────────────────────────────────────

async def run(scenario: str, count: int, delay_ms: float) -> None:
    import sys
    import os
    sys.path.insert(0, os.path.dirname(__file__))

    from app.core.logger import setup_logging
    from app.core.event_bus import start_event_bus, publish

    # Import agents so they subscribe
    import app.agents.threat_agent      # noqa: F401
    import app.agents.decision_agent    # noqa: F401
    import app.agents.enforcement_agent # noqa: F401
    import app.agents.reporting_agent   # noqa: F401

    setup_logging()
    await start_event_bus()

    # Init DB
    from app.database.session import init_db
    await init_db()

    generators = {
        "port_scan": gen_port_scan,
        "syn_flood": gen_syn_flood,
        "brute_force": gen_brute_force,
        "mixed": gen_mixed,
    }
    packets = generators[scenario](count)
    print(f"[SIM] Injecting {len(packets)} packets — scenario: {scenario}")

    for i, pkt in enumerate(packets):
        await publish("device_seen", pkt)
        if delay_ms > 0:
            await asyncio.sleep(delay_ms / 1000)
        if (i + 1) % 50 == 0:
            print(f"[SIM] {i + 1}/{len(packets)} packets sent")

    # Wait for pipeline to process
    print("[SIM] Waiting for agent pipeline to finish...")
    await asyncio.sleep(3)
    print("[SIM] Done.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NTTH Threat Simulator")
    parser.add_argument("--scenario", choices=["port_scan", "syn_flood", "brute_force", "mixed"], default="mixed")
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--delay-ms", type=float, default=10, help="Delay between packets in ms")
    args = parser.parse_args()
    asyncio.run(run(args.scenario, args.count, args.delay_ms))
