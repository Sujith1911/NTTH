#!/usr/bin/env python3
"""
Realtime regression checks for NO TIME TO HACK.

Validates:
- topology_updated events reach websocket clients
- threat events include the frontend-required fields
- scan-triggered device discovery persists records immediately
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

from app.core.event_bus import publish
from app.database.session import AsyncSessionLocal, init_db
from app import main as main_module
from app.main import app as fastapi_app
from app.websocket import live_updates

import app.agents.decision_agent  # noqa: F401
import app.agents.enforcement_agent  # noqa: F401
import app.agents.reporting_agent  # noqa: F401
import app.agents.threat_agent  # noqa: F401
from app.database import crud
from app.api import routes_topology


class FakeWebSocket:
    def __init__(self) -> None:
        self.messages: list[dict] = []

    async def send_text(self, payload: str) -> None:
        self.messages.append(json.loads(payload))


async def _persist_fake_scan_devices() -> list[dict]:
    devices = [
        {
            "src_ip": "198.51.100.10",
            "mac_address": "aa:bb:cc:dd:ee:01",
            "hostname": "scan-host",
            "vendor": "Regression Labs",
            "pkt_len": 0,
            "protocol": "arp_scan",
            "dst_port": None,
            "src_port": None,
            "flags": None,
            "is_syn": False,
            "is_ack": False,
            "is_rst": False,
            "timestamp": "2026-03-19T00:00:00Z",
        }
    ]
    async with AsyncSessionLocal() as db:
        for device in devices:
            await crud.upsert_device_details(
                db,
                device["src_ip"],
                mac_address=device["mac_address"],
                hostname=device["hostname"],
                vendor=device["vendor"],
            )
        await db.commit()
    return devices


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _login(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "changeme"},
    )
    response.raise_for_status()
    body = response.json()
    return {"Authorization": f"Bearer {body['access_token']}"}


async def _inject_threat_sequence() -> None:
    base_packet = {
        "src_ip": "203.0.113.77",
        "dst_ip": "192.168.1.1",
        "pkt_len": 128,
        "protocol": "tcp",
        "src_port": 45678,
        "flags": "S",
        "is_syn": True,
        "is_ack": False,
        "is_rst": False,
        "timestamp": "2026-03-19T00:00:00Z",
    }
    for dst_port in range(20, 35):
        await publish("device_seen", {**base_packet, "dst_port": dst_port})
    await asyncio.sleep(1.5)


def main() -> int:
    asyncio.run(init_db())
    main_module.settings.http_honeypot_port = 18888

    fake_ws = FakeWebSocket()
    live_updates._connections.add(fake_ws)
    original_scan = routes_topology.scan_network
    routes_topology.scan_network = _persist_fake_scan_devices

    try:
        with TestClient(fastapi_app) as client:
            headers = _login(client)

            scan_response = client.post("/api/v1/network/scan", headers=headers, json={})
            scan_response.raise_for_status()
            asyncio.run(asyncio.sleep(0.3))

            devices_response = client.get("/api/v1/devices", headers=headers)
            devices_response.raise_for_status()
            devices = devices_response.json()["items"]
            _assert(
                any(device["ip_address"] == "198.51.100.10" for device in devices),
                "Expected scan-discovered device to be persisted",
            )

            asyncio.run(_inject_threat_sequence())

        topology_events = [msg for msg in fake_ws.messages if msg.get("type") == "topology_updated"]
        threat_events = [msg for msg in fake_ws.messages if msg.get("type") == "threat"]

        _assert(topology_events, "Expected at least one topology_updated event")
        _assert(threat_events, "Expected at least one threat event")

        topology = topology_events[-1]
        _assert("devices_found" in topology, "topology_updated missing devices_found")
        _assert("timestamp" in topology, "topology_updated missing timestamp")

        threat = threat_events[-1]
        required_fields = {
            "id",
            "src_ip",
            "dst_ip",
            "dst_port",
            "protocol",
            "threat_type",
            "risk_score",
            "action_taken",
            "country",
            "city",
            "asn",
            "org",
            "latitude",
            "longitude",
            "detected_at",
            "acknowledged",
        }
        missing = sorted(required_fields.difference(threat))
        _assert(not missing, f"Threat event missing fields: {missing}")

        print("realtime regression checks passed")
        print(f"topology event: {json.dumps(topology)}")
        print(
            "threat sample: "
            + json.dumps(
                {key: threat.get(key) for key in sorted(required_fields)},
                default=str,
            )
        )
        return 0
    finally:
        routes_topology.scan_network = original_scan
        live_updates._connections.discard(fake_ws)


if __name__ == "__main__":
    raise SystemExit(main())
