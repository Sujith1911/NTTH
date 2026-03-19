"""
Network topology endpoint — returns devices, their relationships,
honeypot node, gateway node, and live packet stats for the topology map.
Also exposes a POST /scan trigger to kick off a network scan on demand.
"""
from __future__ import annotations

import asyncio
import socket
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.event_bus import publish
from app.core.logger import get_logger
from app.database import crud
from app.dependencies import get_current_user, get_db
from app.monitor.network_scanner import get_live_stats, scan_network

log = get_logger("routes_topology")
router = APIRouter()

_scan_running = False
_last_scan: Optional[str] = None


def _get_gateway() -> str:
    """Try to detect gateway IP from routing table."""
    try:
        import subprocess, sys
        if sys.platform == "win32":
            out = subprocess.check_output(["route", "print", "0.0.0.0"],
                                          text=True, timeout=5)
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[0] == "0.0.0.0":
                    return parts[2]
        else:
            out = subprocess.check_output(["ip", "route", "show", "default"],
                                          text=True, timeout=5)
            for line in out.splitlines():
                if "default via" in line:
                    return line.split()[2]
    except Exception:
        pass
    return "192.168.1.1"


def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


@router.get("/topology")
async def get_topology(
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
):
    """
    Returns the full network topology:
    - nodes: gateway, local server, each device, honeypot
    - edges: connectivity between them
    - live_stats: real-time per-IP packet/byte counts
    """
    try:
        _, devices = await crud.list_devices(db, 1, 500)
        _, honeypot_sessions = await crud.list_honeypot_sessions(db, 1, 50)
        firewall_rules = await crud.list_active_firewall_rules(db)
    except Exception as exc:
        log.error("topology.db_error", error=str(exc))
        raise
    stats_map = {s["ip"]: s for s in get_live_stats()}

    gateway_ip = _get_gateway()
    local_ip = _get_local_ip()

    # Build nodes
    nodes = []
    edges = []

    # Gateway
    nodes.append({
        "id": "gateway",
        "ip": gateway_ip,
        "label": f"Router\n{gateway_ip}",
        "type": "gateway",
        "is_trusted": True,
        "risk_score": 0,
        "live": stats_map.get(gateway_ip, {}),
    })

    # This server (NTTH backend)
    nodes.append({
        "id": "server",
        "ip": local_ip,
        "label": f"NTTH Server\n{local_ip}",
        "type": "server",
        "is_trusted": True,
        "risk_score": 0,
        "live": stats_map.get(local_ip, {}),
    })
    edges.append({"from": "gateway", "to": "server"})

    # Honeypot node (always shown)
    nodes.append({
        "id": "honeypot",
        "ip": "honeypot",
        "label": "Honeypot\n(SSH/HTTP)",
        "type": "honeypot",
        "is_trusted": True,
        "risk_score": 0,
        "active_sessions": len([s for s in honeypot_sessions if s.ended_at is None]),
        "total_sessions": len(honeypot_sessions),
    })
    edges.append({"from": "server", "to": "honeypot"})

    # Blocked IPs from firewall rules
    blocked_ips = {r.target_ip for r in firewall_rules if r.is_active and r.rule_type == "block"}

    # Devices
    for device in devices:
        node_id = f"dev_{device.ip_address.replace('.', '_')}"
        live = stats_map.get(device.ip_address, {})
        nodes.append({
            "id": node_id,
            "ip": device.ip_address,
            "mac": device.mac_address,
            "hostname": device.hostname,
            "vendor": device.vendor,
            "label": device.hostname or device.ip_address,
            "type": "device",
            "is_trusted": device.is_trusted,
            "risk_score": device.risk_score,
            "first_seen": device.first_seen.isoformat() if device.first_seen else None,
            "last_seen": device.last_seen.isoformat() if device.last_seen else None,
            "is_blocked": device.ip_address in blocked_ips,
            "live": live,
        })
        # Device connects to gateway
        edge = {
            "from": "gateway",
            "to": node_id,
            "risk_score": device.risk_score,
        }
        edges.append(edge)

        # If device was redirected to honeypot (high-risk)
        if device.risk_score > 0.85 or device.ip_address in blocked_ips:
            edges.append({
                "from": node_id,
                "to": "honeypot",
                "type": "redirected",
            })

    # Honeypot sessions from external (non-local) IPs
    known_ips = {d.ip_address for d in devices}
    for session in honeypot_sessions[:20]:
        if session.attacker_ip not in known_ips:
            node_id = f"ext_{session.attacker_ip.replace('.', '_')}"
            if not any(n["id"] == node_id for n in nodes):
                nodes.append({
                    "id": node_id,
                    "ip": session.attacker_ip,
                    "label": f"Attacker\n{session.attacker_ip}",
                    "type": "attacker",
                    "is_trusted": False,
                    "risk_score": 1.0,
                    "country": session.country,
                })
            edges.append({
                "from": node_id,
                "to": "honeypot",
                "type": "attack",
            })

    return {
        "nodes": nodes,
        "edges": edges,
        "live_stats": get_live_stats(),
        "meta": {
            "local_ip": local_ip,
            "gateway_ip": gateway_ip,
            "last_scan": _last_scan,
            "scan_running": _scan_running,
        },
    }


@router.post("/scan")
async def trigger_scan(
    background_tasks: BackgroundTasks,
    _user=Depends(get_current_user),
):
    """Trigger a network scan in the background. Returns immediately."""
    global _scan_running
    if _scan_running:
        return {"status": "already_running"}
    background_tasks.add_task(_run_scan)
    return {"status": "started"}


@router.get("/scan/status")
async def scan_status(_user=Depends(get_current_user)):
    return {"running": _scan_running, "last_scan": _last_scan}


async def _run_scan():
    global _scan_running, _last_scan
    _scan_running = True
    try:
        devices = await scan_network()
        _last_scan = datetime.utcnow().isoformat()
        # Publish topology_updated so WS clients refresh
        await publish("topology_updated", {
            "type": "topology_updated",
            "devices_found": len(devices),
            "timestamp": _last_scan,
        })
        log.info("topology.scan_complete", devices=len(devices))
    except Exception as exc:
        log.error("topology.scan_error", error=str(exc))
    finally:
        _scan_running = False
