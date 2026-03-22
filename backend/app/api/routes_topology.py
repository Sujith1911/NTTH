"""
Network topology endpoint — returns devices, their relationships,
honeypot node, gateway node, and live packet stats for the topology map.
Also exposes a POST /scan trigger to kick off a network scan on demand.
"""
from __future__ import annotations

import asyncio
import socket
from datetime import datetime
from ipaddress import ip_address, ip_network
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.event_bus import publish
from app.core.logger import get_logger
from app.database import crud
from app.dependencies import get_current_user, get_db
from app.monitor.network_scanner import get_live_stats, get_scan_state, scan_network

log = get_logger("routes_topology")
router = APIRouter()
settings = get_settings()
_IGNORED_DISPLAY_NETWORKS = tuple(ip_network(cidr) for cidr in settings.ignored_monitor_cidrs)

def _get_gateway() -> str:
    """Prefer configured gateway IP for stable topology on Docker/Desktop."""
    if settings.gateway_ip:
        return settings.gateway_ip
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
    if settings.server_display_ip:
        return settings.server_display_ip
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip_address(ip) in ip_network("172.16.0.0/12"):
            return "127.0.0.1"
        return ip
    except Exception:
        return "127.0.0.1"


def _display_local_ip(request: Request) -> str:
    if settings.server_display_ip:
        return settings.server_display_ip
    host = request.url.hostname or ""
    if host not in {"127.0.0.1", "localhost", "::1"}:
        return host
    return _get_local_ip()


def _should_hide_ip(ip: str) -> bool:
    try:
        parsed = ip_address(ip)
    except ValueError:
        return True
    return any(parsed in network for network in _IGNORED_DISPLAY_NETWORKS)


@router.get("/topology")
async def get_topology(
    request: Request,
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
    scan_state = get_scan_state()

    gateway_ip = _get_gateway()
    local_ip = _display_local_ip(request)

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
        if _should_hide_ip(session.attacker_ip):
            continue
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
            "scan_subnet": settings.scan_subnet or (f"{gateway_ip}/24" if gateway_ip else ""),
            "last_scan": scan_state["completed_at"],
            "scan_running": scan_state["running"],
            "devices_found_last_scan": scan_state["device_count"],
        },
    }


@router.post("/scan")
async def trigger_scan(
    background_tasks: BackgroundTasks,
    _user=Depends(get_current_user),
):
    """Trigger a network scan in the background. Returns immediately."""
    if get_scan_state()["running"]:
        return {"status": "already_running"}
    background_tasks.add_task(_run_scan)
    return {"status": "started"}


@router.get("/scan/status")
async def scan_status(_user=Depends(get_current_user)):
    scan_state = get_scan_state()
    return {
        "running": scan_state["running"],
        "last_scan": scan_state["completed_at"],
        "devices_found": scan_state["device_count"],
    }


async def _run_scan():
    try:
        devices = await scan_network()
        completed_at = get_scan_state()["completed_at"] or datetime.utcnow().isoformat()
        # Publish topology_updated so WS clients refresh
        await publish("topology_updated", {
            "type": "topology_updated",
            "devices_found": len(devices),
            "timestamp": completed_at,
        })
        log.info("topology.scan_complete", devices=len(devices))
    except Exception as exc:
        log.error("topology.scan_error", error=str(exc))
