"""
Network topology endpoint — returns devices, their relationships,
honeypot node, gateway node, and live packet stats for the topology map.
Also exposes a POST /scan trigger to kick off a network scan on demand.
"""
from __future__ import annotations

import socket
import json
from ipaddress import ip_address, ip_network

from fastapi import APIRouter, BackgroundTasks, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.event_bus import publish
from app.core.logger import get_logger
from app.core.time_utils import local_now_iso
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
        import subprocess
        import sys
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


def _display_local_ip(request: Request, devices) -> str:
    if settings.server_display_ip:
        return settings.server_display_ip
    host = request.url.hostname or ""
    if host not in {"127.0.0.1", "localhost", "::1"}:
        return host
    detected = _get_local_ip()
    if detected != "127.0.0.1":
        return detected
    trusted = next((device.ip_address for device in devices if getattr(device, "is_trusted", False)), None)
    if trusted:
        return trusted
    return detected


def _should_hide_ip(ip: str) -> bool:
    try:
        parsed = ip_address(ip)
    except ValueError:
        return True
    return any(parsed in network for network in _IGNORED_DISPLAY_NETWORKS)


def _is_local_managed_ip(ip: str) -> bool:
    try:
        parsed = ip_address(ip)
    except ValueError:
        return False
    subnet = settings.scan_subnet or ""
    if subnet:
        try:
            return parsed in ip_network(subnet, strict=False)
        except ValueError:
            pass
    return parsed.is_private


def _risk_details(events) -> list[dict]:
    details = []
    for event in events:
        notes = {}
        if event.notes:
            try:
                notes = json.loads(event.notes)
            except Exception:
                notes = {}
        reasons = [
            f"Threat type: {event.threat_type}",
            f"Rule score: {event.rule_score:.2f}" if event.rule_score is not None else None,
            f"ML anomaly score: {event.ml_score:.2f}" if event.ml_score is not None else None,
            f"Action: {event.action_taken or 'observe'}",
            f"Destination: {event.dst_ip or '-'}:{event.dst_port or '-'}",
            notes.get("decision_reason"),
            notes.get("response_mode"),
        ]
        details.append({
            "threat_type": event.threat_type,
            "risk_score": event.risk_score,
            "rule_score": event.rule_score,
            "ml_score": event.ml_score,
            "action": event.action_taken,
            "detected_at": event.detected_at.isoformat() if event.detected_at else None,
            "reasons": [reason for reason in reasons if reason],
        })
    return details


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
    local_ip = _display_local_ip(request, devices)

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
    blocked_ips = {r.target_ip for r in firewall_rules if r.is_active and r.rule_type in {"block", "drop"}}
    redirected_ips = {r.target_ip for r in firewall_rules if r.is_active and r.rule_type == "redirect"}
    throttled_ips = {r.target_ip for r in firewall_rules if r.is_active and r.rule_type == "rate_limit"}
    known_device_ips = {device.ip_address for device in devices}
    local_session_ips = {
        session.attacker_ip
        for session in honeypot_sessions
        if _is_local_managed_ip(session.attacker_ip)
    }
    local_candidate_ips = (
        known_device_ips
        | local_session_ips
        | {ip for ip in blocked_ips | redirected_ips | throttled_ips if _is_local_managed_ip(ip)}
    )
    risk_events = await crud.latest_threat_events_for_ips(
        db,
        list(local_candidate_ips),
        limit_per_ip=5,
    )

    # Devices (skip gateway/server — they have dedicated nodes above)
    _infrastructure_ips = {gateway_ip, local_ip}
    for device in devices:
        if device.ip_address in _infrastructure_ips:
            continue
        node_id = f"dev_{device.ip_address.replace('.', '_')}"
        live = stats_map.get(device.ip_address, {})
        # Parse open_ports from JSON string
        _open_ports = []
        if device.open_ports:
            import json
            try:
                _open_ports = json.loads(device.open_ports)
            except Exception:
                pass
        nodes.append({
            "id": node_id,
            "device_id": device.id,
            "ip": device.ip_address,
            "mac": device.mac_address,
            "hostname": device.hostname,
            "vendor": device.vendor,
            "open_ports": _open_ports,
            "label": device.hostname or device.ip_address,
            "type": "device",
            "is_trusted": device.is_trusted,
            "risk_score": device.risk_score,
            "risk_details": _risk_details(risk_events.get(device.ip_address, [])),
            "first_seen": device.first_seen.isoformat() if device.first_seen else None,
            "last_seen": device.last_seen.isoformat() if device.last_seen else None,
            "is_blocked": device.ip_address in blocked_ips,
            "is_redirected": device.ip_address in redirected_ips,
            "is_throttled": device.ip_address in throttled_ips,
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
        if device.ip_address in redirected_ips or device.risk_score > 0.85:
            edges.append({
                "from": node_id,
                "to": "honeypot",
                "type": "redirected",
            })

    # Synthetic nodes: only show IPs from RECENT sessions or ACTIVE enforcement
    # that don't already have a device entry — prevents stale blocked/unknown nodes
    known_ips = set(known_device_ips)
    from datetime import datetime, timedelta
    _recent_cutoff = datetime.utcnow() - timedelta(hours=1)

    # Only include honeypot session IPs that are recent (within last hour)
    recent_session_ips = {
        session.attacker_ip
        for session in honeypot_sessions
        if _is_local_managed_ip(session.attacker_ip)
        and session.started_at and session.started_at > _recent_cutoff
    }

    synthetic_local_ips = sorted(
        ip
        for ip in recent_session_ips | blocked_ips | redirected_ips | throttled_ips
        if ip not in known_ips and ip not in _infrastructure_ips and _is_local_managed_ip(ip)
    )
    for ip in synthetic_local_ips:
        node_id = f"dev_{ip.replace('.', '_')}"
        latest_events = risk_events.get(ip, [])
        latest_risk = max([event.risk_score or 0 for event in latest_events] or [0.0])
        session_count = len([
            s for s in honeypot_sessions
            if s.attacker_ip == ip and s.started_at and s.started_at > _recent_cutoff
        ])
        nodes.append({
            "id": node_id,
            "device_id": None,
            "ip": ip,
            "label": ip,
            "type": "device",
            "is_trusted": False,
            "risk_score": max(latest_risk, 1.0 if ip in blocked_ips else (0.75 if session_count else 0.0)),
            "risk_details": _risk_details(latest_events),
            "is_blocked": ip in blocked_ips,
            "is_redirected": ip in redirected_ips,
            "is_throttled": ip in throttled_ips,
            "source": "honeypot_or_firewall",
            "honeypot_sessions": session_count,
            "live": stats_map.get(ip, {}),
        })
        edges.append({"from": "gateway", "to": node_id, "risk_score": latest_risk})
        if ip in redirected_ips or session_count:
            edges.append({"from": node_id, "to": "honeypot", "type": "attack"})
        known_ips.add(ip)

    for session in honeypot_sessions[:20]:
        if _should_hide_ip(session.attacker_ip):
            continue
        if _is_local_managed_ip(session.attacker_ip):
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
        completed_at = get_scan_state()["completed_at"] or local_now_iso()
        # Publish topology_updated so WS clients refresh
        await publish("topology_updated", {
            "type": "topology_updated",
            "devices_found": len(devices),
            "timestamp": completed_at,
        })
        log.info("topology.scan_complete", devices=len(devices))
    except Exception as exc:
        log.error("topology.scan_error", error=str(exc))
