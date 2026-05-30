"""
System routes: health check, dashboard stats, logs, emergency flush.
"""
from __future__ import annotations

import ipaddress
import socket
import shutil
import subprocess

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.event_bus import get_metrics
from app.database import crud
from app.database.schemas import DashboardStats, HealthResponse, PaginatedResponse, SystemLogRead
from app.dependencies import get_current_user, get_db, require_admin
from app.monitor.network_scanner import get_effective_scan_subnet, get_scan_state

router = APIRouter()
settings = get_settings()

def _firewall_runtime() -> tuple[bool, str, str | None]:
    nft_available = shutil.which("nft") is not None
    if not settings.firewall_enabled:
        return True, "simulation", "Firewall enforcement is disabled in deployment configuration."
    if not nft_available:
        return True, "degraded", "nftables is unavailable in this runtime, so actions are detected but not enforced."
    return True, "enforcing", None


async def _honeypot_ready() -> bool:
    try:
        from app.honeypot.cowrie_controller import get_cowrie_status
        status = await get_cowrie_status()
        return status.get("status") == "running"
    except Exception:
        return False


async def _security_agents() -> list[dict]:
    firewall_enabled, firewall_mode, firewall_reason = _firewall_runtime()
    honeypot_ready = await _honeypot_ready()
    enforcement_status = "active" if firewall_mode == "enforcing" else firewall_mode
    return [
        {
            "id": "detector",
            "name": "Detection Agent",
            "status": "active",
            "summary": "Scores packets and scans for suspicious behavior.",
        },
        {
            "id": "decision",
            "name": "Decision Agent",
            "status": "active",
            "summary": "Chooses observe, throttle, redirect, or block.",
        },
        {
            "id": "enforcement",
            "name": "Enforcement Agent",
            "status": enforcement_status,
            "summary": firewall_reason or "Applies firewall containment and redirect rules.",
        },
        {
            "id": "deception",
            "name": "Deception Agent",
            "status": "active" if honeypot_ready else "degraded",
            "summary": "Runs the honeypot and diverts hostile traffic into it.",
        },
        {
            "id": "intel",
            "name": "Intel Agent",
            "status": "active",
            "summary": "Enriches attacker IPs with approximate GeoIP, ASN, and org hints.",
        },
        {
            "id": "reporting",
            "name": "Reporting Agent",
            "status": "active",
            "summary": "Persists incidents and streams them live to the UI.",
        },
    ]


def _capture_runtime(sniffer_running: bool) -> tuple[str, str, str | None, bool, str | None]:
    capture_interface = settings.network_interface or "auto"
    capture_ip = None
    if capture_interface and capture_interface != "auto":
        try:
            output = subprocess.check_output(
                ["ip", "-4", "-o", "addr", "show", "dev", capture_interface],
                text=True,
                timeout=2,
                stderr=subprocess.DEVNULL,
            )
            parts = output.split()
            if "inet" in parts:
                capture_ip = parts[parts.index("inet") + 1].split("/", 1)[0]
        except Exception:
            capture_ip = None
    if capture_ip is None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            capture_ip = sock.getsockname()[0]
            sock.close()
        except Exception:
            capture_ip = None

    degraded = False
    reason = None
    realtime_mode = "packet_capture" if sniffer_running else "scan_fallback"

    scan_subnet = (settings.scan_subnet or get_effective_scan_subnet() or "").strip()
    if sniffer_running and capture_ip and scan_subnet:
        try:
            scan_network = ipaddress.ip_network(scan_subnet, strict=False)
            if ipaddress.ip_address(capture_ip) not in scan_network:
                degraded = True
                realtime_mode = "scan_fallback"
                reason = (
                    f"Packet capture is attached to {capture_ip} on {capture_interface}, "
                    f"outside scan subnet {scan_network}."
                )
        except ValueError:
            pass

    if not sniffer_running and reason is None:
        reason = "Packet capture is unavailable; device freshness depends on scheduled and manual scans."

    return realtime_mode, capture_interface, capture_ip, degraded, reason


@router.get("/health", response_model=HealthResponse)
async def health_check(db: AsyncSession = Depends(get_db)):
    db_ok = False
    try:
        await db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        pass

    # Guard sniffer_running — packet_sniffer is not available on Windows
    sniffer_running = False
    try:
        from app.monitor import packet_sniffer
        sniffer_running = packet_sniffer.is_running()
    except Exception:
        pass

    from app.core.scheduler import get_scheduler
    scheduler = get_scheduler()
    ws_clients = 0
    try:
        from app.websocket.live_updates import connection_count
        ws_clients = connection_count()
    except Exception:
        pass
    event_bus_metrics = get_metrics()
    scan_state = get_scan_state()
    effective_scan_subnet = settings.scan_subnet or scan_state.get("subnet") or ""
    realtime_mode, capture_interface, capture_ip, capture_degraded, capture_reason = _capture_runtime(
        sniffer_running
    )
    firewall_enabled, firewall_mode, firewall_reason = _firewall_runtime()
    honeypot_ready = await _honeypot_ready()
    agents = await _security_agents()
    active_agents = sum(1 for agent in agents if agent["status"] == "active")

    return HealthResponse(
        status="ok" if db_ok and not capture_degraded else "degraded",
        version=settings.app_version,
        environment=settings.environment,
        db_ok=db_ok,
        sniffer_running=sniffer_running,
        scheduler_running=scheduler.running if scheduler else False,
        websocket_clients=ws_clients,
        event_bus_backlog=event_bus_metrics["queue_size"],
        event_bus_subscribers=event_bus_metrics["subscriber_handlers"],
        realtime_mode=realtime_mode,
        capture_interface=capture_interface,
        capture_ip=capture_ip,
        scan_subnet=str(effective_scan_subnet),
        packet_capture_degraded=capture_degraded,
        packet_capture_reason=capture_reason,
        last_scan=scan_state["completed_at"],
        discovered_devices=scan_state["device_count"],
        firewall_enabled=firewall_enabled,
        firewall_mode=firewall_mode,
        firewall_reason=firewall_reason,
        honeypot_ready=honeypot_ready,
        security_agents_active=active_agents,
        security_agents_total=len(agents),
    )


@router.get("/stats", response_model=DashboardStats)
async def dashboard_stats(
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
):
    """Return aggregate counts for the dashboard (devices, threats, rules, sessions)."""
    raw = await crud.get_dashboard_stats(db)
    return DashboardStats(**raw)


@router.get("/agents")
async def list_security_agents(_user=Depends(get_current_user)):
    return {"items": await _security_agents()}


@router.get("/logs", response_model=PaginatedResponse)
async def list_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _admin=Depends(require_admin),
):
    total, logs = await crud.list_system_logs(db, page, page_size)
    return PaginatedResponse(
        total=total, page=page, page_size=page_size,
        items=[SystemLogRead.model_validate(l) for l in logs],
    )


@router.post("/emergency-flush")
async def emergency_flush(_admin=Depends(require_admin)):
    """Nuclear option: flush all NTTH nftables rules immediately."""
    if not settings.firewall_enabled:
        return {"flushed": False, "warning": "Firewall control is disabled in this deployment"}
    from app.database.session import AsyncSessionLocal
    from app.firewall.nft_manager import NFTManager
    success = await NFTManager().flush_chain()
    deactivated_rules = 0
    if success:
        async with AsyncSessionLocal() as db:
            deactivated_rules = await crud.deactivate_all_firewall_rules(db)
            await db.commit()
    return {
        "flushed": success,
        "warning": "All dynamic firewall rules removed",
        "deactivated_rules": deactivated_rules,
    }


@router.get("/iocs")
async def list_iocs(
    limit: int = Query(200, ge=1, le=1000),
    _user=Depends(get_current_user),
):
    """Return extracted IOCs from honeypot sessions."""
    try:
        from app.honeypot.ioc_extractor import get_all_iocs
        return {"items": get_all_iocs(limit)}
    except Exception:
        return {"items": []}


@router.get("/iocs/summary")
async def ioc_summary(_user=Depends(get_current_user)):
    """Return IOC collection summary stats."""
    try:
        from app.honeypot.ioc_extractor import get_ioc_summary
        return get_ioc_summary()
    except Exception:
        return {"total_iocs": 0, "by_type": {}, "unique_source_ips": 0}


@router.get("/protocol-awareness")
async def protocol_awareness(_user=Depends(get_current_user)):
    """Return IPv6, fragment, and VPN traffic visibility counters."""
    ipv6_stats = {"ipv6_packets_seen": 0, "fragment_packets_seen": 0}
    try:
        from app.monitor.packet_sniffer import get_ipv6_stats
        ipv6_stats = get_ipv6_stats()
    except Exception:
        pass
    feedback = {}
    try:
        from app.agents.feedback_agent import get_feedback_metrics
        feedback = get_feedback_metrics()
    except Exception:
        pass
    return {
        **ipv6_stats,
        "feedback_metrics": feedback,
    }
