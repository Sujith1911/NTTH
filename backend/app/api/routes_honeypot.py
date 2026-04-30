"""
Honeypot routes: Cowrie SSH + Multi-Protocol honeypot management.

Endpoints:
  GET  /honeypot/sessions         — Cowrie sessions (DB-persisted)
  GET  /honeypot/sessions/{id}    — Single Cowrie session
  GET  /honeypot/status           — Cowrie + multi-honeypot status
  POST /honeypot/start            — Start Cowrie (admin)
  POST /honeypot/stop             — Stop Cowrie (admin)
  GET  /honeypot/active           — All active multi-honeypot ports
  GET  /honeypot/multi/sessions   — In-memory multi-honeypot sessions
  POST /honeypot/deploy/{port}    — Deploy honeypot on a specific port (admin)
  POST /honeypot/undeploy/{port}  — Undeploy a specific port (admin)
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.database import crud
from app.database.schemas import HoneypotSessionRead, PaginatedResponse
from app.dependencies import get_current_user, get_db, require_admin

router = APIRouter()


# ── Cowrie SSH sessions (DB-persisted) ────────────────────────────────────────

@router.get("/sessions", response_model=PaginatedResponse)
async def list_sessions(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db=Depends(get_db),
    _user=Depends(get_current_user),
):
    """List paginated Cowrie SSH honeypot sessions from the database."""
    total, sessions = await crud.list_honeypot_sessions(db, page, page_size)
    return PaginatedResponse(
        total=total, page=page, page_size=page_size,
        items=[HoneypotSessionRead.model_validate(s) for s in sessions],
    )


@router.get("/sessions/{session_id}", response_model=HoneypotSessionRead)
async def get_session(
    session_id: str,
    db=Depends(get_db),
    _user=Depends(get_current_user),
):
    session = await crud.get_honeypot_session(db, session_id)
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    return HoneypotSessionRead.model_validate(session)


# ── Cowrie control (admin) ────────────────────────────────────────────────────

@router.post("/start", status_code=status.HTTP_200_OK)
async def start_cowrie(_admin=Depends(require_admin)):
    """Start the Cowrie SSH honeypot container."""
    from app.honeypot.cowrie_controller import ensure_cowrie_running
    running = await ensure_cowrie_running()
    return {"cowrie_running": running}


@router.post("/stop", status_code=status.HTTP_200_OK)
async def stop_cowrie(_admin=Depends(require_admin)):
    """Stop the Cowrie SSH honeypot container."""
    from app.honeypot.cowrie_controller import stop_cowrie as _stop
    stopped = await _stop()
    return {"stopped": stopped}


# ── Unified status ────────────────────────────────────────────────────────────

@router.get("/status")
async def honeypot_status(_user=Depends(get_current_user)):
    """
    Unified honeypot status:
    - Cowrie SSH container status
    - All active multi-protocol honeypot ports
    - Session counts per protocol
    """
    from app.honeypot.cowrie_controller import get_cowrie_status
    from app.honeypot.multi_honeypot import (
        get_active_honeypots,
        get_session_count,
        get_recent_sessions,
    )

    cowrie = await get_cowrie_status()
    active_pots = get_active_honeypots()
    recent = get_recent_sessions(limit=200)

    # Aggregate counts per protocol
    protocol_counts: dict[str, int] = {}
    for s in recent:
        proto = s.get("protocol", "unknown")
        protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

    return {
        **cowrie,
        "multi_honeypots": {
            "active_ports": active_pots,
            "total_active": len(active_pots),
            "total_sessions": get_session_count(),
            "sessions_by_protocol": protocol_counts,
        },
    }


# ── Multi-Protocol Honeypot ───────────────────────────────────────────────────

@router.get("/active")
async def list_active_honeypots(_user=Depends(get_current_user)):
    """List all currently active multi-protocol honeypot ports."""
    from app.honeypot.multi_honeypot import get_active_honeypots
    pots = get_active_honeypots()
    return {
        "count": len(pots),
        "honeypots": pots,
    }


@router.get("/multi/sessions")
async def list_multi_sessions(
    limit: int = Query(100, ge=1, le=500),
    protocol: str | None = Query(default=None),
    _user=Depends(get_current_user),
):
    """
    List recent multi-protocol honeypot interaction sessions (in-memory).
    Optionally filter by protocol (e.g. http, ftp, mysql, rdp).
    """
    from app.honeypot.multi_honeypot import get_recent_sessions
    sessions = get_recent_sessions(limit=limit)
    if protocol:
        sessions = [s for s in sessions if s.get("protocol") == protocol]
    return {
        "total": len(sessions),
        "sessions": sessions,
    }


@router.post("/deploy/{port}", status_code=status.HTTP_200_OK)
async def deploy_honeypot_port(
    port: int,
    _admin=Depends(require_admin),
):
    """
    Admin: manually deploy a honeypot listener on a specific port.
    The system also does this automatically when attacks are detected.
    """
    if port < 1 or port > 65535:
        raise HTTPException(status_code=400, detail="Port must be 1-65535")
    if port in (8000, 8001):
        raise HTTPException(status_code=400, detail="Cannot deploy on system ports")

    from app.honeypot.multi_honeypot import deploy_honeypot, get_protocol_name
    success = await deploy_honeypot(port)
    if not success:
        raise HTTPException(
            status_code=409,
            detail=f"Port {port} is already in use or honeypot failed to deploy",
        )
    return {
        "deployed": True,
        "port": port,
        "protocol": get_protocol_name(port),
    }


@router.post("/undeploy/{port}", status_code=status.HTTP_200_OK)
async def undeploy_honeypot_port(
    port: int,
    _admin=Depends(require_admin),
):
    """Admin: shut down a honeypot listener on a specific port."""
    from app.honeypot.multi_honeypot import undeploy_honeypot
    stopped = await undeploy_honeypot(port)
    return {"stopped": stopped, "port": port}
