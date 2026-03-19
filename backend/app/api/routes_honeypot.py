"""
Honeypot routes: list/view sessions, start/stop Cowrie (admin).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.database import crud
from app.database.schemas import HoneypotSessionRead, PaginatedResponse
from app.dependencies import get_current_user, get_db, require_admin

router = APIRouter()


@router.get("/sessions", response_model=PaginatedResponse)
async def list_sessions(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db=Depends(get_db),
    _user=Depends(get_current_user),
):
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


@router.post("/start", status_code=status.HTTP_200_OK)
async def start_cowrie(_admin=Depends(require_admin)):
    from app.honeypot.cowrie_controller import ensure_cowrie_running
    running = await ensure_cowrie_running()
    return {"cowrie_running": running}


@router.post("/stop", status_code=status.HTTP_200_OK)
async def stop_cowrie(_admin=Depends(require_admin)):
    from app.honeypot.cowrie_controller import stop_cowrie as _stop
    stopped = await _stop()
    return {"stopped": stopped}


@router.get("/status", status_code=status.HTTP_200_OK)
async def cowrie_status(_user=Depends(get_current_user)):
    from app.honeypot.cowrie_controller import get_cowrie_status
    return await get_cowrie_status()
