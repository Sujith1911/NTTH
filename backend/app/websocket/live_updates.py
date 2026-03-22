"""
WebSocket live update broadcaster.
Clients connect to /ws/live?token=<JWT>.
All connected clients receive real-time threat/firewall/honeypot events.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from app.core import event_bus
from app.core.logger import get_logger
from app.core.security import verify_token

log = get_logger("live_updates")
router = APIRouter()

# Active WebSocket connections
_connections: set[WebSocket] = set()
_lock = asyncio.Lock()


def connection_count() -> int:
    return len(_connections)


async def broadcast(payload: dict) -> None:
    """Send a message to all active WebSocket clients."""
    if not _connections:
        return
    message = json.dumps(payload)
    async with _lock:
        dead: set[WebSocket] = set()
        for ws in _connections:
            try:
                await ws.send_text(message)
            except Exception:
                dead.add(ws)
        _connections.difference_update(dead)


async def _forward_topology_update(payload: dict[str, Any]) -> None:
    """Bridge event-bus topology events to WebSocket clients."""
    await broadcast(payload)


@router.websocket("/live")
async def websocket_live(
    websocket: WebSocket,
    token: str = Query(...),
):
    """Authenticate via JWT token query param, then stream live events."""
    payload = verify_token(token)
    if not payload:
        await websocket.close(code=4001, reason="Unauthorized")
        return

    await websocket.accept()
    async with _lock:
        _connections.add(websocket)

    log.info("ws.client_connected", user=payload.get("sub"), total=len(_connections))

    try:
        # Keep the connection alive; ping every 30s
        while True:
            await asyncio.sleep(30)
            await websocket.send_text(json.dumps({"type": "ping"}))
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        async with _lock:
            _connections.discard(websocket)
        log.info("ws.client_disconnected", user=payload.get("sub"), remaining=len(_connections))


event_bus.subscribe("topology_updated", _forward_topology_update)
