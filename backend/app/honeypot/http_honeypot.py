"""
Lightweight HTTP honeypot — logs all requests as honeypot events.
Runs as a separate Starlette app on port 8888.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime

from app.config import get_settings
from app.core.logger import get_logger
from app.honeypot.session_logger import log_http_session

log = get_logger("http_honeypot")
settings = get_settings()


async def _honeypot_app(scope, receive, send) -> None:
    """Minimal ASGI app that logs every request and returns a fake 200 response."""
    if scope["type"] != "http":
        return

    # Read body
    body = b""
    more_body = True
    while more_body:
        message = await receive()
        body += message.get("body", b"")
        more_body = message.get("more_body", False)

    # Extract metadata
    headers = {k.decode(): v.decode() for k, v in scope.get("headers", [])}
    src_ip = scope.get("client", ("unknown", 0))[0]
    path = scope.get("path", "/")
    method = scope.get("method", "GET")
    query_string = scope.get("query_string", b"").decode()

    attacker_port = scope.get("client", ("unknown", 0))[1]
    session_data = {
        "attacker_ip": src_ip,
        "attacker_port": attacker_port if isinstance(attacker_port, int) else None,
        "method": method,
        "path": path,
        "query": query_string,
        "headers": headers,
        "body": body.decode(errors="replace")[:2048],
        "started_at": datetime.utcnow().isoformat(),
    }

    log.warning("http_honeypot.hit", ip=src_ip, method=method, path=path)
    await log_http_session(session_data)

    # Send convincing fake response
    fake_body = b'{"status":"ok"}'
    await send({
        "type": "http.response.start",
        "status": 200,
        "headers": [
            [b"content-type", b"application/json"],
            [b"server", b"nginx/1.18.0"],
            [b"content-length", str(len(fake_body)).encode()],
        ],
    })
    await send({"type": "http.response.body", "body": fake_body})


async def start_http_honeypot() -> None:
    """Start the HTTP honeypot server using uvicorn programmatically."""
    try:
        import uvicorn  # type: ignore
        config = uvicorn.Config(
            app=_honeypot_app,
            host=settings.http_honeypot_host,
            port=settings.http_honeypot_port,
            log_level="warning",
        )
        server = uvicorn.Server(config)
        await server.serve()
    except Exception as exc:
        log.error("http_honeypot.startup_failed", error=str(exc))
