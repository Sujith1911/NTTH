"""
Multi-Protocol Honeypot — lightweight protocol emulators that auto-deploy
when any port is attacked, not just SSH.

Supported protocols:
  - HTTP/HTTPS (80, 443, 8080, 8443) → Fake login pages, capture credentials
  - FTP (21) → Fake FTP server, log commands
  - Telnet (23) → Fake terminal, log commands
  - MySQL (3306) → Fake MySQL handshake, capture credentials
  - SMB (445) → Connection logger
  - RDP (3389) → Connection logger
  - Generic (any port) → TCP banner grab, log connection attempts

Each honeypot runs as a lightweight asyncio TCP server.
Interactions are logged and published to the event bus.
"""
from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Optional

from app.core.event_bus import publish
from app.core.logger import get_logger

log = get_logger("multi_honeypot")

# Active honeypot servers: port → server instance
_active_honeypots: dict[int, asyncio.Server] = {}

# Session log (in-memory, also published to event bus)
_sessions: list[dict] = []
_MAX_SESSIONS = 500

# Protocol banners — fake responses that lure attackers into interacting
_PROTOCOL_BANNERS = {
    21: b"220 ProFTPD 1.3.5 Server (NTTH FTP) [::ffff:10.0.0.1]\r\n",
    23: b"\xff\xfb\x01\xff\xfb\x03\r\nUbuntu 22.04 LTS\r\nlogin: ",
    80: (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: Apache/2.4.52 (Ubuntu)\r\n"
        b"Content-Type: text/html\r\n\r\n"
        b"<html><head><title>Admin Panel</title></head>"
        b"<body><h2>Login</h2>"
        b"<form method='POST'>"
        b"Username: <input name='user'><br>"
        b"Password: <input name='pass' type='password'><br>"
        b"<button>Login</button>"
        b"</form></body></html>"
    ),
    443: (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: nginx/1.18.0\r\n"
        b"Content-Type: text/html\r\n\r\n"
        b"<html><body><h2>Secure Portal - Login Required</h2></body></html>"
    ),
    3306: (
        b"\x4a\x00\x00\x00\x0a"  # MySQL greeting packet (simplified)
        b"5.7.38-0ubuntu0.22.04.1\x00"
        b"\x08\x00\x00\x00"
        b"abcdefgh\x00"
    ),
    3389: b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x01\x08\x00\x02\x00\x00\x00",
    445: b"\x00",  # SMB — just accept connection and log
    5900: b"RFB 003.008\n",  # VNC
}


def _get_protocol_name(port: int) -> str:
    """Map port number to protocol name."""
    names = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        53: "dns", 80: "http", 110: "pop3", 143: "imap",
        443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
        1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgres",
        5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
        8888: "http-honeypot", 27017: "mongodb",
    }
    return names.get(port, f"tcp-{port}")


async def _handle_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    port: int,
) -> None:
    """Handle a single honeypot connection — send banner, capture input."""
    peer = writer.get_extra_info("peername")
    attacker_ip = peer[0] if peer else "unknown"
    attacker_port = peer[1] if peer else 0
    protocol = _get_protocol_name(port)
    now = datetime.utcnow()

    session = {
        "attacker_ip": attacker_ip,
        "attacker_port": attacker_port,
        "honeypot_port": port,
        "protocol": protocol,
        "connected_at": now.isoformat(),
        "data_received": "",
        "duration_seconds": 0,
    }

    log.info(
        "multi_honeypot.connection",
        attacker_ip=attacker_ip,
        port=port,
        protocol=protocol,
    )

    try:
        # Send protocol banner
        banner = _PROTOCOL_BANNERS.get(port, f"Welcome to {protocol} service\r\n".encode())
        writer.write(banner)
        await writer.drain()

        # Capture attacker input (up to 4KB, timeout 30s)
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=30.0)
            if data:
                # Safely decode, replacing non-printable chars
                text = data.decode("utf-8", errors="replace")
                session["data_received"] = text[:2000]  # Cap at 2000 chars

                # For HTTP — try to extract credentials from POST data
                if port in (80, 443, 8080, 8443) and "user=" in text:
                    session["credentials_captured"] = True

                # For FTP/Telnet — log the command
                if port in (21, 23):
                    session["commands"] = text.strip().split("\n")[:20]

                log.info(
                    "multi_honeypot.data_captured",
                    attacker_ip=attacker_ip,
                    port=port,
                    bytes=len(data),
                )
        except asyncio.TimeoutError:
            pass

        # For interactive protocols, send a second response
        if port == 21 and session["data_received"]:
            writer.write(b"331 Password required\r\n")
            await writer.drain()
            try:
                pwd_data = await asyncio.wait_for(reader.read(1024), timeout=10.0)
                if pwd_data:
                    session["data_received"] += "\n" + pwd_data.decode("utf-8", errors="replace")
                    writer.write(b"530 Login incorrect\r\n")
                    await writer.drain()
            except asyncio.TimeoutError:
                pass

        elif port == 23 and session["data_received"]:
            writer.write(b"Password: ")
            await writer.drain()
            try:
                pwd_data = await asyncio.wait_for(reader.read(1024), timeout=10.0)
                if pwd_data:
                    session["data_received"] += "\nPASS:" + pwd_data.decode("utf-8", errors="replace")
                    writer.write(b"\r\nLogin incorrect\r\n")
                    await writer.drain()
            except asyncio.TimeoutError:
                pass

    except (ConnectionResetError, BrokenPipeError):
        pass
    except Exception as exc:
        log.debug("multi_honeypot.error", error=str(exc))
    finally:
        end_time = datetime.utcnow()
        session["duration_seconds"] = round((end_time - now).total_seconds(), 2)

        # Store session
        _sessions.append(session)
        if len(_sessions) > _MAX_SESSIONS:
            _sessions.pop(0)

        # Publish to event bus for reporting
        await publish("honeypot_interaction", {
            **session,
            "event_type": "multi_honeypot_session",
        })

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def deploy_honeypot(port: int) -> bool:
    """
    Deploy a honeypot on the specified port.

    Called automatically when the decision agent detects an attack
    on a port that doesn't have a dedicated honeypot yet.

    Returns True if successfully deployed, False if already running
    or port is unavailable.
    """
    if port in _active_honeypots:
        return True  # Already running

    try:
        server = await asyncio.start_server(
            lambda r, w: _handle_connection(r, w, port),
            host="0.0.0.0",
            port=port,
            reuse_address=True,
        )
        _active_honeypots[port] = server
        log.info(
            "multi_honeypot.deployed",
            port=port,
            protocol=_get_protocol_name(port),
        )
        return True
    except OSError as exc:
        if "Address already in use" in str(exc):
            log.debug("multi_honeypot.port_in_use", port=port)
        else:
            log.warning("multi_honeypot.deploy_failed", port=port, error=str(exc))
        return False
    except Exception as exc:
        log.warning("multi_honeypot.deploy_failed", port=port, error=str(exc))
        return False


async def undeploy_honeypot(port: int) -> bool:
    """Stop a running honeypot on the specified port."""
    server = _active_honeypots.pop(port, None)
    if server:
        server.close()
        await server.wait_closed()
        log.info("multi_honeypot.undeployed", port=port)
        return True
    return False


async def shutdown_all() -> None:
    """Shutdown all active honeypot servers."""
    for port in list(_active_honeypots.keys()):
        await undeploy_honeypot(port)
    log.info("multi_honeypot.all_shutdown")


# ── Public query API ──────────────────────────────────────────────

def get_active_honeypots() -> list[dict]:
    """Return list of currently active honeypot ports."""
    return [
        {"port": port, "protocol": _get_protocol_name(port)}
        for port in sorted(_active_honeypots.keys())
    ]


def get_sessions(limit: int = 50) -> list[dict]:
    """Return recent honeypot interaction sessions."""
    return _sessions[-limit:]


def get_session_count() -> int:
    return len(_sessions)


def is_honeypot_active(port: int) -> bool:
    return port in _active_honeypots


def get_recent_sessions(limit: int = 100) -> list[dict]:
    """Return recent honeypot sessions (alias for API routes)."""
    return _sessions[-limit:]
