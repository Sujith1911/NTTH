"""
FastAPI application entry point.
Registers all routers, handles lifespan (startup/shutdown),
seeds admin user on first run, mounts WebSocket endpoint.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os
from pathlib import Path

from app.config import get_settings
from app.core.event_bus import start_event_bus, stop_event_bus
from app.core.logger import get_logger, setup_logging
from app.core.scheduler import start_scheduler, stop_scheduler
from app.core.security import hash_password
from app.database import crud
from app.database.crud import create_user, get_user_by_username
from app.database.session import AsyncSessionLocal, init_db
from app.monitor.network_scanner import get_effective_scan_subnet

# Import all agents so they can subscribe on startup
import app.agents.threat_agent      # noqa: F401
import app.agents.decision_agent    # noqa: F401
import app.agents.enforcement_agent # noqa: F401
import app.agents.reporting_agent   # noqa: F401

# Routers
from app.api import (
    routes_auth,
    routes_devices,
    routes_firewall,
    routes_honeypot,
    routes_system,
    routes_threats,
    routes_topology,
)
from app.websocket.live_updates import router as ws_router

setup_logging()
log = get_logger("main")
settings = get_settings()


# ── Lifespan (startup / shutdown) ─────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("ntth.startup", version=settings.app_version, env=settings.environment)

    # 1. Init DB (create tables in dev mode)
    if settings.environment == "development":
        await init_db()

    # 2. Seed admin user
    async with AsyncSessionLocal() as db:
        existing = await get_user_by_username(db, settings.admin_username)
        if not existing:
            await create_user(db, settings.admin_username, hash_password(settings.admin_password), role="admin")
            await db.commit()
            log.info("ntth.admin_seeded", username=settings.admin_username)

    # 2b. Remove stale non-local device rows left behind by older simulated/public attacker events.
    effective_scan_subnet = get_effective_scan_subnet()
    if effective_scan_subnet:
        async with AsyncSessionLocal() as db:
            removed = await crud.purge_devices_outside_subnet(db, effective_scan_subnet)
            await db.commit()
            if removed:
                log.info("ntth.device_cleanup", removed=removed, subnet=effective_scan_subnet)

    # 3. Start event bus
    await start_event_bus()

    # 4. Start scheduler
    await start_scheduler()

    # 5. Start packet sniffer (Linux only — skips gracefully on Windows)
    sniffer_task = None
    try:
        from app.monitor.packet_sniffer import start_sniffer
        sniffer_task = asyncio.create_task(start_sniffer(), name="packet_sniffer")
        log.info("ntth.sniffer_starting", interface=settings.network_interface)
    except Exception as exc:
        log.warning("ntth.sniffer_skipped", reason=str(exc))

    # 6. Start HTTP honeypot
    honeypot_task = None
    try:
        from app.honeypot.http_honeypot import start_http_honeypot
        honeypot_task = asyncio.create_task(start_http_honeypot(), name="http_honeypot")
        log.info("ntth.http_honeypot_started", port=settings.http_honeypot_port)
    except Exception as exc:
        log.warning("ntth.http_honeypot_skipped", reason=str(exc))

    # 7. Start Cowrie JSON log watcher
    cowrie_watcher_task = None
    try:
        from app.honeypot.cowrie_watcher import watch_cowrie_log
        cowrie_watcher_task = asyncio.create_task(watch_cowrie_log(), name="cowrie_watcher")
        log.info("ntth.cowrie_watcher_started")
    except Exception as exc:
        log.warning("ntth.cowrie_watcher_skipped", reason=str(exc))

    # 8. Periodic network scan (start after 5s, repeat every 5 min)
    async def _periodic_scan():
        await asyncio.sleep(5)                        # let everything settle first
        while True:
            try:
                from app.monitor.network_scanner import scan_network
                from app.websocket.live_updates import broadcast
                import datetime as _dt
                devices = await scan_network()
                now_iso = _dt.datetime.utcnow().isoformat() + "Z"
                await broadcast({
                    "type": "topology_updated",
                    "devices_found": len(devices),
                    "timestamp": now_iso,
                    "scan_ts": now_iso,
                })
                log.info("ntth.auto_scan_done", devices=len(devices))
            except Exception as exc:
                log.warning("ntth.auto_scan_failed", reason=str(exc))
            await asyncio.sleep(settings.device_scan_interval_seconds)

    scan_task = asyncio.create_task(_periodic_scan(), name="periodic_scan")

    yield  # ← Application is running

    scan_task.cancel()

    # Shutdown
    log.info("ntth.shutdown")
    if sniffer_task:
        sniffer_task.cancel()
    if honeypot_task:
        honeypot_task.cancel()
    if cowrie_watcher_task:
        cowrie_watcher_task.cancel()
    await stop_scheduler()
    await stop_event_bus()


# ── App factory ───────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="Adaptive AI-Driven Honeypot Firewall — REST API",
        docs_url="/docs" if settings.debug else None,
        redoc_url="/redoc" if settings.debug else None,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Routers
    prefix = "/api/v1"
    app.include_router(routes_auth.router,     prefix=f"{prefix}/auth",     tags=["Auth"])
    app.include_router(routes_devices.router,  prefix=f"{prefix}/devices",  tags=["Devices"])
    app.include_router(routes_threats.router,  prefix=f"{prefix}/threats",  tags=["Threats"])
    app.include_router(routes_firewall.router, prefix=f"{prefix}/firewall", tags=["Firewall"])
    app.include_router(routes_honeypot.router, prefix=f"{prefix}/honeypot", tags=["Honeypot"])
    app.include_router(routes_system.router,   prefix=f"{prefix}/system",   tags=["System"])
    app.include_router(routes_topology.router, prefix=f"{prefix}/network",  tags=["Network"])
    app.include_router(ws_router,              prefix="/ws",                tags=["WebSocket"])

    # ── Serve Flutter Web App (SPA) ────────────────────────────────────────────
    current_file = Path(__file__).resolve()
    flutter_candidates = [
        current_file.parent.parent.parent / "flutter_app" / "build" / "web",
        current_file.parent.parent / "flutter_app" / "build" / "web",
        Path("/app/flutter_app/build/web"),
        Path("/flutter_app/build/web"),
    ]
    flutter_build = next((path for path in flutter_candidates if path.is_dir()), flutter_candidates[0])
    log.info("ntth.flutter_path_check", path=str(flutter_build), exists=flutter_build.is_dir())
    try:
        if flutter_build.is_dir():
            app.mount("/app", StaticFiles(directory=str(flutter_build), html=True), name="flutter")
            app.mount("/", StaticFiles(directory=str(flutter_build), html=True), name="flutter_root")

            log.info("ntth.flutter_mounted", path=str(flutter_build))
        else:
            log.warning("ntth.flutter_not_found", expected=str(flutter_build))
    except Exception as exc:
        log.error("ntth.flutter_mount_failed", error=str(exc))

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=settings.debug)
