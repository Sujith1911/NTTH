"""
Cowrie SSH honeypot controller.
Starts/stops the Cowrie Docker container and checks its status.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
import socket
from typing import Optional

from app.config import get_settings
from app.core.logger import get_logger

log = get_logger("cowrie_controller")
settings = get_settings()
_BACKEND_DIR = Path(__file__).resolve().parents[2]
_COMPOSE_FILE = _BACKEND_DIR / "docker-compose.yml"
_COWRIE_LOG_DIR = _BACKEND_DIR / "cowrie" / "logs"


def _docker_client():
    import docker  # type: ignore

    if Path("/var/run/docker.sock").exists():
        return docker.DockerClient(base_url="unix:///var/run/docker.sock")
    return docker.from_env()


def _probe_tcp(port: int) -> bool:
    for host in ("127.0.0.1", settings.cowrie_container_name):
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except OSError:
            continue
    return False


def _probe_cowrie() -> bool:
    return _probe_tcp(settings.cowrie_redirect_port) or _probe_tcp(2223)


def _docker_error_detail(exc: Exception) -> str:
    message = str(exc)
    if "http+docker" in message:
        return "Docker SDK transport is unavailable in this runtime; using direct service probe instead."
    return message


async def _wait_for_cowrie(timeout_seconds: int = 15) -> bool:
    for _ in range(timeout_seconds):
        if _probe_cowrie():
            return True
        await asyncio.sleep(1)
    return _probe_cowrie()


async def _run_command(*args: str) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    return (
        proc.returncode,
        stdout.decode(errors="replace").strip(),
        stderr.decode(errors="replace").strip(),
    )


async def _run_compose(*args: str) -> tuple[bool, str]:
    if not _COMPOSE_FILE.exists():
        return False, f"Compose file not found: {_COMPOSE_FILE}"

    commands = [
        ("docker", "compose", "-f", str(_COMPOSE_FILE), *args),
        ("docker-compose", "-f", str(_COMPOSE_FILE), *args),
    ]
    errors: list[str] = []
    for command in commands:
        try:
            returncode, stdout, stderr = await _run_command(*command)
        except FileNotFoundError as exc:
            errors.append(str(exc))
            continue

        if returncode == 0:
            return True, stdout or stderr
        errors.append(stderr or stdout or f"{command[0]} exited with {returncode}")
    return False, " | ".join(errors)


async def _start_cowrie_with_compose() -> bool:
    try:
        _COWRIE_LOG_DIR.mkdir(parents=True, exist_ok=True)
        _COWRIE_LOG_DIR.chmod(0o777)
    except OSError as exc:
        log.warning("cowrie_controller.log_dir_prepare_failed", error=str(exc))

    ok, detail = await _run_compose("up", "-d", "cowrie")
    if not ok:
        log.error("cowrie_controller.compose_start_failed", error=detail)
        return False

    log.info("cowrie_controller.compose_started", detail=detail)
    return await _wait_for_cowrie()


async def ensure_cowrie_running() -> bool:
    """Start Cowrie container if not running. Returns True if running."""
    if _probe_cowrie():
        return True

    try:
        import docker  # type: ignore
        client = _docker_client()
        try:
            container = client.containers.get(settings.cowrie_container_name)
            if container.status != "running":
                container.start()
                log.info("cowrie_controller.started", container=settings.cowrie_container_name)
            if await _wait_for_cowrie():
                return True
            log.warning("cowrie_controller.sdk_started_but_probe_failed")
            return await _start_cowrie_with_compose()
        except docker.errors.NotFound:
            log.warning("cowrie_controller.container_not_found", name=settings.cowrie_container_name)
            return await _start_cowrie_with_compose()
    except Exception as exc:
        detail = _docker_error_detail(exc)
        if _probe_cowrie():
            log.warning("cowrie_controller.probe_fallback", error=detail)
            return True
        log.error("cowrie_controller.error", error=detail)
        return await _start_cowrie_with_compose()


async def stop_cowrie() -> bool:
    """Stop the Cowrie container."""
    try:
        import docker  # type: ignore
        client = _docker_client()
        container = client.containers.get(settings.cowrie_container_name)
        container.stop(timeout=10)
        log.info("cowrie_controller.stopped")
        return True
    except Exception as exc:
        detail = _docker_error_detail(exc)
        log.warning("cowrie_controller.stop_sdk_failed", error=detail)
        ok, compose_detail = await _run_compose("stop", "cowrie")
        if ok:
            log.info("cowrie_controller.compose_stopped", detail=compose_detail)
            return True
        log.error("cowrie_controller.stop_error", error=compose_detail or detail)
        return False


async def get_cowrie_status() -> dict:
    """Return container status info."""
    if _probe_cowrie():
        return {
            "status": "running",
            "name": settings.cowrie_container_name,
            "image": "unknown",
            "transport": "tcp_probe",
        }

    try:
        import docker  # type: ignore
        client = _docker_client()
        container = client.containers.get(settings.cowrie_container_name)
        return {
            "status": container.status,
            "name": container.name,
            "image": container.image.tags[0] if container.image.tags else "unknown",
        }
    except Exception as exc:
        if _probe_cowrie():
            return {
                "status": "running",
                "name": settings.cowrie_container_name,
                "image": "unknown",
                "transport": "tcp_probe",
            }
        return {"status": "unavailable", "error": _docker_error_detail(exc)}
