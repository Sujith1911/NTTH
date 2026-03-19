"""
Cowrie SSH honeypot controller.
Starts/stops the Cowrie Docker container and checks its status.
"""
from __future__ import annotations

from app.config import get_settings
from app.core.logger import get_logger

log = get_logger("cowrie_controller")
settings = get_settings()


async def ensure_cowrie_running() -> bool:
    """Start Cowrie container if not running. Returns True if running."""
    try:
        import docker  # type: ignore
        client = docker.from_env()
        try:
            container = client.containers.get(settings.cowrie_container_name)
            if container.status != "running":
                container.start()
                log.info("cowrie_controller.started", container=settings.cowrie_container_name)
            return True
        except docker.errors.NotFound:
            log.warning("cowrie_controller.container_not_found", name=settings.cowrie_container_name)
            return False
    except Exception as exc:
        log.error("cowrie_controller.error", error=str(exc))
        return False


async def stop_cowrie() -> bool:
    """Stop the Cowrie container."""
    try:
        import docker  # type: ignore
        client = docker.from_env()
        container = client.containers.get(settings.cowrie_container_name)
        container.stop(timeout=10)
        log.info("cowrie_controller.stopped")
        return True
    except Exception as exc:
        log.error("cowrie_controller.stop_error", error=str(exc))
        return False


async def get_cowrie_status() -> dict:
    """Return container status info."""
    try:
        import docker  # type: ignore
        client = docker.from_env()
        container = client.containers.get(settings.cowrie_container_name)
        return {
            "status": container.status,
            "name": container.name,
            "image": container.image.tags[0] if container.image.tags else "unknown",
        }
    except Exception as exc:
        return {"status": "unavailable", "error": str(exc)}
