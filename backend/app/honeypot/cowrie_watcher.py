"""
Cowrie JSON log watcher.
Tails cowrie.json in real-time; parses events and logs sessions to DB.
Run as a background asyncio task alongside the main app.
"""
from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime
from typing import TextIO

from app.config import get_settings
from app.core.logger import get_logger
from app.honeypot.session_logger import log_cowrie_session

log = get_logger("cowrie_watcher")
settings = get_settings()


def _normalize_timestamp(raw: str | None) -> datetime:
    if not raw:
        return datetime.utcnow()
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return datetime.utcnow()
    if parsed.tzinfo is not None:
        return parsed.astimezone().replace(tzinfo=None)
    return parsed


def _normalize_duration(value) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


async def watch_cowrie_log() -> None:
    """Tail the Cowrie JSON log file and process new events."""
    log_path = settings.cowrie_log_path

    # Wait for log file to appear
    waited = 0
    while not os.path.exists(log_path):
        if waited == 0:
            log.info("cowrie_watcher.waiting", path=log_path)
        await asyncio.sleep(5)
        waited += 5
        if waited > 300:
            log.warning("cowrie_watcher.timeout", path=log_path)
            return

    file_handle: TextIO | None = None
    current_inode: tuple[int, int] | None = None

    while True:
        try:
            stat = os.stat(log_path)
            inode = (stat.st_dev, stat.st_ino)
            if file_handle is None or current_inode != inode:
                if file_handle is not None:
                    file_handle.close()
                    log.info("cowrie_watcher.reopened", path=log_path)
                file_handle = open(log_path, "r", encoding="utf-8")
                current_inode = inode
                file_handle.seek(0, os.SEEK_END)
                log.info("cowrie_watcher.started", path=log_path)

            line = file_handle.readline()
            if not line:
                try:
                    latest_size = os.path.getsize(log_path)
                except OSError:
                    latest_size = None
                if latest_size is not None and file_handle.tell() > latest_size:
                    file_handle.close()
                    file_handle = None
                    current_inode = None
                    log.info("cowrie_watcher.reset_detected", path=log_path)
                    continue
                await asyncio.sleep(0.5)
                continue

            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)
                event_id = event.get("eventid", "")
                if event_id in (
                    "cowrie.login.failed",
                    "cowrie.login.success",
                    "cowrie.command.input",
                ):
                    await log_cowrie_session(event)
                elif event_id == "cowrie.session.closed":
                    await _close_cowrie_session(event)
            except json.JSONDecodeError:
                log.debug("cowrie_watcher.json_decode_skipped")
            except Exception as exc:
                log.error("cowrie_watcher.error", error=str(exc))
        except FileNotFoundError:
            file_handle = None
            current_inode = None
            await asyncio.sleep(1)
        except Exception as exc:
            log.error("cowrie_watcher.loop_error", error=str(exc))
            await asyncio.sleep(1)


async def _close_cowrie_session(event: dict) -> None:
    """Mark a Cowrie session as closed by updating ended_at in the DB."""
    try:
        from sqlalchemy import select, update
        from app.database.models import HoneypotSession
        from app.database.session import AsyncSessionLocal

        session_id = event.get("session", "")
        if not session_id:
            return

        raw_ts = event.get("timestamp", "")
        ended_at: datetime | None = None
        if raw_ts:
            ended_at = _normalize_timestamp(raw_ts)

        duration = _normalize_duration(event.get("duration"))

        async with AsyncSessionLocal() as db:
            await db.execute(
                update(HoneypotSession)
                .where(HoneypotSession.session_id == session_id)
                .values(
                    ended_at=ended_at or datetime.utcnow(),
                    duration_seconds=duration,
                )
            )
            await db.commit()
        log.info("cowrie_watcher.session_closed", session_id=session_id)
    except Exception as exc:
        log.error("cowrie_watcher.close_error", error=str(exc))
