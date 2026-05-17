"""Short-lived risk clear suppressor.

Prevents stale/backfilled events from immediately restoring risk after an admin
presses Clear Risk & Unblock. New attacks after the grace window still count.
"""
from __future__ import annotations

import time
from datetime import datetime

_CLEARED_AT: dict[str, float] = {}
_SUPPRESS_SECONDS = 20.0


def register_clear(ip: str) -> None:
    if ip:
        _CLEARED_AT[ip] = time.monotonic()


def should_suppress(ip: str, event_timestamp: str | None = None) -> bool:
    if not ip:
        return False
    cleared_at = _CLEARED_AT.get(ip)
    if cleared_at is None:
        return False
    if time.monotonic() - cleared_at <= _SUPPRESS_SECONDS:
        return True
    _CLEARED_AT.pop(ip, None)
    return False

