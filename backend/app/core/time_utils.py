"""Time helpers for UTC storage and machine-local display."""
from __future__ import annotations

from datetime import datetime, time, timezone


def utc_now_naive() -> datetime:
    """UTC timestamp for database columns stored without tzinfo."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def utc_naive_to_local_iso(value: datetime | None) -> str | None:
    """Convert a naive UTC DB timestamp to the system-local ISO timestamp."""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone().isoformat()


def local_now_iso() -> str:
    """Current system-local time as ISO with timezone offset."""
    return datetime.now().astimezone().isoformat()


def local_input_to_utc_naive(value: str | None, *, end_of_day: bool = False) -> datetime | None:
    """Parse a local date/datetime filter and convert it to naive UTC for DB queries."""
    if not value:
        return None
    raw = value.strip()
    if not raw:
        return None
    try:
        if len(raw) == 10:
            parsed_date = datetime.strptime(raw, "%Y-%m-%d").date()
            parsed = datetime.combine(parsed_date, time.max if end_of_day else time.min)
        else:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.astimezone()
        return parsed.astimezone(timezone.utc).replace(tzinfo=None)
    except ValueError:
        return None
