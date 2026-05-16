"""
Structured JSON logger using structlog + Python's standard logging.
Writes to both console and rotating log file.
"""
from __future__ import annotations

import logging
import logging.handlers
import os
from typing import Any

import structlog

from app.config import get_settings

settings = get_settings()


def _setup_stdlib_logging() -> None:
    root = logging.getLogger()
    root.setLevel(getattr(logging, settings.log_level.upper(), logging.INFO))
    if root.handlers:
        return

    # Console handler
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(message)s"))
    root.addHandler(ch)

    # Rotating file handler
    try:
        os.makedirs(settings.log_dir, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(
            filename=os.path.join(settings.log_dir, "ntth.log"),
            maxBytes=settings.log_max_bytes,
            backupCount=settings.log_backup_count,
            encoding="utf-8",
        )
        fh.setFormatter(logging.Formatter("%(message)s"))
        root.addHandler(fh)
    except PermissionError:
        root.warning(
            "log_file_unavailable path=%s reason=permission_denied",
            os.path.join(settings.log_dir, "ntth.log"),
        )


def _configure_structlog() -> None:
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def setup_logging() -> None:
    """Call once at application startup."""
    _setup_stdlib_logging()
    _configure_structlog()


def get_logger(name: str = "ntth") -> Any:
    """Return a bound structlog logger for the given component name."""
    return structlog.get_logger(name)
