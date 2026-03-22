"""
Async event bus — lightweight pub/sub using asyncio.Queue.
Topics: threat_detected | rule_applied | honeypot_hit | device_seen
"""
from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any, Callable, Coroutine

from app.config import get_settings
from app.core.logger import get_logger

log = get_logger("event_bus")
settings = get_settings()

# Internal registry: topic → list of async handler coroutines
_subscribers: dict[str, list[Callable[..., Coroutine]]] = defaultdict(list)
_queue: asyncio.Queue = asyncio.Queue(maxsize=settings.event_bus_queue_size)


def subscribe(topic: str, handler: Callable[..., Coroutine]) -> None:
    """Register an async handler for a topic."""
    _subscribers[topic].append(handler)
    log.debug("event_bus.subscribe", topic=topic, handler=handler.__name__)


async def publish(topic: str, payload: Any) -> None:
    """Put an event onto the queue (non-blocking if space available)."""
    try:
        _queue.put_nowait({"topic": topic, "payload": payload})
    except asyncio.QueueFull:
        log.warning("event_bus.queue_full", topic=topic)


async def _dispatch_loop() -> None:
    """Background task: drain the queue and fan-out to subscribers."""
    while True:
        event = await _queue.get()
        topic: str = event["topic"]
        payload: Any = event["payload"]
        handlers = _subscribers.get(topic, [])
        for handler in handlers:
            try:
                await handler(payload)
            except Exception as exc:
                log.error("event_bus.handler_error", topic=topic, handler=handler.__name__, error=str(exc))
        _queue.task_done()


# ── Lifecycle ─────────────────────────────────────────────────────────────────

_dispatch_task: asyncio.Task | None = None


def get_metrics() -> dict[str, int]:
    """Return lightweight runtime metrics for health and diagnostics."""
    return {
        "queue_size": _queue.qsize(),
        "subscriber_topics": len(_subscribers),
        "subscriber_handlers": sum(len(handlers) for handlers in _subscribers.values()),
    }


async def start_event_bus() -> None:
    global _dispatch_task
    _dispatch_task = asyncio.create_task(_dispatch_loop(), name="event_bus_dispatcher")
    log.info("event_bus.started")


async def stop_event_bus() -> None:
    if _dispatch_task:
        _dispatch_task.cancel()
        try:
            await _dispatch_task
        except asyncio.CancelledError:
            pass
    log.info("event_bus.stopped")
