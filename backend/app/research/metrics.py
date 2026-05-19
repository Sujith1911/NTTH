"""
Lightweight research metrics recorder.

The recorder is intentionally independent from the main SQLite schema so that
paper experiments can be collected without changing operational tables or
affecting packet processing behavior.
"""
from __future__ import annotations

import csv
import json
import os
import resource
import threading
import time
import uuid
from collections import Counter, deque
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any

from app.config import get_settings
from app.core import event_bus

settings = get_settings()
_lock = threading.Lock()
_recent_events: deque[dict[str, Any]] = deque(maxlen=5000)
_stage_counts: Counter[str] = Counter()
_action_counts: Counter[str] = Counter()
_threat_counts: Counter[str] = Counter()
_latency_ms: list[float] = []
_current_experiment: dict[str, Any] | None = None
_packet_observed_total = 0
_PACKET_OBSERVED_SAMPLE_EVERY = 100


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _data_dir() -> Path:
    path = Path("./data")
    path.mkdir(parents=True, exist_ok=True)
    return path


def _jsonl_path() -> Path:
    return _data_dir() / "research_metrics.jsonl"


def _safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (list, tuple)):
        return [_safe(item) for item in value[:20]]
    if isinstance(value, dict):
        return {str(k): _safe(v) for k, v in list(value.items())[:40]}
    return str(value)


def _ensure_trace(payload: dict[str, Any]) -> tuple[str, dict[str, float]]:
    trace_id = payload.get("_research_trace_id")
    if not trace_id:
        trace_id = str(uuid.uuid4())
        payload["_research_trace_id"] = trace_id
    timeline = payload.get("_research_timeline")
    if not isinstance(timeline, dict):
        timeline = {}
        payload["_research_timeline"] = timeline
    return trace_id, timeline


def _append(record: dict[str, Any]) -> None:
    with _lock:
        _recent_events.append(record)
        _stage_counts[record["stage"]] += 1
        action = record.get("action")
        threat_type = record.get("threat_type")
        if action:
            _action_counts[str(action)] += 1
        if threat_type:
            _threat_counts[str(threat_type)] += 1
        latency = record.get("capture_to_enforcement_ms")
        if isinstance(latency, (int, float)):
            _latency_ms.append(float(latency))
            if len(_latency_ms) > 5000:
                del _latency_ms[:1000]

        with _jsonl_path().open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, default=str, sort_keys=True) + "\n")


def mark_packet_observed(payload: dict[str, Any]) -> None:
    global _packet_observed_total
    trace_id, timeline = _ensure_trace(payload)
    now = time.perf_counter()
    timeline.setdefault("packet_observed", now)
    payload["_research_experiment_id"] = current_experiment_id()
    with _lock:
        _packet_observed_total += 1
        _stage_counts["packet_observed"] += 1
        should_sample = (
            _current_experiment is not None
            and _packet_observed_total % _PACKET_OBSERVED_SAMPLE_EVERY == 0
        )
    if should_sample:
        _append(_record("packet_observed_sample", trace_id, payload))


def mark_threat_scored(payload: dict[str, Any]) -> None:
    trace_id, timeline = _ensure_trace(payload)
    timeline["threat_scored"] = time.perf_counter()
    _append(_record("threat_scored", trace_id, payload))


def mark_decision(payload: dict[str, Any]) -> None:
    trace_id, timeline = _ensure_trace(payload)
    timeline["decision_made"] = time.perf_counter()
    _append(_record("decision_made", trace_id, payload))


def mark_report(payload: dict[str, Any]) -> None:
    trace_id, timeline = _ensure_trace(payload)
    timeline["reported"] = time.perf_counter()
    _append(_record("reported", trace_id, payload))


def mark_enforcement_start(payload: dict[str, Any]) -> None:
    trace_id, timeline = _ensure_trace(payload)
    timeline["enforcement_started"] = time.perf_counter()
    _append(_record("enforcement_started", trace_id, payload))


def mark_enforcement_done(payload: dict[str, Any], *, success: bool, error: str | None = None) -> None:
    trace_id, timeline = _ensure_trace(payload)
    timeline["enforcement_done"] = time.perf_counter()
    record = _record("enforcement_done", trace_id, payload)
    record["success"] = success
    record["error"] = error
    start = timeline.get("packet_observed")
    end = timeline.get("enforcement_done")
    if isinstance(start, (int, float)) and isinstance(end, (int, float)):
        record["capture_to_enforcement_ms"] = round((end - start) * 1000, 3)
    _append(record)


def _record(stage: str, trace_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    timeline = payload.get("_research_timeline") or {}
    packet_start = timeline.get("packet_observed")
    now = time.perf_counter()
    elapsed_ms = None
    if isinstance(packet_start, (int, float)):
        elapsed_ms = round((now - packet_start) * 1000, 3)
    return {
        "recorded_at": _utc_iso(),
        "experiment_id": payload.get("_research_experiment_id") or current_experiment_id(),
        "stage": stage,
        "trace_id": trace_id,
        "elapsed_from_capture_ms": elapsed_ms,
        "src_ip": payload.get("src_ip"),
        "dst_ip": payload.get("dst_ip"),
        "src_port": payload.get("src_port"),
        "dst_port": payload.get("dst_port"),
        "protocol": payload.get("protocol"),
        "direction": payload.get("direction"),
        "pkt_len": payload.get("pkt_len"),
        "payload_len": payload.get("payload_len"),
        "threat_type": payload.get("threat_type"),
        "risk_score": payload.get("risk_score"),
        "rule_score": payload.get("rule_score"),
        "ml_score": payload.get("ml_score"),
        "action": payload.get("action"),
        "base_action": payload.get("base_action"),
        "risk_reasons": _safe(payload.get("risk_reasons")),
        "rule_details": _safe(payload.get("rule_details")),
    }


def start_experiment(name: str, scenario: str | None = None, notes: str | None = None) -> dict[str, Any]:
    global _current_experiment
    experiment = {
        "id": str(uuid.uuid4()),
        "name": name.strip() or "unnamed_experiment",
        "scenario": (scenario or "").strip() or None,
        "notes": (notes or "").strip() or None,
        "started_at": _utc_iso(),
        "stopped_at": None,
    }
    _current_experiment = experiment
    _append({
        "recorded_at": _utc_iso(),
        "experiment_id": experiment["id"],
        "stage": "experiment_started",
        "trace_id": None,
        "experiment": experiment,
    })
    return experiment


def stop_experiment() -> dict[str, Any] | None:
    global _current_experiment
    if not _current_experiment:
        return None
    experiment = {**_current_experiment, "stopped_at": _utc_iso()}
    _append({
        "recorded_at": _utc_iso(),
        "experiment_id": experiment["id"],
        "stage": "experiment_stopped",
        "trace_id": None,
        "experiment": experiment,
    })
    _current_experiment = None
    return experiment


def current_experiment_id() -> str | None:
    return _current_experiment["id"] if _current_experiment else None


def current_experiment() -> dict[str, Any] | None:
    return dict(_current_experiment) if _current_experiment else None


def system_snapshot(db_size_bytes: int | None = None) -> dict[str, Any]:
    usage = resource.getrusage(resource.RUSAGE_SELF)
    try:
        load_1, load_5, load_15 = os.getloadavg()
    except OSError:
        load_1 = load_5 = load_15 = None
    bus = event_bus.get_metrics()
    return {
        "recorded_at": _utc_iso(),
        "load_avg_1m": load_1,
        "load_avg_5m": load_5,
        "load_avg_15m": load_15,
        "max_rss_kb": usage.ru_maxrss,
        "user_cpu_seconds": round(usage.ru_utime, 3),
        "system_cpu_seconds": round(usage.ru_stime, 3),
        "event_bus_queue_size": bus.get("queue_size"),
        "event_bus_dropped": bus.get("dropped_events"),
        "event_bus_published": bus.get("published_events"),
        "event_bus_dispatched": bus.get("dispatched_events"),
        "db_size_bytes": db_size_bytes,
    }


def summary() -> dict[str, Any]:
    with _lock:
        latencies = list(_latency_ms)
        recent = list(_recent_events)[-100:]
        stage_counts = dict(_stage_counts)
        action_counts = dict(_action_counts)
        threat_counts = dict(_threat_counts)
    latency_summary = {
        "count": len(latencies),
        "min_ms": round(min(latencies), 3) if latencies else None,
        "avg_ms": round(sum(latencies) / len(latencies), 3) if latencies else None,
        "max_ms": round(max(latencies), 3) if latencies else None,
    }
    return {
        "current_experiment": current_experiment(),
        "stage_counts": stage_counts,
        "action_counts": action_counts,
        "threat_counts": threat_counts,
        "capture_to_enforcement_latency": latency_summary,
        "recent_events": recent,
        "jsonl_path": str(_jsonl_path()),
    }


def export_jsonl(limit: int = 10000) -> str:
    path = _jsonl_path()
    if not path.exists():
        return ""
    lines = path.read_text(encoding="utf-8").splitlines()
    return "\n".join(lines[-limit:]) + ("\n" if lines else "")


def export_csv(limit: int = 10000) -> str:
    path = _jsonl_path()
    rows: list[dict[str, Any]] = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines()[-limit:]:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    fields = [
        "recorded_at", "experiment_id", "stage", "trace_id",
        "elapsed_from_capture_ms", "capture_to_enforcement_ms",
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "direction",
        "pkt_len", "payload_len", "threat_type", "risk_score", "rule_score",
        "ml_score", "action", "base_action", "success", "error",
    ]
    handle = StringIO()
    writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return handle.getvalue()
