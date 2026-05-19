#!/usr/bin/env python3
"""Summarize NTTH research metrics JSONL into paper-ready markdown tables."""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean


def _load(path: Path) -> list[dict]:
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _fmt(value) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.3f}"
    return str(value)


def _table(headers: list[str], rows: list[list]) -> str:
    out = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        out.append("| " + " | ".join(_fmt(value) for value in row) + " |")
    return "\n".join(out)


def summarize(rows: list[dict]) -> str:
    by_experiment: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        exp = row.get("experiment_id") or "unlabeled"
        by_experiment[exp].append(row)

    stage_rows = []
    detection_rows = []
    latency_rows = []
    for exp, events in sorted(by_experiment.items()):
        stages = Counter(str(e.get("stage")) for e in events)
        actions = Counter(str(e.get("action")) for e in events if e.get("action"))
        threats = Counter(str(e.get("threat_type")) for e in events if e.get("threat_type"))
        latencies = [
            float(e["capture_to_enforcement_ms"])
            for e in events
            if isinstance(e.get("capture_to_enforcement_ms"), (int, float))
        ]
        stage_rows.append([
            exp,
            stages.get("packet_observed", 0),
            stages.get("packet_observed_sample", 0),
            stages.get("threat_scored", 0),
            stages.get("decision_made", 0),
            stages.get("enforcement_done", 0),
        ])
        detection_rows.append([
            exp,
            sum(threats.values()),
            ", ".join(f"{k}:{v}" for k, v in sorted(threats.items())) or "-",
            ", ".join(f"{k}:{v}" for k, v in sorted(actions.items())) or "-",
        ])
        latency_rows.append([
            exp,
            len(latencies),
            min(latencies) if latencies else None,
            mean(latencies) if latencies else None,
            max(latencies) if latencies else None,
        ])

    parts = [
        "## Stage Counts",
        _table(
            ["Experiment", "Packets", "Packet Samples", "Threats", "Decisions", "Enforcement Done"],
            stage_rows,
        ),
        "",
        "## Detection Summary",
        _table(["Experiment", "Threat Events", "Threat Types", "Actions"], detection_rows),
        "",
        "## Capture-to-Enforcement Latency",
        _table(["Experiment", "Samples", "Min ms", "Avg ms", "Max ms"], latency_rows),
    ]
    return "\n".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jsonl", type=Path, help="Path to ntth_research_metrics.jsonl")
    args = parser.parse_args()
    rows = _load(args.jsonl)
    print(summarize(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
