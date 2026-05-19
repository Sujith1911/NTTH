import json

from app.research import metrics


def test_metrics_records_capture_to_enforcement_latency(tmp_path, monkeypatch):
    monkeypatch.setattr(metrics, "_data_dir", lambda: tmp_path)
    metrics._recent_events.clear()
    metrics._stage_counts.clear()
    metrics._action_counts.clear()
    metrics._threat_counts.clear()
    metrics._latency_ms.clear()
    metrics._current_experiment = None
    metrics._packet_observed_total = 0

    experiment = metrics.start_experiment("unit_latency", scenario="unit")
    payload = {
        "src_ip": "192.168.4.50",
        "dst_ip": "192.168.4.1",
        "protocol": "tcp",
        "dst_port": 22,
    }

    metrics.mark_packet_observed(payload)
    payload.update(
        {
            "threat_type": "port_scan",
            "risk_score": 0.8,
            "rule_score": 0.8,
            "ml_score": 0.0,
            "action": "block",
        }
    )
    metrics.mark_threat_scored(payload)
    metrics.mark_decision(payload)
    metrics.mark_report(payload)
    metrics.mark_enforcement_start(payload)
    metrics.mark_enforcement_done(payload, success=True)
    metrics.stop_experiment()

    summary = metrics.summary()
    assert summary["current_experiment"] is None
    assert summary["stage_counts"]["threat_scored"] == 1
    assert summary["stage_counts"]["enforcement_done"] == 1
    assert summary["action_counts"]["block"] >= 1
    assert summary["capture_to_enforcement_latency"]["count"] == 1
    assert summary["capture_to_enforcement_latency"]["avg_ms"] >= 0

    jsonl = metrics.export_jsonl()
    assert experiment["id"] in jsonl
    assert "enforcement_done" in jsonl

    csv_payload = metrics.export_csv()
    assert "capture_to_enforcement_ms" in csv_payload
    assert "192.168.4.50" in csv_payload

    rows = [json.loads(line) for line in jsonl.splitlines() if line.strip()]
    assert any(row.get("stage") == "experiment_started" for row in rows)
    assert any(row.get("success") is True for row in rows)

