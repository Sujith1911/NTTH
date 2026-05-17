from app.ids import rule_engine
from app.ids.threshold_config import THRESHOLDS


def test_rule_details_include_port_scan_context():
    src_ip = "192.168.4.250"
    result = None
    for port in range(10_000, 10_000 + THRESHOLDS.port_scan_unique_ports):
        result = rule_engine.evaluate({
            "src_ip": src_ip,
            "dst_port": port,
            "is_syn": True,
        })

    assert result is not None
    assert result["threat_type"] in {"port_scan", "suspicious"}
    assert result["rule_details"]["port_scan"]["unique_ports"] >= THRESHOLDS.port_scan_unique_ports
    assert result["rule_details"]["winning_rule"] == "port_scan"
