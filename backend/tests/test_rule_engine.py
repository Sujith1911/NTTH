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


def test_rule_details_include_arp_sweep_context():
    src_ip = "192.168.4.251"
    result = None
    for host in range(20, 20 + THRESHOLDS.arp_sweep_unique_targets):
        result = rule_engine.evaluate({
            "src_ip": src_ip,
            "dst_ip": f"192.168.4.{host}",
            "protocol": "arp",
            "arp_target_ip": f"192.168.4.{host}",
            "is_arp_request": True,
        })

    assert result is not None
    assert result["threat_type"] == "arp_sweep"
    assert result["rule_details"]["arp_sweep"]["unique_targets"] >= THRESHOLDS.arp_sweep_unique_targets
    assert result["rule_details"]["winning_rule"] == "arp_sweep"


def test_rule_details_include_host_sweep_context():
    src_ip = "192.168.4.252"
    result = None
    for host in range(30, 30 + THRESHOLDS.host_sweep_unique_targets):
        result = rule_engine.evaluate({
            "src_ip": src_ip,
            "dst_ip": f"192.168.4.{host}",
            "protocol": "icmp",
        })

    assert result is not None
    assert result["threat_type"] == "host_sweep"
    assert result["rule_details"]["host_sweep"]["unique_targets"] >= THRESHOLDS.host_sweep_unique_targets
    assert result["rule_details"]["winning_rule"] == "host_sweep"


def test_rule_details_include_stealth_scan_context():
    src_ip = "192.168.4.253"
    result = None
    for _ in range(THRESHOLDS.stealth_scan_attempts):
        result = rule_engine.evaluate({
            "src_ip": src_ip,
            "dst_ip": "192.168.4.1",
            "protocol": "tcp",
            "dst_port": 80,
            "flags": "FPU",
        })

    assert result is not None
    assert result["threat_type"] == "stealth_scan"
    assert result["rule_details"]["stealth_scan"]["attempts"] >= THRESHOLDS.stealth_scan_attempts
    assert result["rule_details"]["winning_rule"] == "stealth_scan"
