"""
Threat Agent — first stage in the agentic pipeline.
Subscribes to 'device_seen' events, runs IDS, enriches with GeoIP,
then publishes a 'threat_detected' event for the Decision Agent.
"""
from __future__ import annotations

from app.core import event_bus
from app.core.logger import get_logger
from app.ids import rule_engine, anomaly_model
from app.ids.risk_calculator import calculate, determine_action
from app.monitor import device_registry
from app.monitor.network_scanner import is_managed_asset_ip

log = get_logger("threat_agent")
_SCANNER_PROBE_PORTS = {
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 5985, 6379,
    8080, 8443, 8888, 9200, 27017,
}
_COMMON_CLIENT_SERVICE_PORTS = {
    53, 80, 123, 443, 500, 853, 8080, 8443, 8888, 4500,
    5222, 5223, 5228, 5229, 5230,
}


async def _handle_device_seen(features: dict) -> None:
    """Process each captured packet's features through the IDS pipeline."""
    from app.config import get_settings
    _settings = get_settings()
    src_ip = features.get("src_ip", "")
    dst_ip = features.get("dst_ip", "")
    try:
        from app.ids.risk_clearance import should_suppress
        if should_suppress(src_ip, features.get("timestamp")):
            return
    except Exception:
        pass

    # Skip traffic from our own IP (our scanner probes ports and triggers false positives)
    _skip_ips = {_settings.server_display_ip, _settings.gateway_ip}
    if src_ip in _skip_ips:
        return

    # Skip multicast/broadcast (mDNS 224.0.0.251, broadcast .255, etc.)
    if (
        src_ip.endswith(".255")
        or dst_ip.endswith(".255")
        or dst_ip.startswith("224.")
        or dst_ip.startswith("239.")
    ):
        return

    device_state = None
    # ── ALWAYS register managed devices, even for benign traffic ──
    # This must happen BEFORE any whitelist return, otherwise devices
    # that only produce whitelisted traffic (VMs, phones) never appear.
    if is_managed_asset_ip(src_ip):
        device_state = device_registry.update(features)

    # Ignore normal web responses from public CDNs to local ephemeral ports.
    # These are replies to Ubuntu/browser traffic, not inbound scans.
    src_port = features.get("src_port")
    dst_port = features.get("dst_port")
    flags = str(features.get("flags") or "")
    server_ip = _settings.server_display_ip

    # Replies to our own TCP connect scanner look like:
    # device:service_port -> server:ephemeral_port. They are not attacks.
    if (
        server_ip
        and dst_ip == server_ip
        and is_managed_asset_ip(src_ip)
        and src_port in _SCANNER_PROBE_PORTS
        and isinstance(dst_port, int)
        and dst_port >= 1024
    ):
        return

    if (
        is_managed_asset_ip(src_ip)
        and dst_ip in {_settings.gateway_ip, _settings.server_display_ip}
        and dst_port in _COMMON_CLIENT_SERVICE_PORTS
    ):
        return

    # Skip responses from public servers back to local ephemeral ports (TCP).
    if (
        src_ip
        and dst_ip
        and not is_managed_asset_ip(src_ip)
        and is_managed_asset_ip(dst_ip)
        and src_port in _COMMON_CLIENT_SERVICE_PORTS
        and isinstance(dst_port, int)
        and dst_port >= 1024
        and ("A" in flags or "S" not in flags)
    ):
        return

    # Skip normal outbound UDP traffic from managed devices to ANY public IP.
    # This covers QUIC/HTTP3, DNS, NTP, and app traffic on non-standard ports.
    # A managed device cannot be an attacker — it's the asset we're protecting.
    protocol = features.get("protocol", "")
    if (
        protocol == "udp"
        and is_managed_asset_ip(src_ip)
        and not is_managed_asset_ip(dst_ip)
    ):
        return

    # Skip inbound UDP responses from public IPs to managed device ephemeral ports.
    # These are reply packets to outbound QUIC/DNS connections initiated by the device.
    if (
        protocol == "udp"
        and not is_managed_asset_ip(src_ip)
        and is_managed_asset_ip(dst_ip)
        and isinstance(dst_port, int)
        and dst_port >= 1024
    ):
        return

    # Skip ALL ICMP from/to managed devices.
    # Browsing generates ICMP (traceroute, CDN pings, gateway pings) — not a threat.
    if protocol == "icmp" and (is_managed_asset_ip(src_ip) or is_managed_asset_ip(dst_ip)):
        return

    # Update device registry (for non-managed IPs that made it past whitelists)
    if not is_managed_asset_ip(src_ip):
        device_state = device_registry.update(features)

    # Rule-based scoring
    rule_result = rule_engine.evaluate(features)

    # ML anomaly scoring
    ml_score = anomaly_model.score(features)

    # Risk calculation
    risk_score = calculate(rule_result["rule_score"], ml_score)
    # Outbound traffic from managed devices to common service ports is ALWAYS benign.
    # Normal phone browsing (HTTPS, DNS, Google Play, etc.) must never raise alerts.
    if (
        features.get("direction") == "outbound"
        and is_managed_asset_ip(src_ip)
        and dst_port in _COMMON_CLIENT_SERVICE_PORTS
    ):
        return
    if rule_result.get("threat_type") == "normal":
        if ml_score < 0.9:
            return
        rule_result["threat_type"] = "anomaly"
    action = determine_action(risk_score, rule_result.get("threat_type", "normal"), src_ip=src_ip)

    # Only emit threat events above the log threshold
    if action == "allow":
        return

    # GeoIP enrichment (non-blocking, best-effort)
    geo_info = {}
    try:
        from app.geoip.geo_lookup import lookup
        geo_info = lookup(features.get("src_ip", ""))
    except Exception:
        pass

    threat_payload = {
        **features,
        **rule_result,
        "ml_score": ml_score,
        "risk_score": risk_score,
        "action": action,
        "risk_reasons": [
            f"rule_score={rule_result.get('rule_score', 0):.2f}",
            f"ml_score={ml_score:.2f}",
            f"port_scan={rule_result.get('port_score', 0):.2f}",
            f"host_sweep={rule_result.get('host_score', 0):.2f}",
            f"arp_sweep={rule_result.get('arp_score', 0):.2f}",
            f"stealth_scan={rule_result.get('stealth_score', 0):.2f}",
            f"syn_flood={rule_result.get('syn_score', 0):.2f}",
            f"brute_force={rule_result.get('brute_score', 0):.2f}",
            f"winning_rule={rule_result.get('rule_details', {}).get('winning_rule', 'none')}",
            f"action={action}",
        ],
        "device_state": device_state,
        **geo_info,
    }

    try:
        from app.research.metrics import mark_threat_scored
        mark_threat_scored(threat_payload)
    except Exception:
        pass

    await event_bus.publish("threat_detected", threat_payload)

    if risk_score >= 0.7:
        log.warning(
            "threat_agent.high_risk",
            src_ip=features.get("src_ip"),
            risk_score=risk_score,
            action=action,
            threat_type=rule_result.get("threat_type"),
        )


# Subscribe at module import time
event_bus.subscribe("device_seen", _handle_device_seen)
