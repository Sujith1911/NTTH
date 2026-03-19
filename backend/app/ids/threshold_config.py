"""
Configurable IDS thresholds — all values flow from app/config.py.
Import this in rule_engine.py and risk_calculator.py.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.config import get_settings

_s = get_settings()


@dataclass(frozen=True)
class ThresholdConfig:
    # Risk action thresholds
    log_threshold: float = _s.risk_log_threshold
    rate_limit_threshold: float = _s.risk_rate_limit_threshold
    honeypot_threshold: float = _s.risk_honeypot_threshold
    block_threshold: float = _s.risk_block_threshold

    # Rule engine detectors
    port_scan_window_seconds: int = _s.port_scan_window_seconds
    port_scan_unique_ports: int = _s.port_scan_unique_ports
    syn_flood_per_second: int = _s.syn_flood_per_second
    brute_force_window_seconds: int = _s.brute_force_window_seconds
    brute_force_attempts: int = _s.brute_force_attempts

    # Risk weighting
    rule_weight: float = 0.6
    ml_weight: float = 0.4


THRESHOLDS = ThresholdConfig()
