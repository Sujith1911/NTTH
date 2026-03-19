"""
Risk calculator — combines rule_score and ml_score into a final risk score.
Formula: risk = 0.6 * rule_score + 0.4 * ml_score
"""
from __future__ import annotations

from app.ids.threshold_config import THRESHOLDS


def calculate(rule_score: float, ml_score: float) -> float:
    """Return weighted risk score in [0.0, 1.0]."""
    risk = THRESHOLDS.rule_weight * rule_score + THRESHOLDS.ml_weight * ml_score
    return round(min(max(risk, 0.0), 1.0), 4)


def determine_action(risk_score: float) -> str:
    """
    Map risk score to a decision string.
    log | rate_limit | honeypot | block
    """
    if risk_score >= THRESHOLDS.block_threshold:
        return "block"
    if risk_score >= THRESHOLDS.honeypot_threshold:
        return "honeypot"
    if risk_score >= THRESHOLDS.rate_limit_threshold:
        return "rate_limit"
    if risk_score >= THRESHOLDS.log_threshold:
        return "log"
    return "allow"
