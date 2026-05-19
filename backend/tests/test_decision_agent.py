from app.agents import decision_agent
from app.config import get_settings


def test_suspicious_ssh_to_protected_device_redirects_to_cowrie():
    settings = get_settings()
    action, response_mode, honeypot_port = decision_agent._choose_response_action(
        {
            "protocol": "tcp",
            "dst_port": 22,
            "risk_score": settings.risk_rate_limit_threshold,
        },
        "rate_limit",
    )

    assert action == "honeypot"
    assert response_mode == "intercept_service_to_honeypot"
    assert honeypot_port == settings.cowrie_redirect_port


def test_suspicious_http_to_protected_device_redirects_to_http_honeypot():
    settings = get_settings()
    action, response_mode, honeypot_port = decision_agent._choose_response_action(
        {
            "protocol": "tcp",
            "dst_port": 80,
            "risk_score": settings.risk_rate_limit_threshold,
        },
        "rate_limit",
    )

    assert action == "honeypot"
    assert response_mode == "intercept_service_to_honeypot"
    assert honeypot_port == settings.http_honeypot_port


def test_direct_honeypot_port_is_not_redirected_again():
    settings = get_settings()
    action, response_mode, honeypot_port = decision_agent._choose_response_action(
        {
            "protocol": "tcp",
            "dst_port": settings.cowrie_redirect_port,
            "risk_score": settings.risk_rate_limit_threshold,
        },
        "rate_limit",
    )

    assert action == "rate_limit"
    assert response_mode == "observe_and_throttle"
    assert honeypot_port is None


def test_low_risk_ssh_is_observed_not_intercepted():
    action, response_mode, honeypot_port = decision_agent._choose_response_action(
        {
            "protocol": "tcp",
            "dst_port": 22,
            "risk_score": 0.2,
        },
        "log",
    )

    assert action == "log"
    assert response_mode == "observe"
    assert honeypot_port is None
