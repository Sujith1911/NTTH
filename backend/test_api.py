#!/usr/bin/env python3
"""
API integration test script for NO TIME TO HACK.

Tests all major API endpoints against a running backend.

Usage:
    cd backend
    python test_api.py --base-url http://localhost:8000 --password changeme
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import sys

import requests


def _ok(name: str) -> None:
    print(f"  [PASS] {name}")


def _fail(name: str, detail: str) -> None:
    print(f"  [FAIL] {name}: {detail}")


def run_tests(base: str, password: str) -> int:
    failures = 0
    session = requests.Session()
    user_session = requests.Session()
    temp_username = f"user_{datetime.now(timezone.utc).strftime('%H%M%S')}"
    temp_password = "userpass123"

    print("\n=== NO TIME TO HACK - API Integration Tests ===\n")

    print("[ Health ]")
    try:
        response = session.get(f"{base}/api/v1/system/health", timeout=5)
        assert response.status_code == 200, f"status={response.status_code}"
        data = response.json()
        assert "status" in data and "db_ok" in data, f"unexpected payload keys={sorted(data.keys())}"
        missing = [
            key
            for key in ("websocket_clients", "event_bus_backlog", "event_bus_subscribers")
            if key not in data
        ]
        assert not missing, (
            "health payload is missing expected runtime fields "
            f"{missing}; the server at {base} may be running older code"
        )
        _ok(
            "GET /system/health -> "
            f"status={data['status']}, db_ok={data['db_ok']}, "
            f"ws_clients={data['websocket_clients']}, backlog={data['event_bus_backlog']}"
        )
    except Exception as exc:
        _fail("GET /system/health", str(exc))
        failures += 1

    print("\n[ Auth ]")
    try:
        response = session.post(
            f"{base}/api/v1/auth/login",
            json={"username": "admin", "password": password},
            timeout=5,
        )
        assert response.status_code == 200, f"status={response.status_code}"
        body = response.json()
        assert "access_token" in body
        refresh_token = body.get("refresh_token", "")
        session.headers["Authorization"] = f"Bearer {body['access_token']}"
        _ok("POST /auth/login")
    except Exception as exc:
        _fail("POST /auth/login", str(exc))
        failures += 1
        print("\n  Cannot continue without auth token - aborting.\n")
        return failures

    try:
        response = session.post(
            f"{base}/api/v1/auth/login",
            json={"username": "admin", "password": "WRONG"},
            timeout=5,
        )
        assert response.status_code == 401, f"expected 401, got {response.status_code}"
        _ok("POST /auth/login with wrong password -> 401")
    except Exception as exc:
        _fail("Wrong password rejection", str(exc))
        failures += 1

    try:
        response = session.get(f"{base}/api/v1/auth/me", timeout=5)
        assert response.status_code == 200, f"status={response.status_code}"
        me = response.json()
        assert me["username"] == "admin"
        _ok(f"GET /auth/me -> username={me['username']}, role={me['role']}")
    except Exception as exc:
        _fail("GET /auth/me", str(exc))
        failures += 1

    try:
        response = session.get(f"{base}/api/v1/auth/users", timeout=5)
        assert response.status_code == 200, f"status={response.status_code}"
        users = response.json()
        assert isinstance(users, list) and len(users) >= 1
        _ok(f"GET /auth/users -> {len(users)} user(s)")
    except Exception as exc:
        _fail("GET /auth/users", str(exc))
        failures += 1

    try:
        response = session.post(
            f"{base}/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
            timeout=5,
        )
        assert response.status_code == 200, f"status={response.status_code}"
        new_tokens = response.json()
        assert "access_token" in new_tokens
        _ok("POST /auth/refresh (body) -> new tokens issued")
    except Exception as exc:
        _fail("POST /auth/refresh", str(exc))
        failures += 1

    try:
        response = session.post(
            f"{base}/api/v1/auth/register",
            json={
                "username": temp_username,
                "password": temp_password,
                "role": "user",
            },
            timeout=5,
        )
        assert response.status_code == 201, f"status={response.status_code}"
        _ok(f"POST /auth/register -> created user {temp_username}")
    except Exception as exc:
        _fail("POST /auth/register", str(exc))
        failures += 1

    try:
        response = user_session.post(
            f"{base}/api/v1/auth/login",
            json={"username": temp_username, "password": temp_password},
            timeout=5,
        )
        assert response.status_code == 200, f"status={response.status_code}"
        body = response.json()
        user_session.headers["Authorization"] = f"Bearer {body['access_token']}"
        _ok(f"POST /auth/login -> standard user {temp_username}")
    except Exception as exc:
        _fail("User login", str(exc))
        failures += 1

    print("\n[ Roles ]")
    try:
        response = user_session.get(f"{base}/api/v1/devices", timeout=5)
        assert response.status_code == 200, f"status={response.status_code}"
        _ok("User can access GET /devices")
    except Exception as exc:
        _fail("User GET /devices", str(exc))
        failures += 1

    try:
        response = user_session.get(f"{base}/api/v1/auth/users", timeout=5)
        assert response.status_code == 403, f"expected 403, got {response.status_code}"
        _ok("User blocked from GET /auth/users -> 403")
    except Exception as exc:
        _fail("User GET /auth/users", str(exc))
        failures += 1

    try:
        response = user_session.post(f"{base}/api/v1/firewall/flush", json={}, timeout=5)
        assert response.status_code == 403, f"expected 403, got {response.status_code}"
        _ok("User blocked from POST /firewall/flush -> 403")
    except Exception as exc:
        _fail("User POST /firewall/flush", str(exc))
        failures += 1

    try:
        response = user_session.post(f"{base}/api/v1/honeypot/start", json={}, timeout=5)
        assert response.status_code == 403, f"expected 403, got {response.status_code}"
        _ok("User blocked from POST /honeypot/start -> 403")
    except Exception as exc:
        _fail("User POST /honeypot/start", str(exc))
        failures += 1

    print("\n[ Devices ]")
    device_id = None
    try:
        response = session.get(f"{base}/api/v1/devices", timeout=5)
        assert response.status_code == 200, f"status={response.status_code}"
        data = response.json()
        assert "total" in data and "items" in data
        _ok(f"GET /devices -> {data['total']} devices")
        if data["items"]:
            device_id = data["items"][0]["id"]
    except Exception as exc:
        _fail("GET /devices", str(exc))
        failures += 1

    if device_id:
        try:
            response = user_session.put(
                f"{base}/api/v1/devices/{device_id}/trust",
                json={"is_trusted": True},
                timeout=5,
            )
            assert response.status_code == 403, f"expected 403, got {response.status_code}"
            _ok("User blocked from PUT /devices/{id}/trust -> 403")
        except Exception as exc:
            _fail("User PUT /devices/{id}/trust", str(exc))
            failures += 1

    if device_id:
        try:
            response = session.get(f"{base}/api/v1/devices/{device_id}", timeout=5)
            assert response.status_code == 200, f"status={response.status_code}"
            _ok(f"GET /devices/{{id}} -> ip={response.json().get('ip_address')}")
        except Exception as exc:
            _fail("GET /devices/{id}", str(exc))
            failures += 1

        try:
            response = session.put(
                f"{base}/api/v1/devices/{device_id}/trust",
                json={"is_trusted": True},
                timeout=5,
            )
            assert response.status_code == 200, f"status={response.status_code}"
            assert response.json()["is_trusted"] is True
            _ok("PUT /devices/{id}/trust -> is_trusted=true")
        except Exception as exc:
            _fail("PUT /devices/{id}/trust", str(exc))
            failures += 1

        try:
            response = session.get(f"{base}/api/v1/devices/{device_id}/stats", timeout=5)
            assert response.status_code == 200, f"status={response.status_code}"
            data = response.json()
            assert "total" in data
            _ok(f"GET /devices/{{id}}/stats -> {data['total']} stat records")
        except Exception as exc:
            _fail("GET /devices/{id}/stats", str(exc))
            failures += 1

    print("\n[ System Stats ]")
    try:
        response = session.get(f"{base}/api/v1/system/stats", timeout=5)
        assert response.status_code == 200, f"status={response.status_code}"
        stats = response.json()
        assert "total_devices" in stats and "total_threats" in stats
        _ok(
            f"GET /system/stats -> devices={stats['total_devices']}, "
            f"threats={stats['total_threats']}, rules={stats['active_firewall_rules']}"
        )
    except Exception as exc:
        _fail("GET /system/stats", str(exc))
        failures += 1

    print("\n[ Threats ]")
    try:
        response = session.get(f"{base}/api/v1/threats", timeout=5)
        assert response.status_code == 200, f"status={response.status_code}"
        data = response.json()
        assert "total" in data
        _ok(f"GET /threats -> {data['total']} events")
    except Exception as exc:
        _fail("GET /threats", str(exc))
        failures += 1

    try:
        response = session.get(f"{base}/api/v1/threats/stats", timeout=5)
        assert response.status_code == 200, f"status={response.status_code}"
        stats = response.json()
        assert "total" in stats and "by_type" in stats
        _ok(f"GET /threats/stats -> total={stats['total']}, {len(stats['by_type'])} type(s)")
    except Exception as exc:
        _fail("GET /threats/stats", str(exc))
        failures += 1

    print("\n[ Firewall ]")
    try:
        response = session.get(f"{base}/api/v1/firewall/rules", timeout=5)
        assert response.status_code == 200, f"status={response.status_code}"
        _ok(f"GET /firewall/rules -> {len(response.json())} active rules")
    except Exception as exc:
        _fail("GET /firewall/rules", str(exc))
        failures += 1

    try:
        response = session.get(f"{base}/api/v1/firewall/rules/history", timeout=5)
        assert response.status_code == 200, f"status={response.status_code}"
        data = response.json()
        assert "total" in data
        _ok(f"GET /firewall/rules/history -> {data['total']} total rules")
    except Exception as exc:
        _fail("GET /firewall/rules/history", str(exc))
        failures += 1

    print("\n[ Honeypot ]")
    try:
        response = session.get(f"{base}/api/v1/honeypot/sessions", timeout=5)
        assert response.status_code == 200, f"status={response.status_code}"
        data = response.json()
        _ok(f"GET /honeypot/sessions -> {data['total']} sessions")
    except Exception as exc:
        _fail("GET /honeypot/sessions", str(exc))
        failures += 1

    try:
        response = session.get(f"{base}/api/v1/honeypot/status", timeout=5)
        assert response.status_code == 200
        _ok("GET /honeypot/status -> " + response.json().get("status", "?"))
    except Exception as exc:
        _fail("GET /honeypot/status", str(exc))
        failures += 1

    try:
        response = session.delete(f"{base}/api/v1/auth/users/{temp_username}", timeout=5)
        assert response.status_code == 204, f"status={response.status_code}"
        _ok(f"DELETE /auth/users/{temp_username} -> deactivated")
    except Exception as exc:
        _fail("DELETE /auth/users/{username}", str(exc))
        failures += 1

    print(f"\n{'=' * 40}")
    if failures == 0:
        print("  [PASS] All tests passed!\n")
    else:
        print(f"  [FAIL] {failures} test(s) failed\n")
    return failures


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NTTH API Integration Tests")
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--password", default="changeme")
    args = parser.parse_args()
    sys.exit(run_tests(args.base_url, args.password))
