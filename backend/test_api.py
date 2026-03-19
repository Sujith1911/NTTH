#!/usr/bin/env python3
"""
API Integration Test Script — NO TIME TO HACK
==============================================
Tests all major API endpoints against a running backend.

Usage:
    cd backend
    python test_api.py --base-url http://localhost:8000 --password changeme

Requires: requests (pip install requests)
"""
from __future__ import annotations

import argparse
import json
import sys
import time

import requests


def _ok(name: str) -> None:
    print(f"  ✅  {name}")


def _fail(name: str, detail: str) -> None:
    print(f"  ❌  {name}: {detail}")


def run_tests(base: str, password: str) -> int:
    failures = 0
    session = requests.Session()
    token = ""

    print("\n═══ NO TIME TO HACK — API Integration Tests ═══\n")

    # ── Health (unauthenticated) ──────────────────────────────────────────────
    print("[ Health ]")
    try:
        r = session.get(f"{base}/api/v1/system/health", timeout=5)
        assert r.status_code == 200, f"status={r.status_code}"
        data = r.json()
        assert "status" in data and "db_ok" in data
        _ok(f"GET /system/health → status={data['status']}, db_ok={data['db_ok']}")
    except Exception as e:
        _fail("GET /system/health", str(e))
        failures += 1

    # ── Auth ──────────────────────────────────────────────────────────────────
    print("\n[ Auth ]")
    try:
        r = session.post(f"{base}/api/v1/auth/login", json={"username": "admin", "password": password}, timeout=5)
        assert r.status_code == 200, f"status={r.status_code}"
        body = r.json()
        assert "access_token" in body
        token = body["access_token"]
        refresh_token = body.get("refresh_token", "")
        session.headers["Authorization"] = f"Bearer {token}"
        _ok("POST /auth/login")
    except Exception as e:
        _fail("POST /auth/login", str(e))
        failures += 1
        print("\n  Cannot continue without auth token — aborting.\n")
        return failures

    try:
        r = session.post(f"{base}/api/v1/auth/login", json={"username": "admin", "password": "WRONG"}, timeout=5)
        assert r.status_code == 401, f"expected 401, got {r.status_code}"
        _ok("POST /auth/login with wrong password → 401")
    except Exception as e:
        _fail("Wrong password rejection", str(e))
        failures += 1

    # GET /me
    try:
        r = session.get(f"{base}/api/v1/auth/me", timeout=5)
        assert r.status_code == 200, f"status={r.status_code}"
        me = r.json()
        assert me["username"] == "admin"
        _ok(f"GET /auth/me → username={me['username']}, role={me['role']}")
    except Exception as e:
        _fail("GET /auth/me", str(e))
        failures += 1

    # GET /users (admin)
    try:
        r = session.get(f"{base}/api/v1/auth/users", timeout=5)
        assert r.status_code == 200, f"status={r.status_code}"
        users = r.json()
        assert isinstance(users, list) and len(users) >= 1
        _ok(f"GET /auth/users → {len(users)} user(s)")
    except Exception as e:
        _fail("GET /auth/users", str(e))
        failures += 1

    # Token refresh (body-based)
    try:
        r = session.post(
            f"{base}/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
            timeout=5,
        )
        assert r.status_code == 200, f"status={r.status_code}"
        new_tokens = r.json()
        assert "access_token" in new_tokens
        _ok("POST /auth/refresh (body) → new tokens issued")
    except Exception as e:
        _fail("POST /auth/refresh", str(e))
        failures += 1

    # ── Devices ───────────────────────────────────────────────────────────────
    print("\n[ Devices ]")
    device_id = None
    try:
        r = session.get(f"{base}/api/v1/devices", timeout=5)
        assert r.status_code == 200, f"status={r.status_code}"
        data = r.json()
        assert "total" in data and "items" in data
        _ok(f"GET /devices → {data['total']} devices")
        if data["items"]:
            device_id = data["items"][0]["id"]
    except Exception as e:
        _fail("GET /devices", str(e))
        failures += 1

    if device_id:
        # GET /devices/{id}
        try:
            r = session.get(f"{base}/api/v1/devices/{device_id}", timeout=5)
            assert r.status_code == 200, f"status={r.status_code}"
            _ok(f"GET /devices/{{id}} → ip={r.json().get('ip_address')}")
        except Exception as e:
            _fail("GET /devices/{id}", str(e))
            failures += 1

        # PUT /devices/{id}/trust
        try:
            r = session.put(f"{base}/api/v1/devices/{device_id}/trust", json={"is_trusted": True}, timeout=5)
            assert r.status_code == 200, f"status={r.status_code}"
            assert r.json()["is_trusted"] is True
            _ok("PUT /devices/{id}/trust → is_trusted=true")
        except Exception as e:
            _fail("PUT /devices/{id}/trust", str(e))
            failures += 1

        # GET /devices/{id}/stats
        try:
            r = session.get(f"{base}/api/v1/devices/{device_id}/stats", timeout=5)
            assert r.status_code == 200, f"status={r.status_code}"
            data = r.json()
            assert "total" in data
            _ok(f"GET /devices/{{id}}/stats → {data['total']} stat records")
        except Exception as e:
            _fail("GET /devices/{id}/stats", str(e))
            failures += 1

    # ── System Stats ──────────────────────────────────────────────────────────
    print("\n[ System Stats ]")
    try:
        r = session.get(f"{base}/api/v1/system/stats", timeout=5)
        assert r.status_code == 200, f"status={r.status_code}"
        s = r.json()
        assert "total_devices" in s and "total_threats" in s
        _ok(
            f"GET /system/stats → devices={s['total_devices']}, "
            f"threats={s['total_threats']}, rules={s['active_firewall_rules']}"
        )
    except Exception as e:
        _fail("GET /system/stats", str(e))
        failures += 1

    # ── Threats ───────────────────────────────────────────────────────────────
    print("\n[ Threats ]")
    try:
        r = session.get(f"{base}/api/v1/threats", timeout=5)
        assert r.status_code == 200, f"status={r.status_code}"
        data = r.json()
        assert "total" in data
        _ok(f"GET /threats → {data['total']} events")
    except Exception as e:
        _fail("GET /threats", str(e))
        failures += 1

    try:
        r = session.get(f"{base}/api/v1/threats/stats", timeout=5)
        assert r.status_code == 200, f"status={r.status_code}"
        s = r.json()
        assert "total" in s and "by_type" in s
        _ok(f"GET /threats/stats → total={s['total']}, {len(s['by_type'])} type(s)")
    except Exception as e:
        _fail("GET /threats/stats", str(e))
        failures += 1

    # ── Firewall ──────────────────────────────────────────────────────────────
    print("\n[ Firewall ]")
    try:
        r = session.get(f"{base}/api/v1/firewall/rules", timeout=5)
        assert r.status_code == 200, f"status={r.status_code}"
        _ok(f"GET /firewall/rules → {len(r.json())} active rules")
    except Exception as e:
        _fail("GET /firewall/rules", str(e))
        failures += 1

    try:
        r = session.get(f"{base}/api/v1/firewall/rules/history", timeout=5)
        assert r.status_code == 200, f"status={r.status_code}"
        data = r.json()
        assert "total" in data
        _ok(f"GET /firewall/rules/history → {data['total']} total rules")
    except Exception as e:
        _fail("GET /firewall/rules/history", str(e))
        failures += 1

    # ── Honeypot ──────────────────────────────────────────────────────────────
    print("\n[ Honeypot ]")
    try:
        r = session.get(f"{base}/api/v1/honeypot/sessions", timeout=5)
        assert r.status_code == 200, f"status={r.status_code}"
        data = r.json()
        _ok(f"GET /honeypot/sessions → {data['total']} sessions")
    except Exception as e:
        _fail("GET /honeypot/sessions", str(e))
        failures += 1

    try:
        r = session.get(f"{base}/api/v1/honeypot/status", timeout=5)
        assert r.status_code == 200
        _ok("GET /honeypot/status → " + r.json().get("status", "?"))
    except Exception as e:
        _fail("GET /honeypot/status", str(e))
        failures += 1

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{'═' * 40}")
    if failures == 0:
        print("  ✅  All tests passed!\n")
    else:
        print(f"  ❌  {failures} test(s) failed\n")
    return failures


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NTTH API Integration Tests")
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--password", default="changeme")
    args = parser.parse_args()
    sys.exit(run_tests(args.base_url, args.password))
