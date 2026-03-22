#!/usr/bin/env python3
"""
Startup regression check for noisy DEBUG environment variables.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent


def _free_port() -> int:
    """Return a free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


_TIMEOUT = 60


def _expected_sniffer_running() -> bool:
    if sys.platform != "win32":
        return True

    try:
        from scapy.config import conf  # type: ignore
    except Exception:
        return False

    return bool(getattr(conf, "use_pcap", False) and getattr(conf, "L2listen", None) is not None)


def main() -> int:
    env = os.environ.copy()
    env["DEBUG"] = "release"
    env["PYTHONIOENCODING"] = "utf-8"

    port = _free_port()  # pick a free port dynamically each run
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        deadline = time.time() + _TIMEOUT
        while time.time() < deadline:
            if process.poll() is not None:
                stdout, stderr = process.communicate(timeout=5)
                raise RuntimeError(
                    f"Server exited early under DEBUG=release\n"
                    f"stdout:\n{stdout}\n"
                    f"stderr:\n{stderr}"
                )
            try:
                response = requests.get(
                    f"http://127.0.0.1:{port}/api/v1/system/health", timeout=2
                )
                if response.status_code == 200:
                    body = response.json()
                    expected_sniffer = _expected_sniffer_running()
                    if body.get("sniffer_running") != expected_sniffer:
                        raise RuntimeError(
                            "Unexpected sniffer health state: "
                            f"expected sniffer_running={expected_sniffer}, got {body.get('sniffer_running')}"
                        )
                    print("startup regression check passed")
                    print(response.text)
                    return 0
            except requests.RequestException:
                time.sleep(0.5)

        # Timeout — collect any stderr for diagnostics
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
        raise RuntimeError(
            f"Server did not become healthy within {_TIMEOUT} seconds\n"
            f"stderr tail:\n" + "\n".join((stderr or "").splitlines()[-20:])
        )
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
