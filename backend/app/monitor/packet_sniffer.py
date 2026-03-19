"""
Enhanced packet sniffer:
- Works on Windows with Npcap installed
- Auto-detects network interface
- Updates the in-memory live stats registry per packet
- Falls back to dummy event emitter if Scapy unavailable
"""
from __future__ import annotations

import asyncio
import sys
from typing import Any

from app.config import get_settings
from app.core.event_bus import publish
from app.core.logger import get_logger
from app.monitor.device_registry import update as registry_update
from app.monitor.feature_extractor import extract_features
from app.monitor.network_scanner import update_live_stats

log = get_logger("packet_sniffer")
settings = get_settings()

_running = False


def _detect_interface() -> str:
    """Auto-detect the primary network interface."""
    configured = settings.network_interface
    if configured and configured not in ("eth0", ""):
        return configured

    # On Windows, try to find the active WiFi/Ethernet interface via Scapy
    if sys.platform == "win32":
        try:
            from scapy.arch.windows import get_windows_if_list  # type: ignore
            ifaces = get_windows_if_list()
            # Prefer interfaces that are up and not loopback
            for iface in ifaces:
                name = iface.get("name", "")
                ips = iface.get("ips", [])
                if any(ip.startswith("192.168.") or ip.startswith("10.") for ip in ips):
                    log.info("sniffer.auto_detected_iface", iface=name, ips=ips)
                    return name
        except Exception as exc:
            log.debug("sniffer.iface_detect_failed", error=str(exc))
        return None  # Let Scapy pick default
    return configured


async def start_sniffer() -> None:
    """Entry point — run Scapy sniffer in a thread-pool executor."""
    try:
        from scapy.all import AsyncSniffer  # type: ignore
    except ImportError:
        log.warning("sniffer.scapy_unavailable",
                    hint="Install Scapy and Npcap (Windows) for packet capture")
        return

    global _running
    _running = True
    loop = asyncio.get_event_loop()
    iface = _detect_interface()

    def _packet_callback(pkt: Any) -> None:
        """Called by Scapy for each captured packet (runs in executor thread)."""
        features = extract_features(pkt)
        if not features:
            return

        # Update in-memory live stats (no DB needed)
        update_live_stats(features)

        # Update device registry (publishes device_seen to event bus)
        registry_update(features)

        # Publish to event bus async-safe
        asyncio.run_coroutine_threadsafe(
            publish("device_seen", features), loop
        )

    sniffer_kwargs: dict = {
        "prn": _packet_callback,
        "store": False,
        "filter": "ip",
    }
    if iface:
        sniffer_kwargs["iface"] = iface

    try:
        sniffer = AsyncSniffer(**sniffer_kwargs)
        sniffer.start()
        log.info("sniffer.started", iface=iface or "auto")

        while _running:
            await asyncio.sleep(1)

    except PermissionError:
        log.warning(
            "sniffer.permission_denied",
            hint="Run as Administrator (Windows) or root (Linux) with Npcap installed"
        )
    except OSError as exc:
        log.warning("sniffer.interface_error", error=str(exc))
    except Exception as exc:
        log.warning("sniffer.error", error=str(exc))
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass
        _running = False
        log.info("sniffer.stopped")


def stop_sniffer() -> None:
    global _running
    _running = False
