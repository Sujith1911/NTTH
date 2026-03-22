"""
Enhanced packet sniffer:
- Works on Windows with Npcap installed
- Auto-detects network interface
- Updates the in-memory live stats registry per packet
- Falls back to dummy event emitter if Scapy unavailable
"""
from __future__ import annotations

import asyncio
import ipaddress
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
_sniffer: Any | None = None


def is_running() -> bool:
    """Return whether the underlying sniffer thread is alive."""
    global _running, _sniffer
    thread = getattr(_sniffer, "thread", None)
    alive = bool(_running and thread and thread.is_alive())
    if _running and not alive:
        _running = False
    return alive


def _can_start_capture() -> tuple[bool, str | None]:
    """Detect whether packet capture is supported in the current environment."""
    if sys.platform == "win32":
        try:
            from scapy.config import conf  # type: ignore
        except Exception as exc:
            return False, f"Scapy configuration unavailable: {exc}"

        if not getattr(conf, "use_pcap", False) or getattr(conf, "L2listen", None) is None:
            return False, "Npcap/WinPcap is not available for layer-2 capture"

    return True, None


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

            preferred_prefix = None
            try:
                preferred_prefix = str(ipaddress.ip_interface(f"{settings.server_display_ip}/24").network.network_address)
            except ValueError:
                preferred_prefix = None

            def _score_iface(iface: dict[str, Any]) -> tuple[int, int]:
                name = (iface.get("name") or "").lower()
                ips = [ip for ip in iface.get("ips", []) if "." in ip]
                has_private = any(
                    ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.")
                    for ip in ips
                )
                is_virtual = any(token in name for token in ("virtual", "vethernet", "vmware", "hyper-v", "loopback"))
                matches_host_subnet = False
                if preferred_prefix:
                    for ip in ips:
                        try:
                            subnet = str(ipaddress.ip_interface(f"{ip}/24").network.network_address)
                            if subnet == preferred_prefix:
                                matches_host_subnet = True
                                break
                        except ValueError:
                            continue
                return (
                    3 if matches_host_subnet else 0,
                    2 if has_private else 0,
                ) if not is_virtual else (0, 0)

            ranked = sorted(ifaces, key=_score_iface, reverse=True)
            for iface in ranked:
                name = iface.get("name", "")
                ips = iface.get("ips", [])
                if _score_iface(iface) > (0, 0):
                    log.info("sniffer.auto_detected_iface", iface=name, ips=ips)
                    return name
            for iface in ranked:
                name = iface.get("name", "")
                ips = iface.get("ips", [])
                if any("." in ip for ip in ips):
                    log.info("sniffer.fallback_iface", iface=name, ips=ips)
                    return name
        except Exception as exc:
            log.debug("sniffer.iface_detect_failed", error=str(exc))
        return None  # Let Scapy pick default
    return configured


async def start_sniffer() -> None:
    """Entry point — run Scapy sniffer in a thread-pool executor."""
    global _running, _sniffer

    try:
        from scapy.all import AsyncSniffer  # type: ignore
    except ImportError:
        log.warning("sniffer.scapy_unavailable",
                    hint="Install Scapy and Npcap (Windows) for packet capture")
        return

    can_start, reason = _can_start_capture()
    if not can_start:
        log.warning("sniffer.unavailable", reason=reason)
        _running = False
        _sniffer = None
        return

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

    sniffer = None
    try:
        sniffer = AsyncSniffer(**sniffer_kwargs)
        sniffer.start()
        _sniffer = sniffer
        await asyncio.sleep(0.25)
        thread = getattr(sniffer, "thread", None)
        if not thread or not thread.is_alive():
            raise RuntimeError("Packet capture backend exited immediately after startup")
        _running = True
        log.info("sniffer.started", iface=iface or "auto")

        while is_running():
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
            if sniffer and getattr(sniffer, "running", False):
                sniffer.stop()
        except Exception:
            pass
        _running = False
        _sniffer = None
        log.info("sniffer.stopped")


def stop_sniffer() -> None:
    global _running
    _running = False
