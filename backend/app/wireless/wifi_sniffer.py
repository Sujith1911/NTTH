"""
WiFi Sniffer — captures raw 802.11 frames using the AR9271 adapter
in monitor mode via Scapy AsyncSniffer.

Coordinates:
  - Channel hopping (background task)
  - Frame extraction → feature dicts
  - Probe tracking (device presence)
  - Deauth detection (attack)
  - Rogue AP detection (evil twin)
  - Event bus publishing for downstream agents

Runs as an asyncio task alongside the wired packet sniffer.
Designed for graceful degradation — if the AR9271 is not present
or monitor mode fails, the wired pipeline continues unaffected.
"""
from __future__ import annotations

import asyncio
from typing import Any, Optional

from app.config import get_settings
from app.core.event_bus import publish
from app.core.logger import get_logger
from app.wireless.wifi_feature_extractor import extract_wifi_features
from app.wireless import probe_tracker, deauth_detector, rogue_ap_detector
from app.wireless.channel_hopper import start_channel_hopper, stop_channel_hopper

log = get_logger("wifi_sniffer")
settings = get_settings()

_running = False
_sniffer: Any = None
_stats = {
    "frames_captured": 0,
    "probes_seen": 0,
    "deauths_seen": 0,
    "beacons_seen": 0,
    "threats_detected": 0,
}


def is_running() -> bool:
    """Return whether the WiFi sniffer is actively capturing."""
    global _running, _sniffer
    thread = getattr(_sniffer, "thread", None)
    alive = bool(_running and thread and thread.is_alive())
    if _running and not alive:
        _running = False
    return alive


def get_stats() -> dict:
    """Return capture statistics."""
    return {
        **_stats,
        "running": is_running(),
        "interface": settings.wifi_interface,
    }


async def start_wifi_sniffer() -> None:
    """
    Entry point — start the AR9271 monitor mode sniffer.

    Called from main.py lifespan if WIFI_ENABLED=true.
    """
    global _running, _sniffer

    if not settings.wifi_enabled:
        log.info("wifi_sniffer.disabled", hint="Set WIFI_ENABLED=true to enable")
        return

    iface = settings.wifi_interface
    if not iface:
        log.warning("wifi_sniffer.no_interface", hint="Set WIFI_INTERFACE in .env")
        return

    try:
        from scapy.all import AsyncSniffer  # type: ignore
    except ImportError:
        log.warning("wifi_sniffer.scapy_unavailable")
        return

    # Configure detectors from settings
    deauth_detector.configure(
        threshold=settings.deauth_threshold,
        window_seconds=settings.deauth_window_seconds,
    )

    # Configure rogue AP whitelist
    if settings.ap_whitelist_ssids:
        rogue_ap_detector.configure_whitelist(settings.ap_whitelist_ssids)

    loop = asyncio.get_event_loop()

    def _wifi_callback(pkt: Any) -> None:
        """Called by Scapy for each captured 802.11 frame."""
        features = extract_wifi_features(pkt)
        if not features:
            return

        _stats["frames_captured"] += 1
        frame_type = features.get("frame_type")

        if frame_type == "probe_request":
            _stats["probes_seen"] += 1
            # Update probe tracker
            device_state = probe_tracker.update(features)
            if device_state:
                asyncio.run_coroutine_threadsafe(
                    publish("wifi_probe_seen", {**features, "device_state": device_state}),
                    loop,
                )

            # Check if this is a known attacker (persistent MAC tracking)
            src_mac = features.get("src_mac")
            if src_mac:
                try:
                    from app.monitor.persistent_tracker import check_wifi_probe
                    attacker = check_wifi_probe(src_mac, [features.get("ssid")] if features.get("ssid") else [])
                    if attacker:
                        asyncio.run_coroutine_threadsafe(
                            publish("wifi_threat_detected", {
                                "threat_type": "known_attacker_nearby",
                                "severity": "high",
                                "src_mac": src_mac,
                                "bssid": "",
                                "rssi": features.get("rssi"),
                                "description": f"Known attacker device {src_mac} detected nearby via WiFi probe",
                                "attacker_profile": attacker,
                                "timestamp": features.get("timestamp"),
                            }),
                            loop,
                        )
                except Exception:
                    pass

        elif frame_type == "deauth":
            _stats["deauths_seen"] += 1
            # Check for deauth attack
            threat = deauth_detector.evaluate(features)
            if threat:
                _stats["threats_detected"] += 1
                asyncio.run_coroutine_threadsafe(
                    publish("wifi_threat_detected", threat),
                    loop,
                )

        elif frame_type == "beacon":
            _stats["beacons_seen"] += 1
            # Check for rogue AP
            threat = rogue_ap_detector.evaluate(features)
            if threat:
                _stats["threats_detected"] += 1
                asyncio.run_coroutine_threadsafe(
                    publish("wifi_threat_detected", threat),
                    loop,
                )

    # Start channel hopper
    channels = settings.wifi_channels
    hopper_task = asyncio.create_task(
        start_channel_hopper(
            interface=iface,
            channels=channels,
            hop_interval=settings.wifi_hop_interval,
        ),
        name="wifi_channel_hopper",
    )

    # Small delay to let hopper initialize
    await asyncio.sleep(0.5)

    # Start Scapy sniffer on monitor interface
    sniffer = None
    try:
        sniffer = AsyncSniffer(
            iface=iface,
            prn=_wifi_callback,
            store=False,
            # No BPF filter — we want all 802.11 frames in monitor mode
        )
        sniffer.start()
        _sniffer = sniffer
        await asyncio.sleep(0.5)

        thread = getattr(sniffer, "thread", None)
        if not thread or not thread.is_alive():
            raise RuntimeError(f"WiFi sniffer on {iface} exited immediately")

        _running = True
        log.info("wifi_sniffer.started", interface=iface, channels=channels)

        # Keep alive until stopped
        while is_running():
            await asyncio.sleep(1)

    except PermissionError:
        log.warning(
            "wifi_sniffer.permission_denied",
            hint="Run as root for monitor mode capture",
        )
    except OSError as exc:
        if "No such device" in str(exc):
            log.warning(
                "wifi_sniffer.adapter_not_found",
                interface=iface,
                hint="Plug in AR9271 and run: sudo airmon-ng start <interface>",
            )
        else:
            log.warning("wifi_sniffer.os_error", error=str(exc))
    except Exception as exc:
        log.warning("wifi_sniffer.error", error=str(exc))
    finally:
        try:
            if sniffer and getattr(sniffer, "running", False):
                sniffer.stop()
        except Exception:
            pass
        stop_channel_hopper()
        hopper_task.cancel()
        _running = False
        _sniffer = None
        log.info("wifi_sniffer.stopped")


def stop_wifi_sniffer() -> None:
    """Signal the WiFi sniffer to stop."""
    global _running
    _running = False
    stop_channel_hopper()
