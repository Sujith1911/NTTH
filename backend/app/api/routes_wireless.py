"""
Wireless API routes — REST endpoints for WiFi monitoring data.

All endpoints require User-level JWT authentication.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends

from app.dependencies import get_current_user, require_admin

router = APIRouter()


@router.get("/status")
async def wireless_status(_user=Depends(get_current_user)):
    """AR9271 adapter status, capture stats, and detector state."""
    from app.wireless.wifi_sniffer import get_stats, is_running
    from app.wireless.deauth_detector import get_stats as deauth_stats
    from app.wireless.rogue_ap_detector import get_rogue_count, get_observed_aps
    from app.wireless.probe_tracker import get_device_count
    from app.config import get_settings

    settings = get_settings()

    # Auto-monitor setup status
    monitor_info = {}
    try:
        from app.wireless.auto_monitor import get_monitor_status
        monitor_info = get_monitor_status()
    except Exception:
        pass

    return {
        "enabled": settings.wifi_enabled,
        "interface": settings.wifi_interface,
        "running": is_running(),
        "capture_stats": get_stats(),
        "tracked_devices": get_device_count(),
        "observed_aps": len(get_observed_aps()),
        "rogue_ap_alerts": get_rogue_count(),
        "deauth_stats": deauth_stats(),
        "auto_monitor": monitor_info,
    }


@router.get("/devices")
async def wireless_devices(_user=Depends(get_current_user)):
    """List all WiFi devices discovered via probe requests."""
    from app.wireless.probe_tracker import get_all_devices
    devices = get_all_devices()
    return {
        "count": len(devices),
        "devices": devices,
    }


@router.get("/devices/{mac}")
async def wireless_device_detail(mac: str, _user=Depends(get_current_user)):
    """Get detailed info for a specific WiFi device by MAC address."""
    from app.wireless.probe_tracker import get_device
    device = get_device(mac)
    if not device:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="WiFi device not found")
    return device


@router.get("/probes")
async def wireless_probes(_user=Depends(get_current_user)):
    """List all unique SSIDs seen in probe requests."""
    from app.wireless.probe_tracker import get_unique_ssids, get_device_count
    ssids = get_unique_ssids()
    return {
        "total_devices": get_device_count(),
        "unique_ssids": len(ssids),
        "ssids": ssids,
    }


@router.get("/aps")
async def wireless_aps(_user=Depends(get_current_user)):
    """List all observed access points from beacon frames."""
    from app.wireless.rogue_ap_detector import get_observed_aps
    aps = get_observed_aps()
    return {
        "count": len(aps),
        "access_points": aps,
    }


@router.get("/whitelist")
async def get_ap_whitelist(_user=Depends(get_current_user)):
    """Get the current AP SSID whitelist."""
    from app.wireless.rogue_ap_detector import get_whitelist
    return {"whitelist": get_whitelist()}


@router.post("/whitelist")
async def update_ap_whitelist(
    body: dict,
    _user=Depends(require_admin),
):
    """
    Update the AP SSID whitelist.

    Body: ``{"ssids": ["MyNetwork", "MyNetwork_5G"]}``
    """
    ssids = body.get("ssids", [])
    if not isinstance(ssids, list):
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="ssids must be a list")

    from app.wireless.rogue_ap_detector import configure_whitelist
    configure_whitelist(ssids)
    return {"status": "updated", "ssids": ssids}


@router.get("/threats")
async def wireless_threats(_user=Depends(get_current_user)):
    """Get current WiFi threat monitoring state."""
    from app.wireless.deauth_detector import get_stats as deauth_stats
    from app.wireless.rogue_ap_detector import get_rogue_count

    return {
        "deauth_monitoring": deauth_stats(),
        "rogue_ap_alerts": get_rogue_count(),
    }
