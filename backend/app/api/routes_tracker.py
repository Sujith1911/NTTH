"""
Attacker Tracker API — REST endpoints for persistent attacker tracking.

Exposes the MAC-based fingerprinting data to the dashboard and external tools.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.dependencies import get_current_user, require_admin

router = APIRouter()


@router.get("/attackers")
async def list_attackers(_user=Depends(get_current_user)):
    """List all known attackers from the persistent tracker."""
    from app.monitor.persistent_tracker import get_all_attackers
    attackers = get_all_attackers()
    return {
        "count": len(attackers),
        "attackers": attackers,
    }


@router.get("/attackers/{mac}")
async def get_attacker(mac: str, _user=Depends(get_current_user)):
    """Get details for a specific attacker by MAC address."""
    from app.monitor.persistent_tracker import get_attacker_by_mac
    attacker = get_attacker_by_mac(mac)
    if not attacker:
        raise HTTPException(status_code=404, detail="Attacker MAC not found")
    return attacker


@router.delete("/attackers/{mac}")
async def remove_attacker(mac: str, _user=Depends(require_admin)):
    """Remove a MAC from the attacker tracker (admin only)."""
    from app.monitor.persistent_tracker import remove_attacker
    removed = remove_attacker(mac)
    if not removed:
        raise HTTPException(status_code=404, detail="Attacker MAC not found")
    return {"status": "removed", "mac": mac}


@router.get("/honeypots")
async def list_honeypots(_user=Depends(get_current_user)):
    """List all active multi-protocol honeypot instances."""
    from app.honeypot.multi_honeypot import get_active_honeypots
    honeypots = get_active_honeypots()
    return {
        "count": len(honeypots),
        "honeypots": honeypots,
    }


@router.get("/honeypots/sessions")
async def list_honeypot_sessions(_user=Depends(get_current_user)):
    """List recent honeypot interaction sessions."""
    from app.honeypot.multi_honeypot import get_recent_sessions
    sessions = get_recent_sessions()
    return {
        "count": len(sessions),
        "sessions": sessions,
    }


@router.get("/feedback")
async def feedback_metrics(_user=Depends(get_current_user)):
    """Get feedback agent metrics: FP rate, honeypot engagement, etc."""
    from app.agents.feedback_agent import get_feedback_metrics
    return get_feedback_metrics()


@router.get("/feedback/top-enforced")
async def top_enforced(_user=Depends(get_current_user)):
    """Get the most frequently enforced IPs."""
    from app.agents.feedback_agent import get_top_enforced
    return {"items": get_top_enforced(limit=20)}


@router.get("/feedback/history/{ip}")
async def enforcement_history(ip: str, _user=Depends(get_current_user)):
    """Get enforcement history for a specific IP."""
    from app.agents.feedback_agent import get_enforcement_history
    history = get_enforcement_history(ip)
    return {"ip": ip, "count": len(history), "events": history}
