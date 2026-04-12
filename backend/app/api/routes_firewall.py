"""
Firewall routes: view/add/delete rules, full history, emergency flush.
Write operations are admin-only.
"""
from __future__ import annotations

import shutil
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.config import get_settings
from app.database import crud
from app.database.schemas import FirewallRuleCreate, FirewallRuleRead, PaginatedResponse
from app.dependencies import get_current_user, get_db, require_admin

router = APIRouter()
settings = get_settings()


def _firewall_runtime_status() -> dict:
    nft_available = shutil.which("nft") is not None
    if not settings.firewall_enabled:
        return {
            "desired_enabled": False,
            "runtime_supported": nft_available,
            "mode": "simulation",
            "reason": "Firewall enforcement is disabled in deployment configuration.",
        }
    if not nft_available:
        return {
            "desired_enabled": True,
            "runtime_supported": False,
            "mode": "degraded",
            "reason": "nftables is not available in the current runtime, so redirects and blocks cannot be enforced.",
        }
    return {
        "desired_enabled": True,
        "runtime_supported": True,
        "mode": "enforcing",
        "reason": None,
    }


@router.get("/status")
async def firewall_status(
    db=Depends(get_db),
    _user=Depends(get_current_user),
):
    active_rules = await crud.list_active_firewall_rules(db)
    total_rules, _ = await crud.list_all_firewall_rules(db, 1, 1)
    containment = await crud.get_containment_summary(db)
    runtime = _firewall_runtime_status()
    return {
        **runtime,
        "active_rules": len(active_rules),
        "total_rules_seen": total_rules,
        "containment": containment,
        "rule_types": {
            "block": "Drop all traffic from a hostile source IP.",
            "rate_limit": "Throttle a noisy source to reduce impact while observing it.",
            "redirect": "Send the hostile source to the honeypot instead of the real service.",
        },
    }


@router.get("/rules", response_model=list[FirewallRuleRead])
async def list_rules(
    db=Depends(get_db),
    _user=Depends(get_current_user),
):
    """List currently active firewall rules."""
    rules = await crud.list_active_firewall_rules(db)
    return [FirewallRuleRead.model_validate(r) for r in rules]


@router.get("/rules/history", response_model=PaginatedResponse)
async def list_rules_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db=Depends(get_db),
    _user=Depends(get_current_user),
):
    """Paginated history of ALL firewall rules (active and expired)."""
    total, rules = await crud.list_all_firewall_rules(db, page, page_size)
    return PaginatedResponse(
        total=total, page=page, page_size=page_size,
        items=[FirewallRuleRead.model_validate(r) for r in rules],
    )


@router.post("/rules", response_model=FirewallRuleRead, status_code=status.HTTP_201_CREATED)
async def add_rule(
    payload: FirewallRuleCreate,
    db=Depends(get_db),
    admin=Depends(require_admin),
):
    if not settings.firewall_enabled:
        raise HTTPException(status_code=503, detail="Firewall control is disabled in this deployment")
    from app.firewall.nft_manager import NFTManager
    nft = NFTManager()
    handle = None
    try:
        if payload.rule_type == "block":
            handle = await nft.add_block(
                payload.target_ip,
                persist=False,
                created_by=admin.username,
                reason=payload.reason,
            )
        elif payload.rule_type == "rate_limit":
            handle = await nft.add_rate_limit(
                payload.target_ip,
                persist=False,
                created_by=admin.username,
                reason=payload.reason,
            )
        elif payload.rule_type == "drop":
            handle = await nft.add_block(
                payload.target_ip,
                persist=False,
                created_by=admin.username,
                reason=payload.reason,
            )
        elif payload.rule_type == "redirect":
            if payload.target_port is None:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="redirect rules require target_port to specify the original attacked port",
                )
            handle = await nft.add_redirect(
                payload.target_ip,
                src_port=payload.target_port,
                dst_port=settings.cowrie_redirect_port,
                persist=False,
                created_by=admin.username,
                reason=payload.reason,
            )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"nftables error: {exc}")

    expires_at = (
        datetime.utcnow() + timedelta(seconds=payload.expires_in_seconds)
        if payload.expires_in_seconds else None
    )
    rule = await crud.create_firewall_rule(
        db,
        rule_type=payload.rule_type,
        target_ip=payload.target_ip,
        target_port=(
            settings.cowrie_redirect_port
            if payload.rule_type == "redirect"
            else payload.target_port
        ),
        match_dst_port=(
            payload.target_port
            if payload.rule_type == "redirect"
            else None
        ),
        protocol=payload.protocol,
        nft_handle=handle,
        created_by=admin.username,
        expires_at=expires_at,
        reason=payload.reason,
    )
    return FirewallRuleRead.model_validate(rule)


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    rule_id: str,
    db=Depends(get_db),
    _admin=Depends(require_admin),
):
    if not settings.firewall_enabled:
        raise HTTPException(status_code=503, detail="Firewall control is disabled in this deployment")
    rule = await crud.deactivate_firewall_rule(db, rule_id)
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    if rule.nft_handle and rule.nft_handle != "unknown":
        from app.firewall.nft_manager import NFTManager
        await NFTManager().delete_rule(rule.nft_handle)


@router.post("/flush", status_code=status.HTTP_200_OK)
async def emergency_flush(_admin=Depends(require_admin)):
    """Flush ALL ntth firewall rules — emergency use only."""
    if not settings.firewall_enabled:
        raise HTTPException(status_code=503, detail="Firewall control is disabled in this deployment")
    from app.database.session import AsyncSessionLocal
    from app.firewall.nft_manager import NFTManager
    success = await NFTManager().flush_chain()
    if not success:
        raise HTTPException(status_code=500, detail="Flush failed — check nft logs")
    async with AsyncSessionLocal() as db:
        removed = await crud.deactivate_all_firewall_rules(db)
        await db.commit()
    return {"message": "All NTTH firewall rules flushed", "success": True, "deactivated_rules": removed}
