"""
Firewall routes: view/add/delete rules, full history, emergency flush.
Write operations are admin-only.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import crud
from app.database.schemas import FirewallRuleCreate, FirewallRuleRead, PaginatedResponse
from app.dependencies import get_current_user, get_db, require_admin

router = APIRouter()


@router.get("/rules", response_model=list[FirewallRuleRead])
async def list_rules(
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
):
    """List currently active firewall rules."""
    rules = await crud.list_active_firewall_rules(db)
    return [FirewallRuleRead.model_validate(r) for r in rules]


@router.get("/rules/history", response_model=PaginatedResponse)
async def list_rules_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
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
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin),
):
    from app.firewall.nft_manager import NFTManager
    nft = NFTManager()
    handle = None
    try:
        if payload.rule_type == "block":
            handle = await nft.add_block(payload.target_ip)
        elif payload.rule_type == "rate_limit":
            handle = await nft.add_rate_limit(payload.target_ip)
        elif payload.rule_type == "drop":
            handle = await nft.add_block(payload.target_ip)
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
        target_port=payload.target_port,
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
    db: AsyncSession = Depends(get_db),
    _admin=Depends(require_admin),
):
    rule = await crud.deactivate_firewall_rule(db, rule_id)
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    if rule.nft_handle and rule.nft_handle != "unknown":
        from app.firewall.nft_manager import NFTManager
        await NFTManager().delete_rule(rule.nft_handle)


@router.post("/flush", status_code=status.HTTP_200_OK)
async def emergency_flush(_admin=Depends(require_admin)):
    """Flush ALL ntth firewall rules — emergency use only."""
    from app.firewall.nft_manager import NFTManager
    success = await NFTManager().flush_chain()
    if not success:
        raise HTTPException(status_code=500, detail="Flush failed — check nft logs")
    return {"message": "All NTTH firewall rules flushed", "success": True}
