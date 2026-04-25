"""
Packet Inspector API — REST endpoints for browsing captured network packets.

Users can filter by IP, protocol, threat type, and view packet statistics.
All endpoints require User-level JWT authentication.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import crud
from app.dependencies import get_current_user, get_db

router = APIRouter()


@router.get("")
async def list_packets(
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    src_ip: str = Query(None, description="Filter by source IP"),
    dst_ip: str = Query(None, description="Filter by destination IP"),
    protocol: str = Query(None, description="Filter by protocol: tcp, udp, icmp"),
    threat_type: str = Query(None, description="Filter by threat type"),
    only_threats: bool = Query(False, description="Show only threat-flagged packets"),
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
):
    """
    List captured packets with filtering for forensic inspection.

    Returns paginated packet records with full metadata.
    """
    total, packets = await crud.list_captured_packets(
        db,
        page=page,
        page_size=page_size,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        threat_type=threat_type,
        only_threats=only_threats,
    )
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [
            {
                "id": pkt.id,
                "src_ip": pkt.src_ip,
                "dst_ip": pkt.dst_ip,
                "src_port": pkt.src_port,
                "dst_port": pkt.dst_port,
                "protocol": pkt.protocol,
                "pkt_len": pkt.pkt_len,
                "flags": pkt.flags,
                "is_syn": pkt.is_syn,
                "is_ack": pkt.is_ack,
                "is_rst": pkt.is_rst,
                "threat_type": pkt.threat_type,
                "risk_score": pkt.risk_score,
                "action_taken": pkt.action_taken,
                "captured_at": pkt.captured_at.isoformat() if pkt.captured_at else None,
            }
            for pkt in packets
        ],
    }


@router.get("/stats")
async def packet_stats(
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
):
    """
    Aggregated packet capture statistics for the dashboard.

    Returns total captured, threat vs normal split, and protocol breakdown.
    """
    return await crud.get_captured_packet_stats(db)
