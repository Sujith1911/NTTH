"""
Packet Inspector API — REST endpoints for browsing captured network packets.

Users can filter by IP, protocol, threat type, and view packet statistics.
All endpoints require User-level JWT authentication.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import crud
from app.config import get_settings
from app.core.time_utils import local_input_to_utc_naive, utc_naive_to_local_iso
from app.dependencies import get_current_user, get_db, require_admin

router = APIRouter()
settings = get_settings()

SERVICE_PORTS: dict[str, list[int]] = {
    "ftp": [20, 21],
    "ssh": [22],
    "telnet": [23],
    "dns": [53],
    "http": [80, 8080, 8888],
    "https": [443, 8443],
    "ntp": [123],
    "smb": [445],
    "dns_tls": [853],
    "mysql": [3306],
    "rdp": [3389],
    "ipsec": [500, 4500],
    "vnc": [5900],
    "redis": [6379],
    "mongodb": [27017],
}


def _service_ports(service: str | None) -> list[int] | None:
    if not service:
        return None
    normalized = service.strip().lower().replace("-", "_")
    return SERVICE_PORTS.get(normalized)


def _packet_payload(pkt) -> dict:
    return {
        "id": pkt.id,
        "src_ip": pkt.src_ip,
        "dst_ip": pkt.dst_ip,
        "src_port": pkt.src_port,
        "dst_port": pkt.dst_port,
        "protocol": pkt.protocol,
        "pkt_len": pkt.pkt_len,
        "payload_len": pkt.payload_len,
        "direction": pkt.direction,
        "src_mac": pkt.src_mac,
        "dst_mac": pkt.dst_mac,
        "ip_version": pkt.ip_version,
        "ip_ttl": pkt.ip_ttl,
        "ip_tos": pkt.ip_tos,
        "ip_id": pkt.ip_id,
        "ip_flags": pkt.ip_flags,
        "frag_offset": pkt.frag_offset,
        "flags": pkt.flags,
        "tcp_seq": pkt.tcp_seq,
        "tcp_ack": pkt.tcp_ack,
        "tcp_window": pkt.tcp_window,
        "tcp_options": pkt.tcp_options,
        "udp_len": pkt.udp_len,
        "icmp_type": pkt.icmp_type,
        "icmp_code": pkt.icmp_code,
        "payload_preview": pkt.payload_preview,
        "payload_text": pkt.payload_text,
        "http_method": pkt.http_method,
        "http_host": pkt.http_host,
        "http_path": pkt.http_path,
        "http_user_agent": pkt.http_user_agent,
        "http_content_type": pkt.http_content_type,
        "http_body_preview": pkt.http_body_preview,
        "http_form_fields": pkt.http_form_fields,
        "is_syn": pkt.is_syn,
        "is_ack": pkt.is_ack,
        "is_rst": pkt.is_rst,
        "threat_type": pkt.threat_type,
        "risk_score": pkt.risk_score,
        "action_taken": pkt.action_taken,
        "captured_at": utc_naive_to_local_iso(pkt.captured_at),
    }


@router.get("")
async def list_packets(
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    src_ip: str = Query(None, description="Filter by source IP"),
    dst_ip: str = Query(None, description="Filter by destination IP"),
    protocol: str = Query(None, description="Filter by protocol: tcp, udp, icmp"),
    service: str = Query(None, description="Filter by service: http, https, dns, ssh, ..."),
    direction: str = Query(None, description="Filter by direction: inbound, outbound, local, unknown"),
    threat_type: str = Query(None, description="Filter by threat type"),
    captured_from: str = Query(None, description="Local date/datetime lower bound"),
    captured_to: str = Query(None, description="Local date/datetime upper bound"),
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
        service_ports=_service_ports(service),
        direction=direction,
        threat_type=threat_type,
        captured_from=local_input_to_utc_naive(captured_from),
        captured_to=local_input_to_utc_naive(captured_to, end_of_day=True),
        only_threats=only_threats,
    )
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [
            _packet_payload(pkt)
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


@router.post("/delete-filtered")
async def delete_filtered_packets(
    payload: dict | None = Body(default=None),
    db: AsyncSession = Depends(get_db),
    _admin=Depends(require_admin),
):
    """Admin-only: delete all packets matching the current filters."""
    payload = payload or {}
    deleted = await crud.delete_captured_packets(
        db,
        src_ip=(payload.get("src_ip") or "").strip() or None,
        dst_ip=(payload.get("dst_ip") or "").strip() or None,
        protocol=(payload.get("protocol") or "").strip() or None,
        service_ports=_service_ports(payload.get("service")),
        direction=(payload.get("direction") or "").strip() or None,
        threat_type=(payload.get("threat_type") or "").strip() or None,
        captured_from=local_input_to_utc_naive(payload.get("captured_from")),
        captured_to=local_input_to_utc_naive(payload.get("captured_to"), end_of_day=True),
        only_threats=bool(payload.get("only_threats", False)),
    )
    await db.commit()
    return {"deleted": deleted}


@router.post("/cleanup-noise")
async def cleanup_packet_noise(
    db: AsyncSession = Depends(get_db),
    _admin=Depends(require_admin),
):
    """Admin-only: remove synthetic scan/broadcast packet rows."""
    deleted = await crud.purge_packet_noise(db)
    demo_cleanup = await crud.purge_synthetic_demo_data(db)
    benign_cleanup = await crud.purge_benign_web_false_positives(db)
    scanner_cleanup = await crud.purge_scanner_false_positives(
        db,
        server_ip=settings.server_display_ip,
        subnet=settings.scan_subnet,
    )
    await db.commit()
    return {
        "deleted": deleted,
        "demo_cleanup": demo_cleanup,
        "benign_cleanup": benign_cleanup,
        "scanner_cleanup": scanner_cleanup,
    }


@router.get("/{packet_id}")
async def packet_detail(
    packet_id: int,
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
):
    pkt = await crud.get_captured_packet(db, packet_id)
    if not pkt:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Packet not found")
    return _packet_payload(pkt)


@router.delete("/{packet_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_packet(
    packet_id: int,
    db: AsyncSession = Depends(get_db),
    _admin=Depends(require_admin),
):
    deleted = await crud.delete_captured_packet(db, packet_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Packet not found")
    await db.commit()
