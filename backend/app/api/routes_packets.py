"""
Packet Inspector API — REST endpoints for browsing captured network packets.

Users can filter by IP, protocol, threat type, and view packet statistics.
All endpoints require User-level JWT authentication.
"""
from __future__ import annotations

import csv
import io
import json
import struct

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Response, status
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


def _filter_args(payload: dict | None) -> dict:
    payload = payload or {}
    return {
        "src_ip": (payload.get("src_ip") or "").strip() or None,
        "dst_ip": (payload.get("dst_ip") or "").strip() or None,
        "protocol": (payload.get("protocol") or "").strip() or None,
        "service_ports": _service_ports(payload.get("service")),
        "direction": (payload.get("direction") or "").strip() or None,
        "threat_type": (payload.get("threat_type") or "").strip() or None,
        "captured_from": local_input_to_utc_naive(payload.get("captured_from")),
        "captured_to": local_input_to_utc_naive(payload.get("captured_to"), end_of_day=True),
        "only_threats": bool(payload.get("only_threats", False)),
        "search": (payload.get("search") or "").strip() or None,
    }


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
        "tls_sni": pkt.tls_sni,
        "tls_alpn": pkt.tls_alpn,
        "tls_version": pkt.tls_version,
        "tls_record_type": pkt.tls_record_type,
        "quic_hint": pkt.quic_hint,
        "flow_id": pkt.flow_id,
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
    search: str = Query(None, description="Search endpoints, HTTP fields, TLS SNI, or payload text"),
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
        search=search,
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


@router.get("/flows/{flow_id}")
async def packet_flow(
    flow_id: str,
    limit: int = Query(200, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
):
    packets = await crud.packets_by_flow(db, flow_id, limit=limit)
    return {
        "flow_id": flow_id,
        "total_returned": len(packets),
        "items": [_packet_payload(pkt) for pkt in packets],
    }


def _pcap_bytes(packets) -> bytes:
    out = io.BytesIO()
    out.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
    for pkt in packets:
        try:
            src = bytes(int(part) for part in pkt.src_ip.split("."))
            dst = bytes(int(part) for part in pkt.dst_ip.split("."))
        except Exception:
            continue
        payload = bytes.fromhex(pkt.payload_preview or "")
        proto = {"icmp": 1, "tcp": 6, "udp": 17}.get(pkt.protocol, 0)
        ip_header = bytearray(20)
        ip_header[0] = 0x45
        ip_header[8] = pkt.ip_ttl or 64
        ip_header[9] = proto
        ip_header[12:16] = src
        ip_header[16:20] = dst
        transport = b""
        if pkt.protocol == "tcp":
            flags = 0
            flag_text = pkt.flags or ""
            for marker, bit in (("F", 0x01), ("S", 0x02), ("R", 0x04), ("P", 0x08), ("A", 0x10)):
                if marker in flag_text:
                    flags |= bit
            transport = struct.pack(
                "!HHIIBBHHH",
                pkt.src_port or 0,
                pkt.dst_port or 0,
                pkt.tcp_seq or 0,
                pkt.tcp_ack or 0,
                5 << 4,
                flags,
                pkt.tcp_window or 0,
                0,
                0,
            )
        elif pkt.protocol == "udp":
            transport = struct.pack("!HHHH", pkt.src_port or 0, pkt.dst_port or 0, 8 + len(payload), 0)
        elif pkt.protocol == "icmp":
            transport = struct.pack("!BBH", pkt.icmp_type or 0, pkt.icmp_code or 0, 0)
        total_len = 20 + len(transport) + len(payload)
        ip_header[2:4] = total_len.to_bytes(2, "big")
        data = bytes(ip_header) + transport + payload
        ts = pkt.captured_at.timestamp() if pkt.captured_at else 0
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        out.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
        out.write(data)
    return out.getvalue()


@router.post("/export")
async def export_packets(
    payload: dict | None = Body(default=None),
    format: str = Query("csv", pattern="^(csv|json|pcap)$"),
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
):
    filters = _filter_args(payload)
    packets = await crud.export_captured_packets(db, limit=5000, **filters)
    if format == "json":
        body = json.dumps([_packet_payload(pkt) for pkt in packets], default=str)
        return Response(body, media_type="application/json")
    if format == "pcap":
        return Response(
            _pcap_bytes(packets),
            media_type="application/vnd.tcpdump.pcap",
            headers={"Content-Disposition": "attachment; filename=ntth_packets.pcap"},
        )
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "id", "captured_at", "direction", "protocol", "src_ip", "src_port",
            "dst_ip", "dst_port", "pkt_len", "payload_len", "flags", "tls_sni",
            "http_host", "http_path", "threat_type", "risk_score", "action_taken",
        ],
    )
    writer.writeheader()
    for pkt in packets:
        row = _packet_payload(pkt)
        writer.writerow({key: row.get(key) for key in writer.fieldnames})
    return Response(
        output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=ntth_packets.csv"},
    )


@router.post("/delete-filtered")
async def delete_filtered_packets(
    payload: dict | None = Body(default=None),
    db: AsyncSession = Depends(get_db),
    _admin=Depends(require_admin),
):
    """Admin-only: delete all packets matching the current filters."""
    deleted = await crud.delete_captured_packets(
        db,
        **_filter_args(payload),
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
