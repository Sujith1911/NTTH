"""
SQLAlchemy ORM models — one class per DB table.
Tables: users, devices, device_stats, threat_events,
        honeypot_sessions, firewall_rules, system_logs
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey,
    Integer, String, Text, func,
)
from sqlalchemy.orm import relationship

from app.database.session import Base


def _uuid() -> str:
    return str(uuid.uuid4())


# ── Users ─────────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=_uuid)
    username = Column(String(64), unique=True, nullable=False, index=True)
    hashed_password = Column(String(128), nullable=False)
    role = Column(String(16), nullable=False, default="user")  # "admin" | "user"
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)


# ── Devices ───────────────────────────────────────────────────────────────────

class Device(Base):
    __tablename__ = "devices"

    id = Column(String(36), primary_key=True, default=_uuid)
    ip_address = Column(String(45), unique=True, nullable=False, index=True)
    mac_address = Column(String(17), nullable=True)
    hostname = Column(String(128), nullable=True)
    vendor = Column(String(128), nullable=True)
    first_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    is_trusted = Column(Boolean, default=False, nullable=False)
    risk_score = Column(Float, default=0.0, nullable=False)

    stats = relationship("DeviceStat", back_populates="device", cascade="all, delete-orphan")
    threats = relationship("ThreatEvent", back_populates="device", cascade="all, delete-orphan")


class DeviceStat(Base):
    __tablename__ = "device_stats"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String(36), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    recorded_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    packet_count = Column(Integer, default=0)
    byte_count = Column(Integer, default=0)
    unique_ports = Column(Integer, default=0)
    syn_count = Column(Integer, default=0)
    protocol = Column(String(8), nullable=True)

    device = relationship("Device", back_populates="stats")


# ── Threat Events ─────────────────────────────────────────────────────────────

class ThreatEvent(Base):
    __tablename__ = "threat_events"

    id = Column(String(36), primary_key=True, default=_uuid)
    device_id = Column(String(36), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True)
    src_ip = Column(String(45), nullable=False, index=True)
    dst_ip = Column(String(45), nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(8), nullable=True)
    threat_type = Column(String(64), nullable=False)  # port_scan | syn_flood | brute_force | anomaly
    risk_score = Column(Float, nullable=False)
    rule_score = Column(Float, nullable=True)
    ml_score = Column(Float, nullable=True)
    action_taken = Column(String(32), nullable=True)  # log | rate_limit | honeypot | block
    # GeoIP
    country = Column(String(64), nullable=True)
    city = Column(String(64), nullable=True)
    asn = Column(String(64), nullable=True)
    org = Column(String(128), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)

    detected_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    acknowledged = Column(Boolean, default=False, nullable=False)
    acknowledged_by = Column(String(64), nullable=True)
    notes = Column(Text, nullable=True)

    device = relationship("Device", back_populates="threats")


# ── Honeypot Sessions ─────────────────────────────────────────────────────────

class HoneypotSession(Base):
    __tablename__ = "honeypot_sessions"

    id = Column(String(36), primary_key=True, default=_uuid)
    session_id = Column(String(64), unique=True, nullable=False, index=True)  # Cowrie session ID
    attacker_ip = Column(String(45), nullable=False, index=True)
    observed_attacker_ip = Column(String(45), nullable=True)
    attacker_port = Column(Integer, nullable=True)
    victim_ip = Column(String(45), nullable=True, index=True)
    victim_port = Column(Integer, nullable=True)
    honeypot_type = Column(String(16), nullable=False)  # "ssh" | "http"
    username_tried = Column(String(128), nullable=True)
    password_tried = Column(String(256), nullable=True)
    commands_run = Column(Text, nullable=True)  # JSON list
    duration_seconds = Column(Float, nullable=True)
    source_masked = Column(Boolean, default=False, nullable=False)
    source_mask_reason = Column(Text, nullable=True)
    # GeoIP
    country = Column(String(64), nullable=True)
    city = Column(String(64), nullable=True)
    asn = Column(String(64), nullable=True)
    org = Column(String(128), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)

    started_at = Column(DateTime, nullable=False, index=True)
    ended_at = Column(DateTime, nullable=True)


# ── Firewall Rules ────────────────────────────────────────────────────────────

class FirewallRule(Base):
    __tablename__ = "firewall_rules"

    id = Column(String(36), primary_key=True, default=_uuid)
    rule_type = Column(String(32), nullable=False)  # rate_limit | block | redirect | drop
    target_ip = Column(String(45), nullable=False, index=True)
    target_port = Column(Integer, nullable=True)
    match_dst_ip = Column(String(45), nullable=True, index=True)
    match_dst_port = Column(Integer, nullable=True)
    protocol = Column(String(8), nullable=True)
    nft_handle = Column(String(64), nullable=True)  # nftables internal handle for deletion
    is_active = Column(Boolean, default=True, nullable=False)
    created_by = Column(String(64), nullable=True)  # "system" | username
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    removed_at = Column(DateTime, nullable=True)
    reason = Column(Text, nullable=True)


# ── System Logs ───────────────────────────────────────────────────────────────

class SystemLog(Base):
    __tablename__ = "system_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    level = Column(String(16), nullable=False)  # DEBUG | INFO | WARNING | ERROR | CRITICAL
    component = Column(String(64), nullable=False)
    message = Column(Text, nullable=False)
    extra = Column(Text, nullable=True)  # JSON blob for arbitrary key-value pairs
    logged_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)


# ── Captured Packets ──────────────────────────────────────────────────────────

class CapturedPacket(Base):
    """
    Stores monitored network packets for user inspection and forensic analysis.
    Only 'interesting' packets are persisted (threats, suspicious, or sampled normal).
    """
    __tablename__ = "captured_packets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    src_ip = Column(String(45), nullable=False, index=True)
    dst_ip = Column(String(45), nullable=False, index=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(8), nullable=False)  # tcp | udp | icmp | other
    pkt_len = Column(Integer, nullable=True)
    flags = Column(String(16), nullable=True)  # TCP flags string e.g. "S", "SA", "A"
    is_syn = Column(Boolean, default=False, nullable=False)
    is_ack = Column(Boolean, default=False, nullable=False)
    is_rst = Column(Boolean, default=False, nullable=False)
    threat_type = Column(String(64), nullable=True)  # null for normal traffic
    risk_score = Column(Float, nullable=True)
    action_taken = Column(String(32), nullable=True)  # log | rate_limit | honeypot | block
    captured_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
