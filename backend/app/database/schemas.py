"""
Pydantic v2 schemas for API request/response validation.
Each model has Read (response) and Create (request) variants where appropriate.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


# ── Shared ────────────────────────────────────────────────────────────────────

class OrmBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ── Auth ──────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshTokenRequest(BaseModel):
    """Body payload for POST /auth/refresh."""
    refresh_token: str


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=8)
    role: str = Field(default="user", pattern="^(admin|user)$")


class UserRead(OrmBase):
    id: str
    username: str
    role: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None


# ── Devices ───────────────────────────────────────────────────────────────────

class DeviceRead(OrmBase):
    id: str
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    is_trusted: bool
    risk_score: float


class DeviceStatRead(OrmBase):
    id: int
    device_id: str
    recorded_at: datetime
    packet_count: int
    byte_count: int
    unique_ports: int
    syn_count: int
    protocol: Optional[str] = None


# ── Threat Events ─────────────────────────────────────────────────────────────

class ThreatEventRead(OrmBase):
    id: str
    device_id: Optional[str] = None
    src_ip: str
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    threat_type: str
    risk_score: float
    rule_score: Optional[float] = None
    ml_score: Optional[float] = None
    action_taken: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[str] = None
    org: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    detected_at: datetime
    acknowledged: bool
    acknowledged_by: Optional[str] = None
    notes: Optional[str] = None
    source_tag: Optional[str] = None
    victim_ip: Optional[str] = None
    response_mode: Optional[str] = None
    location_accuracy: Optional[str] = None
    location_summary: Optional[str] = None
    network_origin: Optional[str] = None
    target_hidden: bool = False
    quarantine_target: bool = False
    honeypot_port: Optional[int] = None


class ThreatAcknowledge(BaseModel):
    notes: Optional[str] = None


# ── Honeypot Sessions ─────────────────────────────────────────────────────────

class HoneypotSessionRead(OrmBase):
    id: str
    session_id: str
    attacker_ip: str
    observed_attacker_ip: Optional[str] = None
    attacker_port: Optional[int] = None
    victim_ip: Optional[str] = None
    victim_port: Optional[int] = None
    honeypot_type: str
    username_tried: Optional[str] = None
    password_tried: Optional[str] = None
    commands_run: Optional[str] = None
    duration_seconds: Optional[float] = None
    source_masked: bool = False
    source_mask_reason: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[str] = None
    org: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    started_at: datetime
    ended_at: Optional[datetime] = None


# ── Firewall Rules ────────────────────────────────────────────────────────────

class FirewallRuleCreate(BaseModel):
    rule_type: str = Field(..., pattern="^(rate_limit|block|redirect|drop)$")
    target_ip: str
    target_port: Optional[int] = None
    protocol: Optional[str] = Field(default=None, pattern="^(tcp|udp|icmp)?$")
    expires_in_seconds: Optional[int] = Field(default=3600, ge=60)
    reason: Optional[str] = None


class FirewallRuleRead(OrmBase):
    id: str
    rule_type: str
    target_ip: str
    target_port: Optional[int] = None
    match_dst_ip: Optional[str] = None
    match_dst_port: Optional[int] = None
    protocol: Optional[str] = None
    nft_handle: Optional[str] = None
    is_active: bool
    created_by: Optional[str] = None
    expires_at: Optional[datetime] = None
    created_at: datetime
    removed_at: Optional[datetime] = None
    reason: Optional[str] = None


# ── System ────────────────────────────────────────────────────────────────────

class SystemLogRead(OrmBase):
    id: int
    level: str
    component: str
    message: str
    extra: Optional[str] = None
    logged_at: datetime


class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    db_ok: bool
    sniffer_running: bool
    scheduler_running: bool
    websocket_clients: int = 0
    event_bus_backlog: int = 0
    event_bus_subscribers: int = 0
    realtime_mode: str = "packet_capture"
    capture_interface: str = ""
    capture_ip: Optional[str] = None
    scan_subnet: str = ""
    packet_capture_degraded: bool = False
    packet_capture_reason: Optional[str] = None
    last_scan: Optional[str] = None
    discovered_devices: int = 0
    firewall_enabled: bool = False
    firewall_mode: str = "disabled"
    firewall_reason: Optional[str] = None
    honeypot_ready: bool = False
    security_agents_active: int = 0
    security_agents_total: int = 0


# ── Pagination ────────────────────────────────────────────────────────────────

class PaginatedResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: list


# ── Device extras ─────────────────────────────────────────────────────────────

class DeviceTrustUpdate(BaseModel):
    is_trusted: bool


# ── Stats / Dashboard ─────────────────────────────────────────────────────────

class DashboardStats(BaseModel):
    total_devices: int
    total_threats: int
    active_firewall_rules: int
    total_honeypot_sessions: int
    unacknowledged_threats: int
    high_risk_threats: int  # risk_score >= 0.9


class ThreatTypeCount(BaseModel):
    threat_type: str
    count: int


class ThreatActionCount(BaseModel):
    action_taken: Optional[str]
    count: int


class ThreatStats(BaseModel):
    by_type: list[ThreatTypeCount]
    by_action: list[ThreatActionCount]
    total: int
