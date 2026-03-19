"""Initial schema — creates all NTTH tables.

Revision ID: 001_initial
Revises: 
Create Date: 2026-03-19
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

# Alembic metadata
revision = "001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── users ──────────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("username", sa.String(64), nullable=False, unique=True),
        sa.Column("hashed_password", sa.String(128), nullable=False),
        sa.Column("role", sa.String(16), nullable=False, server_default="user"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("last_login", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_users_username", "users", ["username"], unique=True)

    # ── devices ────────────────────────────────────────────────────────────────
    op.create_table(
        "devices",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("ip_address", sa.String(45), nullable=False, unique=True),
        sa.Column("mac_address", sa.String(17), nullable=True),
        sa.Column("hostname", sa.String(128), nullable=True),
        sa.Column("vendor", sa.String(128), nullable=True),
        sa.Column("first_seen", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("is_trusted", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0.0"),
    )
    op.create_index("ix_devices_ip_address", "devices", ["ip_address"], unique=True)

    # ── device_stats ───────────────────────────────────────────────────────────
    op.create_table(
        "device_stats",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("device_id", sa.String(36), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("recorded_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("packet_count", sa.Integer(), server_default="0"),
        sa.Column("byte_count", sa.Integer(), server_default="0"),
        sa.Column("unique_ports", sa.Integer(), server_default="0"),
        sa.Column("syn_count", sa.Integer(), server_default="0"),
        sa.Column("protocol", sa.String(8), nullable=True),
    )

    # ── threat_events ──────────────────────────────────────────────────────────
    op.create_table(
        "threat_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("device_id", sa.String(36), sa.ForeignKey("devices.id", ondelete="SET NULL"), nullable=True),
        sa.Column("src_ip", sa.String(45), nullable=False),
        sa.Column("dst_ip", sa.String(45), nullable=True),
        sa.Column("dst_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(8), nullable=True),
        sa.Column("threat_type", sa.String(64), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("rule_score", sa.Float(), nullable=True),
        sa.Column("ml_score", sa.Float(), nullable=True),
        sa.Column("action_taken", sa.String(32), nullable=True),
        sa.Column("country", sa.String(64), nullable=True),
        sa.Column("city", sa.String(64), nullable=True),
        sa.Column("asn", sa.String(64), nullable=True),
        sa.Column("org", sa.String(128), nullable=True),
        sa.Column("latitude", sa.Float(), nullable=True),
        sa.Column("longitude", sa.Float(), nullable=True),
        sa.Column("detected_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("acknowledged", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("acknowledged_by", sa.String(64), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
    )
    op.create_index("ix_threat_events_src_ip", "threat_events", ["src_ip"])
    op.create_index("ix_threat_events_detected_at", "threat_events", ["detected_at"])

    # ── honeypot_sessions ──────────────────────────────────────────────────────
    op.create_table(
        "honeypot_sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("session_id", sa.String(64), nullable=False, unique=True),
        sa.Column("attacker_ip", sa.String(45), nullable=False),
        sa.Column("attacker_port", sa.Integer(), nullable=True),
        sa.Column("honeypot_type", sa.String(16), nullable=False),
        sa.Column("username_tried", sa.String(128), nullable=True),
        sa.Column("password_tried", sa.String(256), nullable=True),
        sa.Column("commands_run", sa.Text(), nullable=True),
        sa.Column("duration_seconds", sa.Float(), nullable=True),
        sa.Column("country", sa.String(64), nullable=True),
        sa.Column("city", sa.String(64), nullable=True),
        sa.Column("asn", sa.String(64), nullable=True),
        sa.Column("org", sa.String(128), nullable=True),
        sa.Column("latitude", sa.Float(), nullable=True),
        sa.Column("longitude", sa.Float(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("ended_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_honeypot_sessions_session_id", "honeypot_sessions", ["session_id"], unique=True)
    op.create_index("ix_honeypot_sessions_attacker_ip", "honeypot_sessions", ["attacker_ip"])
    op.create_index("ix_honeypot_sessions_started_at", "honeypot_sessions", ["started_at"])

    # ── firewall_rules ─────────────────────────────────────────────────────────
    op.create_table(
        "firewall_rules",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("rule_type", sa.String(32), nullable=False),
        sa.Column("target_ip", sa.String(45), nullable=False),
        sa.Column("target_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(8), nullable=True),
        sa.Column("nft_handle", sa.String(64), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("created_by", sa.String(64), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("removed_at", sa.DateTime(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
    )
    op.create_index("ix_firewall_rules_target_ip", "firewall_rules", ["target_ip"])

    # ── system_logs ────────────────────────────────────────────────────────────
    op.create_table(
        "system_logs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("level", sa.String(16), nullable=False),
        sa.Column("component", sa.String(64), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("extra", sa.Text(), nullable=True),
        sa.Column("logged_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_system_logs_logged_at", "system_logs", ["logged_at"])


def downgrade() -> None:
    op.drop_table("system_logs")
    op.drop_table("firewall_rules")
    op.drop_table("honeypot_sessions")
    op.drop_table("threat_events")
    op.drop_table("device_stats")
    op.drop_table("devices")
    op.drop_table("users")
