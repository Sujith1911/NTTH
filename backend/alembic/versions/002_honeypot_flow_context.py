"""Add victim-aware redirect and honeypot session context.

Revision ID: 002_honeypot_flow_context
Revises: 001_initial
Create Date: 2026-03-23
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "002_honeypot_flow_context"
down_revision = "001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("honeypot_sessions", sa.Column("observed_attacker_ip", sa.String(length=45), nullable=True))
    op.add_column("honeypot_sessions", sa.Column("victim_ip", sa.String(length=45), nullable=True))
    op.add_column("honeypot_sessions", sa.Column("victim_port", sa.Integer(), nullable=True))
    op.add_column(
        "honeypot_sessions",
        sa.Column("source_masked", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("honeypot_sessions", sa.Column("source_mask_reason", sa.Text(), nullable=True))
    op.create_index("ix_honeypot_sessions_victim_ip", "honeypot_sessions", ["victim_ip"], unique=False)

    op.add_column("firewall_rules", sa.Column("match_dst_ip", sa.String(length=45), nullable=True))
    op.add_column("firewall_rules", sa.Column("match_dst_port", sa.Integer(), nullable=True))
    op.create_index("ix_firewall_rules_match_dst_ip", "firewall_rules", ["match_dst_ip"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_firewall_rules_match_dst_ip", table_name="firewall_rules")
    op.drop_column("firewall_rules", "match_dst_port")
    op.drop_column("firewall_rules", "match_dst_ip")

    op.drop_index("ix_honeypot_sessions_victim_ip", table_name="honeypot_sessions")
    op.drop_column("honeypot_sessions", "source_mask_reason")
    op.drop_column("honeypot_sessions", "source_masked")
    op.drop_column("honeypot_sessions", "victim_port")
    op.drop_column("honeypot_sessions", "victim_ip")
    op.drop_column("honeypot_sessions", "observed_attacker_ip")
