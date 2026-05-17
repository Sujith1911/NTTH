"""add TLS and flow packet detail fields

Revision ID: 005_tls_flow_packet_details
Revises: 004_http_packet_details
Create Date: 2026-05-16
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "005_tls_flow_packet_details"
down_revision = "004_http_packet_details"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("captured_packets", sa.Column("tls_sni", sa.String(length=255), nullable=True))
    op.add_column("captured_packets", sa.Column("tls_alpn", sa.Text(), nullable=True))
    op.add_column("captured_packets", sa.Column("tls_version", sa.String(length=16), nullable=True))
    op.add_column("captured_packets", sa.Column("tls_record_type", sa.Integer(), nullable=True))
    op.add_column("captured_packets", sa.Column("quic_hint", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("captured_packets", sa.Column("flow_id", sa.String(length=255), nullable=True))
    op.create_index("ix_captured_packets_flow_id", "captured_packets", ["flow_id"])
    op.create_index("ix_captured_packets_ports", "captured_packets", ["src_port", "dst_port"])
    op.create_index("ix_captured_packets_tls_sni", "captured_packets", ["tls_sni"])


def downgrade() -> None:
    op.drop_index("ix_captured_packets_tls_sni", table_name="captured_packets")
    op.drop_index("ix_captured_packets_ports", table_name="captured_packets")
    op.drop_index("ix_captured_packets_flow_id", table_name="captured_packets")
    op.drop_column("captured_packets", "flow_id")
    op.drop_column("captured_packets", "quic_hint")
    op.drop_column("captured_packets", "tls_record_type")
    op.drop_column("captured_packets", "tls_version")
    op.drop_column("captured_packets", "tls_alpn")
    op.drop_column("captured_packets", "tls_sni")
