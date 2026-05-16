"""Add packet inspection detail columns.

Revision ID: 003_packet_inspection_details
Revises: 002_honeypot_flow_context
Create Date: 2026-05-16
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "003_packet_inspection_details"
down_revision = "002_honeypot_flow_context"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for column in (
        sa.Column("payload_len", sa.Integer(), nullable=True),
        sa.Column("direction", sa.String(length=16), nullable=True),
        sa.Column("src_mac", sa.String(length=17), nullable=True),
        sa.Column("dst_mac", sa.String(length=17), nullable=True),
        sa.Column("ip_version", sa.Integer(), nullable=True),
        sa.Column("ip_ttl", sa.Integer(), nullable=True),
        sa.Column("ip_tos", sa.Integer(), nullable=True),
        sa.Column("ip_id", sa.Integer(), nullable=True),
        sa.Column("ip_flags", sa.String(length=16), nullable=True),
        sa.Column("frag_offset", sa.Integer(), nullable=True),
        sa.Column("tcp_seq", sa.Integer(), nullable=True),
        sa.Column("tcp_ack", sa.Integer(), nullable=True),
        sa.Column("tcp_window", sa.Integer(), nullable=True),
        sa.Column("tcp_options", sa.Text(), nullable=True),
        sa.Column("udp_len", sa.Integer(), nullable=True),
        sa.Column("icmp_type", sa.Integer(), nullable=True),
        sa.Column("icmp_code", sa.Integer(), nullable=True),
        sa.Column("payload_preview", sa.Text(), nullable=True),
    ):
        op.add_column("captured_packets", column)


def downgrade() -> None:
    for name in (
        "payload_preview",
        "icmp_code",
        "icmp_type",
        "udp_len",
        "tcp_options",
        "tcp_window",
        "tcp_ack",
        "tcp_seq",
        "frag_offset",
        "ip_flags",
        "ip_id",
        "ip_tos",
        "ip_ttl",
        "ip_version",
        "dst_mac",
        "src_mac",
        "direction",
        "payload_len",
    ):
        op.drop_column("captured_packets", name)
