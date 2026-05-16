"""add HTTP packet detail fields

Revision ID: 004_http_packet_details
Revises: 003_packet_inspection_details
Create Date: 2026-05-16
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "004_http_packet_details"
down_revision = "003_packet_inspection_details"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("captured_packets", sa.Column("payload_text", sa.Text(), nullable=True))
    op.add_column("captured_packets", sa.Column("http_method", sa.String(length=12), nullable=True))
    op.add_column("captured_packets", sa.Column("http_host", sa.String(length=255), nullable=True))
    op.add_column("captured_packets", sa.Column("http_path", sa.Text(), nullable=True))
    op.add_column("captured_packets", sa.Column("http_user_agent", sa.Text(), nullable=True))
    op.add_column("captured_packets", sa.Column("http_content_type", sa.String(length=255), nullable=True))
    op.add_column("captured_packets", sa.Column("http_body_preview", sa.Text(), nullable=True))
    op.add_column("captured_packets", sa.Column("http_form_fields", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("captured_packets", "http_form_fields")
    op.drop_column("captured_packets", "http_body_preview")
    op.drop_column("captured_packets", "http_content_type")
    op.drop_column("captured_packets", "http_user_agent")
    op.drop_column("captured_packets", "http_path")
    op.drop_column("captured_packets", "http_host")
    op.drop_column("captured_packets", "http_method")
    op.drop_column("captured_packets", "payload_text")
