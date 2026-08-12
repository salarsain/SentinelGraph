"""Initial migration — users, authorized_scopes, scope_validations

Revision ID: 001_initial
Revises: None
Create Date: 2024-01-01
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID

revision: str = "001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── Enable extensions ────────────────────────────────
    op.execute("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"")
    op.execute("CREATE EXTENSION IF NOT EXISTS \"pgcrypto\"")

    # ── Users table ──────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("email", sa.String(320), nullable=False, unique=True, index=True),
        sa.Column("hashed_password", sa.String(512), nullable=False),
        sa.Column("full_name", sa.String(255), nullable=False),
        sa.Column("role", sa.Enum("admin", "analyst", "viewer", name="user_role"), nullable=False, server_default="analyst"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("is_verified", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("bio", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    # ── Authorized Scopes table ──────────────────────────
    op.create_table(
        "authorized_scopes",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("owner_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("scope_type", sa.Enum("domain", "wildcard", "ip_range", "url_prefix", name="scope_type"), nullable=False),
        sa.Column("target", sa.String(512), nullable=False, index=True),
        sa.Column("include_subdomains", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("status", sa.Enum("pending", "active", "suspended", "revoked", name="scope_status"), nullable=False, server_default="pending", index=True),
        sa.Column("ip_allowlist", ARRAY(sa.String), nullable=True),
        sa.Column("ip_blocklist", ARRAY(sa.String), nullable=True),
        sa.Column("excluded_paths", ARRAY(sa.String), nullable=True),
        sa.Column("max_requests_per_second", sa.Integer, nullable=False, server_default=sa.text("10")),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("config", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    # ── Scope Validations table ──────────────────────────
    op.create_table(
        "scope_validations",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("scope_id", UUID(as_uuid=True), sa.ForeignKey("authorized_scopes.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("method", sa.Enum("dns_txt", "meta_tag", "file_upload", "manual", "self_hosted", name="validation_method"), nullable=False),
        sa.Column("is_valid", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("validation_token", sa.String(512), nullable=True),
        sa.Column("details", JSONB, nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("scope_validations")
    op.drop_table("authorized_scopes")
    op.drop_table("users")
    op.execute("DROP TYPE IF EXISTS validation_method")
    op.execute("DROP TYPE IF EXISTS scope_status")
    op.execute("DROP TYPE IF EXISTS scope_type")
    op.execute("DROP TYPE IF EXISTS user_role")
