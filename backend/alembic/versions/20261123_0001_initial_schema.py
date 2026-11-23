"""Initial schema: projects, settings, audit_events + Phase-1 scaffolding tables.

Revision ID: 20261123_0001
Revises:
Create Date: 2026-11-23

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20261123_0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "projects",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "settings",
        sa.Column("key", sa.String(length=255), nullable=False),
        sa.Column("value_json", sa.JSON(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.PrimaryKeyConstraint("key"),
    )
    op.create_table(
        "tool_installations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("scanner_id", sa.String(length=128), nullable=False),
        sa.Column("version", sa.String(length=128), nullable=True),
        sa.Column("path_or_runtime", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("meta_json", sa.JSON(), nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scanner_id"),
    )
    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=True),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("actor", sa.String(length=128), nullable=False),
        sa.Column("detail_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_events_project_created", "audit_events", ["project_id", "created_at"])

    op.create_table(
        "scope_entries",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("type", sa.Enum("ip", "cidr", "domain", "url", "api_spec", "path", name="scope_entry_type"), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("meta_json", sa.JSON(), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.Enum("pending", "verified", "rejected", name="scope_entry_status"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "assets",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("type", sa.String(length=64), nullable=False),
        sa.Column("identifier", sa.String(length=512), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("labels_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "type", "identifier", name="uq_assets_project_type_id"),
    )
    op.create_table(
        "scan_profiles",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("depth", sa.Enum("quick", "standard", "deep", name="scan_depth"), nullable=False),
        sa.Column("tool_set_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "credentials_refs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("label", sa.String(length=255), nullable=False),
        sa.Column("vault_blob", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "scans",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("profile_id", sa.String(length=36), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "pending",
                "running",
                "completed",
                "failed",
                "cancelled",
                "interrupted",
                name="scan_status",
            ),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scope_snapshot_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.ForeignKeyConstraint(["profile_id"], ["scan_profiles.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("fingerprint", sa.String(length=128), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column(
            "severity",
            sa.Enum("info", "low", "medium", "high", "critical", name="finding_severity"),
            nullable=False,
        ),
        sa.Column("category", sa.String(length=128), nullable=False),
        sa.Column("scanner_id", sa.String(length=128), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "fingerprint", name="uq_findings_project_fingerprint"),
    )
    op.create_table(
        "scan_tasks",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("scanner_id", sa.String(length=128), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "pending",
                "running",
                "completed",
                "failed",
                "cancelled",
                "interrupted",
                name="scan_task_status",
            ),
            nullable=False,
        ),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.Column("handle_ref", sa.String(length=255), nullable=True),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("log_path", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "evidence",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("kind", sa.String(length=64), nullable=False),
        sa.Column("path_or_blob_ref", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "finding_occurrences",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=True),
        sa.Column("asset_id", sa.String(length=36), nullable=True),
        sa.Column("raw_ref", sa.Text(), nullable=True),
        sa.Column("seen_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("finding_occurrences")
    op.drop_table("evidence")
    op.drop_table("scan_tasks")
    op.drop_table("findings")
    op.drop_table("scans")
    op.drop_table("credentials_refs")
    op.drop_table("scan_profiles")
    op.drop_table("assets")
    op.drop_table("scope_entries")
    op.drop_index("ix_audit_events_project_created", table_name="audit_events")
    op.drop_table("audit_events")
    op.drop_table("tool_installations")
    op.drop_table("settings")
    op.drop_table("projects")
