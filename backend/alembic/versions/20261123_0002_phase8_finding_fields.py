"""Phase 8: finding status, confidence, remediation, description.

Revision ID: 20261123_0002
Revises: 20261123_0001
Create Date: 2026-11-23

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20261123_0002"
down_revision: Union[str, None] = "20261123_0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("findings") as batch:
        batch.add_column(
            sa.Column(
                "status",
                sa.Enum("open", "fixed", "false_positive", name="finding_status"),
                nullable=False,
                server_default="open",
            )
        )
        batch.add_column(
            sa.Column(
                "confidence",
                sa.Enum("unknown", "low", "medium", "high", name="finding_confidence"),
                nullable=False,
                server_default="unknown",
            )
        )
        batch.add_column(sa.Column("remediation", sa.Text(), nullable=True))
        batch.add_column(sa.Column("description", sa.Text(), nullable=True))
        batch.create_index(
            "ix_findings_project_status_severity",
            ["project_id", "status", "severity"],
        )


def downgrade() -> None:
    with op.batch_alter_table("findings") as batch:
        batch.drop_index("ix_findings_project_status_severity")
        batch.drop_column("description")
        batch.drop_column("remediation")
        batch.drop_column("confidence")
        batch.drop_column("status")
    op.execute("DROP TYPE IF EXISTS finding_status")
    op.execute("DROP TYPE IF EXISTS finding_confidence")
