"""Asset inventory helpers — real DB rows only."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Asset
from app.services.projects import get_project


def list_assets(db: Session, project_id: str) -> list[Asset]:
    get_project(db, project_id)
    return list(
        db.scalars(
            select(Asset)
            .where(Asset.project_id == project_id)
            .order_by(Asset.created_at.desc())
        ).all()
    )


def upsert_asset_from_scope(
    db: Session,
    *,
    project_id: str,
    asset_type: str,
    identifier: str,
) -> Asset:
    """Create or refresh an asset row when scope is added (no fake data)."""
    ident = identifier.strip()[:512]
    atype = (asset_type or "unknown")[:64]
    row = (
        db.query(Asset)
        .filter(
            Asset.project_id == project_id,
            Asset.type == atype,
            Asset.identifier == ident,
        )
        .one_or_none()
    )
    now = datetime.now(timezone.utc)
    if row is None:
        row = Asset(
            project_id=project_id,
            type=atype,
            identifier=ident,
            last_seen_at=now,
            labels_json={"source": "scope"},
        )
        db.add(row)
        db.flush()
    else:
        row.last_seen_at = now
    return row
