"""Asset inventory API — real DB rows only."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.schemas import AssetRead
from app.db.session import get_db
from app.services.assets_service import list_assets
from app.services.projects import ProjectNotFoundError

router = APIRouter(tags=["assets"])


@router.get("/projects/{project_id}/assets", response_model=list[AssetRead])
def list_project_assets(project_id: str, db: Session = Depends(get_db)) -> list[AssetRead]:
    try:
        rows = list_assets(db, project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found") from exc
    return [AssetRead.model_validate(r) for r in rows]
