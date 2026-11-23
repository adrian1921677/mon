"""Dashboard API — aggregates from real project data."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.schemas import DashboardRead
from app.db.session import get_db
from app.services.dashboard_service import build_dashboard
from app.services.projects import ProjectNotFoundError

router = APIRouter(tags=["dashboard"])


@router.get("/projects/{project_id}/dashboard", response_model=DashboardRead)
def get_dashboard(project_id: str, db: Session = Depends(get_db)) -> DashboardRead:
    try:
        data = build_dashboard(db, project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found") from exc
    return DashboardRead.model_validate(data)
