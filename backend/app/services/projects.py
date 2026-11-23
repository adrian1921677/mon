"""Project CRUD service."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.schemas import ProjectCreate, ProjectUpdate
from app.db.models import Project
from app.services.audit import record_audit


class ProjectNotFoundError(LookupError):
    pass


def list_projects(db: Session) -> list[Project]:
    return list(db.scalars(select(Project).order_by(Project.created_at.desc())).all())


def get_project(db: Session, project_id: str) -> Project:
    project = db.get(Project, project_id)
    if project is None:
        raise ProjectNotFoundError(project_id)
    return project


def create_project(db: Session, payload: ProjectCreate) -> Project:
    project = Project(name=payload.name.strip(), description=payload.description)
    db.add(project)
    db.flush()
    record_audit(
        db,
        action="project.created",
        project_id=project.id,
        detail={"name": project.name},
    )
    db.commit()
    db.refresh(project)
    return project


def update_project(db: Session, project_id: str, payload: ProjectUpdate) -> Project:
    project = get_project(db, project_id)
    data = payload.model_dump(exclude_unset=True)
    if "name" in data and data["name"] is not None:
        project.name = data["name"].strip()
    if "description" in data:
        project.description = data["description"]
    record_audit(
        db,
        action="project.updated",
        project_id=project.id,
        detail=data,
    )
    db.commit()
    db.refresh(project)
    return project


def delete_project(db: Session, project_id: str) -> None:
    project = get_project(db, project_id)
    name = project.name
    record_audit(
        db,
        action="project.deleted",
        project_id=project.id,
        detail={"name": name},
    )
    db.delete(project)
    db.commit()
