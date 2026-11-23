"""Scope entries REST API + dry-run validation."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.schemas import (
    ScopeEntryCreate,
    ScopeEntryRead,
    ScopeEntryUpdate,
    ScopeValidateRequest,
    ScopeValidateResponse,
)
from app.db.session import get_db
from app.services import scope_service
from app.services.projects import ProjectNotFoundError

router = APIRouter(tags=["scope"])


def _http_for_scope_error(exc: Exception) -> HTTPException:
    if isinstance(exc, ProjectNotFoundError):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    if isinstance(exc, scope_service.ScopeEntryNotFoundError):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scope entry not found")
    if isinstance(exc, scope_service.ScopeRejectedError):
        r = exc.result
        # 422: validation rejected by Scope Engine (not a schema error).
        code = getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", None) or status.HTTP_422_UNPROCESSABLE_ENTITY
        return HTTPException(
            status_code=code,
            detail={
                "allowed": False,
                "reason": r.reason.value,
                "message": r.message,
                "resolved_ips": list(r.resolved_ips),
                "meta": r.meta,
            },
        )
    raise exc


@router.get("/projects/{project_id}/scope", response_model=list[ScopeEntryRead])
def list_scope(project_id: str, db: Session = Depends(get_db)) -> list[ScopeEntryRead]:
    try:
        entries = scope_service.list_scope_entries(db, project_id)
    except ProjectNotFoundError as exc:
        raise _http_for_scope_error(exc) from exc
    return [ScopeEntryRead.model_validate(e) for e in entries]


@router.post(
    "/projects/{project_id}/scope",
    response_model=ScopeEntryRead,
    status_code=status.HTTP_201_CREATED,
)
def create_scope(
    project_id: str,
    payload: ScopeEntryCreate,
    db: Session = Depends(get_db),
) -> ScopeEntryRead:
    try:
        entry = scope_service.create_scope_entry(db, project_id, payload)
    except (ProjectNotFoundError, scope_service.ScopeRejectedError) as exc:
        raise _http_for_scope_error(exc) from exc
    return ScopeEntryRead.model_validate(entry)


# Static path before {entry_id} so "validate" is never captured as an id.
@router.post(
    "/projects/{project_id}/scope/validate",
    response_model=ScopeValidateResponse,
)
def validate_scope(
    project_id: str,
    payload: ScopeValidateRequest,
    db: Session = Depends(get_db),
) -> ScopeValidateResponse:
    try:
        result = scope_service.validate_dry_run(db, project_id, payload)
    except ProjectNotFoundError as exc:
        raise _http_for_scope_error(exc) from exc
    return ScopeValidateResponse(**result)


@router.get("/projects/{project_id}/scope/{entry_id}", response_model=ScopeEntryRead)
def get_scope(project_id: str, entry_id: str, db: Session = Depends(get_db)) -> ScopeEntryRead:
    try:
        entry = scope_service.get_scope_entry(db, project_id, entry_id)
    except (ProjectNotFoundError, scope_service.ScopeEntryNotFoundError) as exc:
        raise _http_for_scope_error(exc) from exc
    return ScopeEntryRead.model_validate(entry)


@router.patch("/projects/{project_id}/scope/{entry_id}", response_model=ScopeEntryRead)
def update_scope(
    project_id: str,
    entry_id: str,
    payload: ScopeEntryUpdate,
    db: Session = Depends(get_db),
) -> ScopeEntryRead:
    try:
        entry = scope_service.update_scope_entry(db, project_id, entry_id, payload)
    except (
        ProjectNotFoundError,
        scope_service.ScopeEntryNotFoundError,
        scope_service.ScopeRejectedError,
    ) as exc:
        raise _http_for_scope_error(exc) from exc
    return ScopeEntryRead.model_validate(entry)


@router.delete("/projects/{project_id}/scope/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scope(project_id: str, entry_id: str, db: Session = Depends(get_db)) -> None:
    try:
        scope_service.delete_scope_entry(db, project_id, entry_id)
    except (ProjectNotFoundError, scope_service.ScopeEntryNotFoundError) as exc:
        raise _http_for_scope_error(exc) from exc
