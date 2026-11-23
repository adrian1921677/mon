"""Tool Manager API — list / refresh scanner installations."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.schemas import ToolInstallationRead, ToolLiveRead
from app.db.session import get_db
from app.scanners.registry import ScannerRegistryError, get_registry
from app.services import tool_manager

router = APIRouter(prefix="/tools", tags=["tools"])


@router.get("", response_model=list[ToolLiveRead])
async def list_tools(
    include_test_only: bool = Query(False),
    persist: bool = Query(False, description="Upsert probe results into tool_installations"),
    db: Session = Depends(get_db),
) -> list[ToolLiveRead]:
    rows = await tool_manager.list_tools_live(
        db,
        include_test_only=include_test_only,
        persist=persist,
    )
    return [ToolLiveRead.model_validate(r) for r in rows]


@router.post("/refresh", response_model=list[ToolInstallationRead])
async def refresh_tools(
    include_test_only: bool = Query(False),
    db: Session = Depends(get_db),
) -> list[ToolInstallationRead]:
    rows = await tool_manager.refresh_installations(db, include_test_only=include_test_only)
    return [ToolInstallationRead.model_validate(r) for r in rows]


@router.get("/installations", response_model=list[ToolInstallationRead])
def list_installations(db: Session = Depends(get_db)) -> list[ToolInstallationRead]:
    return [ToolInstallationRead.model_validate(r) for r in tool_manager.list_installations(db)]


@router.get("/{scanner_id}", response_model=ToolLiveRead)
async def get_tool(
    scanner_id: str,
    db: Session = Depends(get_db),
) -> ToolLiveRead:
    reg = get_registry()
    try:
        adapter = reg.get(scanner_id)
    except ScannerRegistryError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    if adapter.is_test_only:
        # Still allow lookup by id for diagnostics, but mark clearly.
        pass
    probed = await tool_manager.probe_adapter(adapter)
    row = tool_manager.get_installation(db, scanner_id)
    probed["checked_at"] = row.checked_at.isoformat() if row and row.checked_at else None
    probed["persisted"] = row is not None
    return ToolLiveRead.model_validate(probed)
