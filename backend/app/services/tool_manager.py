"""Tool Manager — persist installation probes to ``tool_installations``."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import ToolInstallation
from app.scanners.base import InstallationStatus, ScannerAdapter
from app.scanners.registry import ScannerRegistry, get_registry
from app.services.audit import record_audit


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def probe_adapter(adapter: ScannerAdapter) -> dict[str, Any]:
    info = await adapter.check_installation()
    version = info.version
    if info.status is InstallationStatus.installed and version in (None, "unknown"):
        version = await adapter.get_version()
    return {
        "scanner_id": adapter.scanner_id,
        "display_name": adapter.display_name,
        "description": adapter.description,
        "capabilities": sorted(c.value for c in adapter.capabilities),
        "preferred_runtime": adapter.preferred_runtime.value,
        "is_active": adapter.is_active,
        "is_test_only": adapter.is_test_only,
        "integration_phase": adapter.integration_phase,
        "status": info.status.value,
        "version": version,
        "path_or_runtime": info.path_or_runtime,
        "message": info.message,
        "binary_path": info.binary_path,
        "meta": info.meta,
    }


def upsert_installation(
    db: Session,
    *,
    scanner_id: str,
    status: str,
    version: str | None,
    path_or_runtime: str,
    meta: dict[str, Any] | None = None,
) -> ToolInstallation:
    row = db.query(ToolInstallation).filter(ToolInstallation.scanner_id == scanner_id).one_or_none()
    if row is None:
        row = ToolInstallation(scanner_id=scanner_id)
        db.add(row)
    row.status = status
    row.version = version
    row.path_or_runtime = path_or_runtime
    row.meta_json = meta or {}
    row.checked_at = _utcnow()
    return row


async def refresh_installations(
    db: Session,
    *,
    registry: ScannerRegistry | None = None,
    include_test_only: bool = False,
) -> list[ToolInstallation]:
    reg = registry or get_registry()
    adapters = reg.list(include_test_only=include_test_only)
    rows: list[ToolInstallation] = []
    for adapter in adapters:
        probed = await probe_adapter(adapter)
        meta = {
            "display_name": probed["display_name"],
            "message": probed["message"],
            "binary_path": probed["binary_path"],
            "capabilities": probed["capabilities"],
            "is_active": probed["is_active"],
            "is_test_only": probed["is_test_only"],
            "integration_phase": probed["integration_phase"],
            **(probed.get("meta") or {}),
        }
        row = upsert_installation(
            db,
            scanner_id=probed["scanner_id"],
            status=probed["status"],
            version=probed["version"],
            path_or_runtime=probed["path_or_runtime"],
            meta=meta,
        )
        rows.append(row)
    record_audit(
        db,
        action="tools.refresh",
        detail={"count": len(rows), "include_test_only": include_test_only},
    )
    db.commit()
    for row in rows:
        db.refresh(row)
    return rows


def list_installations(db: Session) -> list[ToolInstallation]:
    return (
        db.query(ToolInstallation)
        .order_by(ToolInstallation.scanner_id.asc())
        .all()
    )


def get_installation(db: Session, scanner_id: str) -> ToolInstallation | None:
    return (
        db.query(ToolInstallation)
        .filter(ToolInstallation.scanner_id == scanner_id)
        .one_or_none()
    )


async def list_tools_live(
    db: Session,
    *,
    registry: ScannerRegistry | None = None,
    include_test_only: bool = False,
    persist: bool = False,
) -> list[dict[str, Any]]:
    """
    Live probe of registry adapters.

    When ``persist`` is True, also upsert ``tool_installations``.
    """
    reg = registry or get_registry()
    out: list[dict[str, Any]] = []
    for adapter in reg.list(include_test_only=include_test_only):
        probed = await probe_adapter(adapter)
        row = get_installation(db, adapter.scanner_id)
        probed["checked_at"] = row.checked_at.isoformat() if row and row.checked_at else None
        probed["persisted"] = row is not None
        if persist:
            upsert_installation(
                db,
                scanner_id=probed["scanner_id"],
                status=probed["status"],
                version=probed["version"],
                path_or_runtime=probed["path_or_runtime"],
                meta={
                    "display_name": probed["display_name"],
                    "message": probed["message"],
                    "binary_path": probed["binary_path"],
                    "capabilities": probed["capabilities"],
                    "is_active": probed["is_active"],
                    "is_test_only": probed["is_test_only"],
                    "integration_phase": probed["integration_phase"],
                    **(probed.get("meta") or {}),
                },
            )
        out.append(probed)
    if persist:
        record_audit(db, action="tools.refresh", detail={"count": len(out)})
        db.commit()
    return out
