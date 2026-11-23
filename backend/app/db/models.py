"""ORM models for Phase 1 (+ scaffolding tables for later phases)."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    JSON,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class ScopeEntryType(str, enum.Enum):
    ip = "ip"
    cidr = "cidr"
    domain = "domain"
    url = "url"
    api_spec = "api_spec"
    path = "path"


class ScopeEntryStatus(str, enum.Enum):
    pending = "pending"
    verified = "verified"
    rejected = "rejected"


class ScanDepth(str, enum.Enum):
    quick = "quick"
    standard = "standard"
    deep = "deep"


class ScanStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"
    interrupted = "interrupted"


class FindingSeverity(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class FindingStatus(str, enum.Enum):
    open = "open"
    fixed = "fixed"
    false_positive = "false_positive"


class FindingConfidence(str, enum.Enum):
    unknown = "unknown"
    low = "low"
    medium = "medium"
    high = "high"


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    scope_entries: Mapped[list[ScopeEntry]] = relationship(back_populates="project")
    assets: Mapped[list[Asset]] = relationship(back_populates="project")
    scan_profiles: Mapped[list[ScanProfile]] = relationship(back_populates="project")
    scans: Mapped[list[Scan]] = relationship(back_populates="project")
    findings: Mapped[list[Finding]] = relationship(back_populates="project")
    credentials_refs: Mapped[list[CredentialsRef]] = relationship(back_populates="project")
    audit_events: Mapped[list[AuditEvent]] = relationship(back_populates="project")


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(255), primary_key=True)
    value_json: Mapped[Any] = mapped_column(JSON, nullable=False, default=dict)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    project_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    actor: Mapped[str] = mapped_column(String(128), nullable=False, default="local")
    detail_json: Mapped[Any] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    project: Mapped[Optional[Project]] = relationship(back_populates="audit_events")

    __table_args__ = (Index("ix_audit_events_project_created", "project_id", "created_at"),)


class ScopeEntry(Base):
    __tablename__ = "scope_entries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    type: Mapped[ScopeEntryType] = mapped_column(
        Enum(ScopeEntryType, name="scope_entry_type"), nullable=False
    )
    value: Mapped[str] = mapped_column(Text, nullable=False)
    meta_json: Mapped[Any] = mapped_column(JSON, nullable=False, default=dict)
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    status: Mapped[ScopeEntryStatus] = mapped_column(
        Enum(ScopeEntryStatus, name="scope_entry_status"),
        nullable=False,
        default=ScopeEntryStatus.pending,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    project: Mapped[Project] = relationship(back_populates="scope_entries")


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    type: Mapped[str] = mapped_column(String(64), nullable=False)
    identifier: Mapped[str] = mapped_column(String(512), nullable=False)
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    labels_json: Mapped[Any] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    project: Mapped[Project] = relationship(back_populates="assets")

    __table_args__ = (
        UniqueConstraint("project_id", "type", "identifier", name="uq_assets_project_type_id"),
    )


class ScanProfile(Base):
    __tablename__ = "scan_profiles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    project_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    depth: Mapped[ScanDepth] = mapped_column(
        Enum(ScanDepth, name="scan_depth"), nullable=False, default=ScanDepth.standard
    )
    tool_set_json: Mapped[Any] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    project: Mapped[Optional[Project]] = relationship(back_populates="scan_profiles")
    scans: Mapped[list[Scan]] = relationship(back_populates="profile")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    profile_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("scan_profiles.id", ondelete="SET NULL"), nullable=True
    )
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status"), nullable=False, default=ScanStatus.pending
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    scope_snapshot_json: Mapped[Any] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    project: Mapped[Project] = relationship(back_populates="scans")
    profile: Mapped[Optional[ScanProfile]] = relationship(back_populates="scans")
    tasks: Mapped[list[ScanTask]] = relationship(back_populates="scan")


class ScanTask(Base):
    __tablename__ = "scan_tasks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    scanner_id: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_task_status", create_constraint=False),
        nullable=False,
        default=ScanStatus.pending,
    )
    pid: Mapped[Optional[int]] = mapped_column(nullable=True)
    handle_ref: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    exit_code: Mapped[Optional[int]] = mapped_column(nullable=True)
    log_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    scan: Mapped[Scan] = relationship(back_populates="tasks")


class ToolInstallation(Base):
    __tablename__ = "tool_installations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scanner_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    version: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    path_or_runtime: Mapped[str] = mapped_column(String(64), nullable=False, default="native")
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    meta_json: Mapped[Any] = mapped_column(JSON, nullable=False, default=dict)
    checked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    severity: Mapped[FindingSeverity] = mapped_column(
        Enum(FindingSeverity, name="finding_severity"), nullable=False
    )
    category: Mapped[str] = mapped_column(String(128), nullable=False)
    scanner_id: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus, name="finding_status"),
        nullable=False,
        default=FindingStatus.open,
    )
    confidence: Mapped[FindingConfidence] = mapped_column(
        Enum(FindingConfidence, name="finding_confidence"),
        nullable=False,
        default=FindingConfidence.unknown,
    )
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    project: Mapped[Project] = relationship(back_populates="findings")
    occurrences: Mapped[list[FindingOccurrence]] = relationship(back_populates="finding")
    evidence: Mapped[list[Evidence]] = relationship(back_populates="finding")

    __table_args__ = (
        UniqueConstraint("project_id", "fingerprint", name="uq_findings_project_fingerprint"),
        Index("ix_findings_project_status_severity", "project_id", "status", "severity"),
    )


class FindingOccurrence(Base):
    __tablename__ = "finding_occurrences"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    asset_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    raw_ref: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    finding: Mapped[Finding] = relationship(back_populates="occurrences")


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    path_or_blob_ref: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    finding: Mapped[Finding] = relationship(back_populates="evidence")


class CredentialsRef(Base):
    """Encrypted credential reference only — never store plaintext."""

    __tablename__ = "credentials_refs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    vault_blob: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    project: Mapped[Project] = relationship(back_populates="credentials_refs")
