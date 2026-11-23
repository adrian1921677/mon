"""Explicit approval gate for active checks (backend-enforced)."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.db.models import Setting
from app.scope.types import ValidationReason, ValidationResult

SETTING_ACTIVE_TESTS = "security.active_tests_enabled"
SETTING_DEEP_PROFILE = "security.deep_profile_enabled"


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, dict):
        return bool(value.get("enabled", False))
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return False


def is_active_tests_enabled(db: Session | None = None, settings_map: dict[str, Any] | None = None) -> bool:
    if settings_map is not None:
        return _truthy(settings_map.get(SETTING_ACTIVE_TESTS, False))
    if db is None:
        return False
    row = db.get(Setting, SETTING_ACTIVE_TESTS)
    if row is None:
        return False
    return _truthy(row.value_json)


def require_active_tests(
    db: Session | None = None,
    *,
    settings_map: dict[str, Any] | None = None,
) -> ValidationResult:
    if is_active_tests_enabled(db, settings_map):
        return ValidationResult.ok(message="active tests enabled")
    return ValidationResult.deny(
        ValidationReason.active_tests_disabled,
        "active checks require explicit setting security.active_tests_enabled=true",
    )


def is_deep_profile_enabled(db: Session | None = None, settings_map: dict[str, Any] | None = None) -> bool:
    if settings_map is not None:
        return _truthy(settings_map.get(SETTING_DEEP_PROFILE, False))
    if db is None:
        return False
    row = db.get(Setting, SETTING_DEEP_PROFILE)
    if row is None:
        return False
    return _truthy(row.value_json)
