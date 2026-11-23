"""Scope Engine — backend-only target validation (DNS/SSRF/rebinding)."""

from app.scope.engine import ScopeEngine, ScopeValidationError
from app.scope.types import ScopeTarget, ValidationResult

__all__ = [
    "ScopeEngine",
    "ScopeTarget",
    "ScopeValidationError",
    "ValidationResult",
]
