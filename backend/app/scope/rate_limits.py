"""Rate-limit and time-budget hooks for scope-gated work."""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock

from app.scope.types import ValidationReason, ValidationResult

# Setting keys (JSON values stored in `settings` table).
SETTING_RATE_LIMITS = "scope.rate_limits"
SETTING_TIME_LIMITS = "scope.time_limits"

DEFAULT_RATE_LIMITS: dict[str, int] = {
    "validations_per_minute": 120,
    "active_checks_per_hour": 30,
}

DEFAULT_TIME_LIMITS: dict[str, int] = {
    "dns_timeout_seconds": 5,
    "connect_timeout_seconds": 10,
    "scan_wall_clock_seconds": 3600,
}


@dataclass
class RateLimitState:
    """In-memory sliding windows (per process). Persisted settings control caps."""

    _events: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))
    _lock: Lock = field(default_factory=Lock)

    def check(
        self,
        key: str,
        *,
        limit: int,
        window_seconds: float,
    ) -> ValidationResult:
        now = time.monotonic()
        with self._lock:
            bucket = self._events[key]
            cutoff = now - window_seconds
            self._events[key] = [t for t in bucket if t >= cutoff]
            if len(self._events[key]) >= limit:
                return ValidationResult.deny(
                    ValidationReason.rate_limited,
                    f"rate limit exceeded for {key} ({limit}/{int(window_seconds)}s)",
                    meta={"key": key, "limit": limit, "window_seconds": window_seconds},
                )
            self._events[key].append(now)
        return ValidationResult.ok(message="rate ok", meta={"key": key})

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._events.clear()
            else:
                self._events.pop(key, None)


_global_rate_state = RateLimitState()


def get_rate_state() -> RateLimitState:
    return _global_rate_state


@dataclass(frozen=True)
class TimeBudget:
    started_at: float
    max_seconds: float

    @classmethod
    def start(cls, max_seconds: float) -> TimeBudget:
        return cls(started_at=time.monotonic(), max_seconds=max_seconds)

    def remaining(self) -> float:
        return max(0.0, self.max_seconds - (time.monotonic() - self.started_at))

    def check(self) -> ValidationResult:
        if self.remaining() <= 0:
            return ValidationResult.deny(
                ValidationReason.time_budget_exceeded,
                f"time budget of {self.max_seconds:.0f}s exceeded",
            )
        return ValidationResult.ok(
            message="within time budget",
            meta={"remaining_seconds": self.remaining()},
        )
