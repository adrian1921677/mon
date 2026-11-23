"""Process Manager — safe subprocess orchestration (no shell=True)."""

from app.process.manager import (
    CommandSpec,
    ManagedProcess,
    ProcessManager,
    ProcessResult,
    ProcessStatus,
)
from app.process.recovery import mark_interrupted_tasks

__all__ = [
    "CommandSpec",
    "ManagedProcess",
    "ProcessManager",
    "ProcessResult",
    "ProcessStatus",
    "mark_interrupted_tasks",
]
