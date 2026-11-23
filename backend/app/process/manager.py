"""Process Manager: spawn/cancel/timeout/concurrency — never shell=True."""

from __future__ import annotations

import asyncio
import os
import signal
import sys
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from app.process.sanitize import sanitize_arg_list, sanitize_env, sanitize_text


class ProcessStatus(str, Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"
    timed_out = "timed_out"
    interrupted = "interrupted"


@dataclass(frozen=True)
class CommandSpec:
    """Executable specification — argv list only, never a shell string."""

    argv: tuple[str, ...]
    cwd: str | None = None
    env: Mapping[str, str] | None = None
    timeout_seconds: float | None = None
    task_id: str | None = None
    scan_id: str | None = None
    sensitive_flags: tuple[str, ...] = ("--password", "--token", "--api-key", "-p")

    def __post_init__(self) -> None:
        if not self.argv:
            raise ValueError("CommandSpec.argv must not be empty")
        if not all(isinstance(a, str) for a in self.argv):
            raise TypeError("CommandSpec.argv must be a sequence of strings")
        # Reject accidental shell strings passed as a single blob with spaces
        # when someone wrongly does CommandSpec(argv=("cmd && other",)).
        # We still allow paths with spaces as a single argv element.


@dataclass
class ProcessResult:
    status: ProcessStatus
    exit_code: int | None
    stdout: str
    stderr: str
    duration_seconds: float
    pid: int | None = None
    handle_id: str | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status is ProcessStatus.completed and (self.exit_code or 0) == 0


@dataclass
class ManagedProcess:
    handle_id: str
    spec: CommandSpec
    status: ProcessStatus = ProcessStatus.pending
    pid: int | None = None
    started_at: float | None = None
    finished_at: float | None = None
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    error: str | None = None
    _proc: asyncio.subprocess.Process | None = field(default=None, repr=False)
    _cancel_requested: bool = False


StatusCallback = Callable[[ManagedProcess], None]


class ProcessManager:
    """
    Sole place that starts subprocesses.

    - argv as list only (shell=False always)
    - timeouts + cancel (process group / tree where possible)
    - bounded concurrency via semaphore
    - optional status callback for persistence hooks
    """

    def __init__(
        self,
        *,
        max_concurrent: int = 4,
        default_timeout_seconds: float | None = 300.0,
        on_status: StatusCallback | None = None,
    ) -> None:
        if max_concurrent < 1:
            raise ValueError("max_concurrent must be >= 1")
        self._max_concurrent = max_concurrent
        self._default_timeout = default_timeout_seconds
        self._on_status = on_status
        self._sem = asyncio.Semaphore(max_concurrent)
        self._lock = asyncio.Lock()
        self._processes: dict[str, ManagedProcess] = {}

    @property
    def max_concurrent(self) -> int:
        return self._max_concurrent

    def list_processes(self) -> list[ManagedProcess]:
        return list(self._processes.values())

    def get(self, handle_id: str) -> ManagedProcess | None:
        return self._processes.get(handle_id)

    def _emit(self, mp: ManagedProcess) -> None:
        if self._on_status is not None:
            self._on_status(mp)

    async def run(self, spec: CommandSpec) -> ProcessResult:
        """Run a command to completion (with timeout/cancel support)."""
        handle_id = str(uuid.uuid4())
        mp = ManagedProcess(handle_id=handle_id, spec=spec)
        async with self._lock:
            self._processes[handle_id] = mp

        async with self._sem:
            return await self._execute(mp)

    async def start(self, spec: CommandSpec) -> ManagedProcess:
        """Start in background; caller may cancel via handle_id."""
        handle_id = str(uuid.uuid4())
        mp = ManagedProcess(handle_id=handle_id, spec=spec)
        async with self._lock:
            self._processes[handle_id] = mp

        async def _runner() -> None:
            async with self._sem:
                await self._execute(mp)

        asyncio.create_task(_runner())
        # Wait until running or finished quickly.
        for _ in range(50):
            if mp.status is not ProcessStatus.pending or mp.error:
                break
            await asyncio.sleep(0.01)
        return mp

    async def cancel(self, handle_id: str, *, grace_seconds: float = 2.0) -> bool:
        mp = self._processes.get(handle_id)
        if mp is None or mp._proc is None:
            return False
        if mp.status not in {ProcessStatus.pending, ProcessStatus.running}:
            return False
        mp._cancel_requested = True
        await self._terminate_tree(mp._proc, grace_seconds=grace_seconds)
        return True

    async def _execute(self, mp: ManagedProcess) -> ProcessResult:
        spec = mp.spec
        timeout = spec.timeout_seconds if spec.timeout_seconds is not None else self._default_timeout
        argv = list(spec.argv)
        env = os.environ.copy()
        if spec.env:
            env.update(dict(spec.env))

        # Log-safe snapshot (never log raw secrets).
        safe_argv = sanitize_arg_list(argv, sensitive_flags=spec.sensitive_flags)
        safe_env = sanitize_env(spec.env)
        _ = safe_argv, safe_env  # available for future structured logging

        mp.status = ProcessStatus.running
        mp.started_at = time.monotonic()
        self._emit(mp)

        try:
            # CRITICAL: shell=False — argv list only.
            kwargs: dict[str, Any] = {
                "stdout": asyncio.subprocess.PIPE,
                "stderr": asyncio.subprocess.PIPE,
                "env": env,
            }
            if spec.cwd:
                cwd_path = Path(spec.cwd)
                if not cwd_path.is_dir():
                    raise FileNotFoundError(f"cwd does not exist: {spec.cwd}")
                kwargs["cwd"] = str(cwd_path)

            if sys.platform != "win32":
                # Start new session so we can kill the process group on cancel/timeout.
                kwargs["start_new_session"] = True

            proc = await asyncio.create_subprocess_exec(*argv, **kwargs)
            mp._proc = proc
            mp.pid = proc.pid
            self._emit(mp)

            try:
                if timeout is not None and timeout > 0:
                    stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                else:
                    stdout_b, stderr_b = await proc.communicate()
            except asyncio.TimeoutError:
                await self._terminate_tree(proc, grace_seconds=2.0)
                mp.status = ProcessStatus.timed_out
                mp.exit_code = proc.returncode
                mp.error = f"timed out after {timeout}s"
                stdout_b, stderr_b = b"", b""
                # Drain if still possible
                try:
                    out, err = await asyncio.wait_for(proc.communicate(), timeout=1.0)
                    stdout_b, stderr_b = out, err
                except (asyncio.TimeoutError, ProcessLookupError):
                    pass

            mp.stdout = sanitize_text((stdout_b or b"").decode("utf-8", errors="replace"))
            mp.stderr = sanitize_text((stderr_b or b"").decode("utf-8", errors="replace"))
            mp.exit_code = proc.returncode
            mp.finished_at = time.monotonic()

            if mp.status is ProcessStatus.timed_out:
                pass
            elif mp._cancel_requested:
                mp.status = ProcessStatus.cancelled
            elif proc.returncode == 0:
                mp.status = ProcessStatus.completed
            else:
                mp.status = ProcessStatus.failed

        except FileNotFoundError as exc:
            mp.status = ProcessStatus.failed
            mp.error = str(exc)
            mp.finished_at = time.monotonic()
        except Exception as exc:  # noqa: BLE001 — persist failure, don't crash worker
            mp.status = ProcessStatus.failed
            mp.error = sanitize_text(str(exc))
            mp.finished_at = time.monotonic()

        self._emit(mp)
        duration = (mp.finished_at or time.monotonic()) - (mp.started_at or time.monotonic())
        return ProcessResult(
            status=mp.status,
            exit_code=mp.exit_code,
            stdout=mp.stdout,
            stderr=mp.stderr,
            duration_seconds=duration,
            pid=mp.pid,
            handle_id=mp.handle_id,
            error=mp.error,
        )

    async def _terminate_tree(self, proc: asyncio.subprocess.Process, *, grace_seconds: float) -> None:
        if proc.returncode is not None:
            return
        try:
            if sys.platform == "win32":
                proc.terminate()
            else:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)  # type: ignore[arg-type]
                except (ProcessLookupError, PermissionError, OSError):
                    proc.terminate()
        except ProcessLookupError:
            return

        try:
            await asyncio.wait_for(proc.wait(), timeout=grace_seconds)
            return
        except asyncio.TimeoutError:
            pass

        try:
            if sys.platform == "win32":
                proc.kill()
            else:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)  # type: ignore[arg-type]
                except (ProcessLookupError, PermissionError, OSError):
                    proc.kill()
        except ProcessLookupError:
            return
        try:
            await asyncio.wait_for(proc.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            pass


def assert_argv_list(argv: Sequence[str]) -> list[str]:
    """Helper for adapters: ensure argv is a clean string list."""
    if isinstance(argv, str):
        raise TypeError("argv must be a list/tuple of strings, not a shell string")
    out = list(argv)
    if not out:
        raise ValueError("argv empty")
    if not all(isinstance(a, str) for a in out):
        raise TypeError("argv elements must be strings")
    return out
