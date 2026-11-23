"""Shared installation probes — no fake success."""

from __future__ import annotations

import shutil
from pathlib import Path

from app.scanners.base import InstallationInfo, InstallationStatus, RuntimeKind


def probe_binaries(
    names: tuple[str, ...],
    *,
    runtime: RuntimeKind = RuntimeKind.native,
    hint: str = "",
) -> InstallationInfo:
    """Return installed only if at least one binary is on PATH."""
    if not names:
        return InstallationInfo(
            status=InstallationStatus.not_installed,
            path_or_runtime=runtime.value,
            message=hint or "no binary names configured",
        )
    for name in names:
        path = shutil.which(name)
        if path:
            return InstallationInfo(
                status=InstallationStatus.installed,
                path_or_runtime=runtime.value,
                binary_path=str(Path(path)),
                message=f"found {name} at {path}",
                meta={"binary": name},
            )
    listed = ", ".join(names)
    return InstallationInfo(
        status=InstallationStatus.not_installed,
        path_or_runtime=runtime.value,
        message=hint or f"none of [{listed}] found on PATH — install via Tool Manager / WSL / Docker",
    )
