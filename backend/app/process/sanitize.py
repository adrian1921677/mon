"""Log sanitization — strip secrets from argv/env/output."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

# Common secret-looking keys / patterns.
_SECRET_KEY_RE = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|auth|credential|bearer|private[_-]?key)",
    re.IGNORECASE,
)
_SECRET_VALUE_RE = re.compile(
    r"(?i)(bearer\s+)[a-z0-9\-._~+/]+=*|((?:password|token|api[_-]?key|secret)\s*[=:]\s*)(\S+)"
)

REDACTED = "***REDACTED***"


def sanitize_arg_list(args: Sequence[str], *, sensitive_flags: Sequence[str] | None = None) -> list[str]:
    """Return a copy of argv with secret-looking values redacted for logs."""
    flags = {f.lower() for f in (sensitive_flags or ("--password", "--token", "--api-key", "-p"))}
    out: list[str] = []
    redact_next = False
    for arg in args:
        if redact_next:
            out.append(REDACTED)
            redact_next = False
            continue
        lower = arg.lower()
        # --token=value
        if "=" in arg:
            key, _, _val = arg.partition("=")
            if key.lower() in flags or _SECRET_KEY_RE.search(key):
                out.append(f"{key}={REDACTED}")
                continue
        if lower in flags or (lower.startswith("--") and _SECRET_KEY_RE.search(lower)):
            out.append(arg)
            redact_next = True
            continue
        out.append(_SECRET_VALUE_RE.sub(lambda m: (m.group(1) or m.group(2) or "") + REDACTED, arg))
    return out


def sanitize_env(env: Mapping[str, str] | None) -> dict[str, str]:
    if not env:
        return {}
    cleaned: dict[str, str] = {}
    for key, value in env.items():
        if _SECRET_KEY_RE.search(key):
            cleaned[key] = REDACTED
        else:
            cleaned[key] = _SECRET_VALUE_RE.sub(
                lambda m: (m.group(1) or m.group(2) or "") + REDACTED, value
            )
    return cleaned


def sanitize_text(text: str) -> str:
    return _SECRET_VALUE_RE.sub(lambda m: (m.group(1) or m.group(2) or "") + REDACTED, text)
