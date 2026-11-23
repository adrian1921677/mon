"""Stable finding fingerprints for deduplication."""

from __future__ import annotations

import hashlib


def fingerprint_for(scanner_id: str, parts: tuple[str, ...]) -> str:
    """
    Build a stable SHA-256 hex fingerprint.

    Parts should be normalized (lowercased where appropriate by the caller),
    include category/rule/target identity, and exclude volatile timestamps.
    """
    normalized = [scanner_id.strip().lower()]
    for part in parts:
        normalized.append(" ".join(str(part).strip().lower().split()))
    material = "\x1f".join(normalized)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
