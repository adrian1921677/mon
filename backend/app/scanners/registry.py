"""Scanner registry: scanner_id → adapter."""

from __future__ import annotations

from collections.abc import Iterable

from app.scanners.base import Capability, ScannerAdapter


class ScannerRegistryError(KeyError):
    pass


class ScannerRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, ScannerAdapter] = {}

    def register(self, adapter: ScannerAdapter, *, replace: bool = False) -> None:
        sid = adapter.scanner_id
        if not sid:
            raise ValueError("adapter.scanner_id must be set")
        if sid in self._adapters and not replace:
            raise ScannerRegistryError(f"scanner already registered: {sid}")
        self._adapters[sid] = adapter

    def get(self, scanner_id: str) -> ScannerAdapter:
        try:
            return self._adapters[scanner_id]
        except KeyError as exc:
            raise ScannerRegistryError(f"unknown scanner: {scanner_id}") from exc

    def has(self, scanner_id: str) -> bool:
        return scanner_id in self._adapters

    def list(
        self,
        *,
        include_test_only: bool = False,
        capability: Capability | None = None,
    ) -> list[ScannerAdapter]:
        items = list(self._adapters.values())
        if not include_test_only:
            items = [a for a in items if not a.is_test_only]
        if capability is not None:
            items = [a for a in items if capability in a.capabilities]
        return sorted(items, key=lambda a: a.scanner_id)

    def ids(self, *, include_test_only: bool = False) -> list[str]:
        return [a.scanner_id for a in self.list(include_test_only=include_test_only)]

    def clear(self) -> None:
        self._adapters.clear()

    def __len__(self) -> int:
        return len(self._adapters)

    def __contains__(self, scanner_id: object) -> bool:
        return isinstance(scanner_id, str) and scanner_id in self._adapters

    def __iter__(self) -> Iterable[ScannerAdapter]:
        return iter(self.list(include_test_only=True))


_REGISTRY: ScannerRegistry | None = None


def get_registry() -> ScannerRegistry:
    global _REGISTRY
    if _REGISTRY is None:
        from app.scanners.bootstrap import build_default_registry

        _REGISTRY = build_default_registry()
    return _REGISTRY


def reset_registry(registry: ScannerRegistry | None = None) -> ScannerRegistry:
    """Test helper — replace or rebuild the process-wide registry."""
    global _REGISTRY
    if registry is None:
        from app.scanners.bootstrap import build_default_registry

        _REGISTRY = build_default_registry()
    else:
        _REGISTRY = registry
    return _REGISTRY
