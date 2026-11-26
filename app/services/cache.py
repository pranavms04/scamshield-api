import time
from typing import Any


class TTLCache:
    """Tiny in-process cache. Swap for Redis when you run more than one server
    (each process would otherwise have its own cache)."""

    def __init__(self, ttl_seconds: int, max_items: int = 10_000):
        self.ttl, self.max_items = ttl_seconds, max_items
        self._data: dict[str, tuple[float, Any]] = {}

    def get(self, key: str) -> Any | None:
        item = self._data.get(key)
        if item is None or item[0] < time.monotonic():
            self._data.pop(key, None)
            return None
        return item[1]

    def set(self, key: str, value: Any) -> None:
        if len(self._data) >= self.max_items:
            self._data.pop(next(iter(self._data)))  # evict oldest inserted
        self._data[key] = (time.monotonic() + self.ttl, value)
