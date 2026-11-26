import time
from collections import defaultdict, deque

from fastapi import HTTPException, status


class LoginGuard:
    """Blocks brute-force password guessing: after `max_failures` wrong passwords for one account
    (or from one IP) within `window_seconds`, further attempts get 429 until the window passes.
    In-memory like the rate limiter; use Redis when running more than one server."""

    def __init__(self, max_failures: int = 5, window_seconds: int = 900):
        self.max_failures, self.window = max_failures, window_seconds
        self._failures: dict[str, deque[float]] = defaultdict(deque)

    def _recent(self, key: str, now: float) -> deque[float]:
        q = self._failures[key]
        while q and q[0] <= now - self.window:
            q.popleft()
        return q

    def check(self, *keys: str) -> None:
        now = time.monotonic()
        for key in keys:
            q = self._recent(key, now)
            if len(q) >= self.max_failures:
                retry = int(self.window - (now - q[0])) + 1
                raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                                    "Too many failed login attempts. Try again later.",
                                    headers={"Retry-After": str(retry)})

    def fail(self, *keys: str) -> None:
        now = time.monotonic()
        for key in keys:
            self._recent(key, now).append(now)

    def reset(self, *keys: str) -> None:
        for key in keys:
            self._failures.pop(key, None)
