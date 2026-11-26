import time
from collections import defaultdict, deque

from fastapi import HTTPException, status


class SlidingWindowLimiter:
    """Allow N requests per rolling 60 s per client. In production use Redis
    (INCR + EXPIRE or a sorted set) so the limit is shared across servers."""

    def __init__(self, per_minute: int):
        self.per_minute = per_minute
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def hit(self, client_id: str) -> None:
        now = time.monotonic()
        q = self._hits[client_id]
        while q and q[0] <= now - 60:
            q.popleft()
        if len(q) >= self.per_minute:
            retry = int(60 - (now - q[0])) + 1
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Rate limit exceeded",
                                headers={"Retry-After": str(retry)})
        q.append(now)
