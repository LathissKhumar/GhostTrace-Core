"""FastAPI middleware for GhostTrace production deployment.

Provides:
- RequestIDMiddleware: Injects a unique request ID into every request
  and sets the logging context variable so all logs include it.
- RateLimitMiddleware: In-memory sliding-window rate limiter per IP,
  configurable per-route limits.
- TimingMiddleware: Logs request method, path, status, and duration.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections import defaultdict
from collections.abc import Callable
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from logging_config import request_id_var

logger = logging.getLogger(__name__)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Assigns a unique request ID to every incoming request.

    The request ID is:
    1. Extracted from X-Request-ID header if present, otherwise generated.
    2. Set in the logging context so all log lines include it.
    3. Returned in the X-Request-ID response header.
    """

    async def dispatch(self, request: Request, call_next: Callable[..., Any]) -> Response:
        req_id = request.headers.get("x-request-id", uuid.uuid4().hex[:16])

        # Set context variable for structured logging
        token = request_id_var.set(req_id)

        # Store on request state for endpoint access
        request.state.request_id = req_id

        try:
            response = await call_next(request)
            response.headers["X-Request-ID"] = req_id
            return response
        finally:
            request_id_var.reset(token)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory sliding-window rate limiter per client IP.

    Uses a dictionary of {ip: [timestamp, ...]} with a sliding window.
    Old timestamps are pruned on each check. No external dependencies
    (Redis, etc.) — purely in-memory, suitable for single-process deploys.
    """

    def __init__(self, app: Any, requests_per_minute: int = 60) -> None:
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.window_seconds = 60.0
        # Per-IP request timestamps
        self._requests: dict[str, list[float]] = defaultdict(list)
        # Optional per-path overrides: path_prefix → limit
        self._path_limits: dict[str, int] = {
            "/run": min(requests_per_minute, 10),  # LLM-intensive
            "/upload": requests_per_minute,
        }

    def _get_limit(self, path: str) -> int:
        """Return the rate limit for a given path."""
        for prefix, limit in self._path_limits.items():
            if path.startswith(prefix):
                return limit
        return self.requests_per_minute

    def _check_rate_limit(self, client_ip: str, path: str) -> tuple[bool, int]:
        """Check if the client has exceeded the rate limit.

        Returns:
            Tuple of (is_allowed, retry_after_seconds).
        """
        now = time.monotonic()
        limit = self._get_limit(path)
        window_start = now - self.window_seconds

        # Prune old timestamps
        timestamps = self._requests[client_ip]
        self._requests[client_ip] = [
            ts for ts in timestamps if ts > window_start
        ]

        if len(self._requests[client_ip]) >= limit:
            # Calculate retry-after based on oldest timestamp in window
            oldest = self._requests[client_ip][0]
            retry_after = int(oldest + self.window_seconds - now) + 1
            return False, max(retry_after, 1)

        # Record this request
        self._requests[client_ip].append(now)
        return True, 0

    async def dispatch(self, request: Request, call_next: Callable[..., Any]) -> Response:
        # Skip rate limiting for health checks
        if request.url.path == "/health":
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        allowed, retry_after = self._check_rate_limit(client_ip, request.url.path)

        if not allowed:
            logger.warning(
                "Rate limit exceeded",
                extra={"client_ip": client_ip, "path": request.url.path},
            )
            return JSONResponse(
                status_code=429,
                content={
                    "error": "rate_limit_exceeded",
                    "detail": f"Too many requests. Limit: {self._get_limit(request.url.path)} per minute.",
                    "retry_after": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )

        return await call_next(request)


class TimingMiddleware(BaseHTTPMiddleware):
    """Logs request method, path, status code, and duration."""

    async def dispatch(self, request: Request, call_next: Callable[..., Any]) -> Response:
        start = time.perf_counter()
        method = request.method
        path = request.url.path

        try:
            response = await call_next(request)
            duration_ms = (time.perf_counter() - start) * 1000

            # Log at WARNING for 5xx, INFO otherwise
            level = logging.WARNING if response.status_code >= 500 else logging.INFO
            logger.log(
                level,
                "%s %s → %d (%.0fms)",
                method,
                path,
                response.status_code,
                duration_ms,
            )
            return response

        except Exception:
            duration_ms = (time.perf_counter() - start) * 1000
            logger.error(
                "%s %s → 500 (%.0fms) UNHANDLED",
                method,
                path,
                duration_ms,
            )
            raise
