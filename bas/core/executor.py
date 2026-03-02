"""
Attack executor - handles the actual execution of individual attack operations.

Provides rate limiting, concurrency control, and result collection.
All network operations go through this layer.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import httpx

from bas.core.scope import ScopeEnforcer


@dataclass
class AttackRequest:
    """A single attack request to be executed."""
    request_id: str
    target: str
    method: str = "GET"
    path: str = "/"
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, str] = field(default_factory=dict)
    body: str | bytes | None = None
    content_type: str = "text/plain"
    timeout: float = 30.0
    follow_redirects: bool = False


@dataclass
class AttackResponse:
    """Response from an attack request."""
    request_id: str
    target: str
    status_code: int
    headers: dict[str, str]
    body: bytes
    elapsed_ms: float
    timestamp: datetime = field(default_factory=datetime.now)
    error: str | None = None
    indicators: list[str] = field(default_factory=list)

    @property
    def body_text(self) -> str:
        try:
            return self.body.decode("utf-8", errors="replace")
        except Exception:
            return ""


class RateLimiter:
    """Token bucket rate limiter."""

    def __init__(self, rate: int):
        self._rate = rate
        self._tokens = float(rate)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self._rate, self._tokens + elapsed * self._rate)
            self._last_refill = now

            if self._tokens < 1:
                wait_time = (1 - self._tokens) / self._rate
                await asyncio.sleep(wait_time)
                self._tokens = 0
            else:
                self._tokens -= 1


class AttackExecutor:
    """
    Executes attack requests with scope enforcement, rate limiting,
    and concurrency control.
    """

    def __init__(
        self,
        scope: ScopeEnforcer,
        max_rps: int = 10,
        max_concurrent: int = 5,
        proxy: str | None = None,
    ):
        self._scope = scope
        self._rate_limiter = RateLimiter(max_rps)
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._proxy = proxy
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> AttackExecutor:
        transport_kwargs: dict[str, Any] = {}
        if self._proxy:
            self._client = httpx.AsyncClient(
                proxy=self._proxy,
                verify=False,
                **transport_kwargs,
            )
        else:
            self._client = httpx.AsyncClient(
                verify=False,
                **transport_kwargs,
            )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.aclose()

    async def execute_single(self, request: AttackRequest) -> AttackResponse:
        """Execute a single attack request with all safety checks."""
        # Scope check - fail-closed
        self._scope.validate_target(request.target)

        if self._scope.is_dry_run:
            return AttackResponse(
                request_id=request.request_id,
                target=request.target,
                status_code=0,
                headers={},
                body=b"[DRY RUN]",
                elapsed_ms=0.0,
            )

        await self._rate_limiter.acquire()

        async with self._semaphore:
            return await self._do_request(request)

    async def execute_batch(self, requests: list[AttackRequest]) -> list[AttackResponse]:
        """Execute multiple attack requests concurrently."""
        tasks = [self.execute_single(req) for req in requests]
        return await asyncio.gather(*tasks, return_exceptions=False)

    async def _do_request(self, request: AttackRequest) -> AttackResponse:
        """Perform the actual HTTP request."""
        if not self._client:
            raise RuntimeError("Executor not initialized. Use 'async with AttackExecutor(...) as executor:'")

        url = request.target.rstrip("/") + "/" + request.path.lstrip("/")
        headers = {**request.headers}
        if request.body and request.content_type:
            headers.setdefault("Content-Type", request.content_type)

        start = time.monotonic()
        try:
            response = await self._client.request(
                method=request.method,
                url=url,
                headers=headers,
                params=request.params,
                content=request.body if isinstance(request.body, bytes) else (
                    request.body.encode() if request.body else None
                ),
                timeout=request.timeout,
                follow_redirects=request.follow_redirects,
            )
            elapsed = (time.monotonic() - start) * 1000

            return AttackResponse(
                request_id=request.request_id,
                target=request.target,
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.content,
                elapsed_ms=elapsed,
            )

        except httpx.TimeoutException:
            elapsed = (time.monotonic() - start) * 1000
            return AttackResponse(
                request_id=request.request_id,
                target=request.target,
                status_code=0,
                headers={},
                body=b"",
                elapsed_ms=elapsed,
                error="timeout",
            )
        except httpx.RequestError as exc:
            elapsed = (time.monotonic() - start) * 1000
            return AttackResponse(
                request_id=request.request_id,
                target=request.target,
                status_code=0,
                headers={},
                body=b"",
                elapsed_ms=elapsed,
                error=str(exc),
            )
