"""An outside check on twinhole itself.

Every alert depends on twinhole running, so if it (or the machine under it) stops,
nothing says so. With HEARTBEAT_URL set, twinhole calls that address after its health
checks, at most once per HEARTBEAT_INTERVAL. A service that expects the call, such as
healthchecks.io or an Uptime Kuma "push" monitor on another machine, raises the alarm
when the calls stop.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable

import httpx

log = logging.getLogger(__name__)


class Heartbeat:
    def __init__(
        self,
        url: str,
        interval: int,
        clock: Callable[[], float] = time.time,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.url = url
        self.interval = interval
        self.clock = clock
        self.last_ok: float | None = None
        self.last_error: str | None = None
        self._due = 0.0
        self._http = httpx.AsyncClient(timeout=10, transport=transport) if url else None

    @property
    def enabled(self) -> bool:
        return self._http is not None

    async def beat(self) -> None:
        if self._http is None:
            return
        now = self.clock()
        if now < self._due:
            return
        self._due = now + self.interval
        try:
            r = await self._http.get(self.url)
            r.raise_for_status()
        except httpx.HTTPError as e:
            # Not an alert: when this can't get out, the service on the other end is the one to say so.
            self.last_error = str(e) or type(e).__name__
            log.info("heartbeat failed: %s", self.last_error)
            return
        self.last_ok, self.last_error = now, None

    def status(self) -> dict:
        return {"enabled": self.enabled, "last_ok": self.last_ok and int(self.last_ok), "error": self.last_error}

    async def aclose(self) -> None:
        if self._http is not None:
            await self._http.aclose()
