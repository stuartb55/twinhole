"""Alert state machine and ntfy delivery.

Each condition (e.g. "192.168.1.118:dns4") is observed every cycle as bad, good or
unknown. It fires once it has been bad for long enough, sends exactly one alert,
and sends one "recovered" message when it next comes good. Active alerts are kept
in SQLite so a restart neither repeats nor forgets them.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

import httpx

from .store import Store

log = logging.getLogger(__name__)

URGENT, DEFAULT, LOW = 5, 3, 2


class Notifier(Protocol):
    async def send(self, title: str, message: str, priority: int, tags: list[str]) -> None: ...


class Ntfy:
    def __init__(self, url: str, topic: str, token: str = "", transport: httpx.AsyncBaseTransport | None = None):
        self.url, self.topic = url, topic
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        self._http = httpx.AsyncClient(timeout=10, headers=headers, transport=transport)

    async def send(self, title: str, message: str, priority: int, tags: list[str]) -> None:
        body = {"topic": self.topic, "title": title, "message": message, "priority": priority, "tags": tags}
        r = await self._http.post(self.url, json=body)
        r.raise_for_status()

    async def aclose(self) -> None:
        await self._http.aclose()


class NoNotifier:
    async def send(self, title: str, message: str, priority: int, tags: list[str]) -> None:
        log.info("ntfy not configured; would send: %s - %s", title, message)


@dataclass
class _Pending:
    count: int = 0
    since: float = 0.0


class AlertManager:
    def __init__(self, store: Store, notifier: Notifier, clock: Callable[[], float] = time.time):
        self.store = store
        self.notifier = notifier
        self.clock = clock
        self._pending: dict[str, _Pending] = {}
        self.active = store.active_alerts()

    async def observe(
        self,
        key: str,
        bad: bool | None,
        *,
        pihole: str | None,
        title: str,
        detail: str,
        priority: int,
        after_count: int = 1,
        after_seconds: float = 0,
        recovered_detail: str = "",
    ) -> None:
        """Record one observation. `bad=None` means "couldn't tell" and changes nothing."""
        if bad is None:
            return
        now = self.clock()
        if bad:
            p = self._pending.setdefault(key, _Pending(since=now))
            p.count += 1
            if key in self.active:
                return
            if p.count >= after_count and now - p.since >= after_seconds:
                self.active[key] = {"key": key, "since": int(p.since), "title": title, "detail": detail}
                self.store.save_alert(key, int(p.since), title, detail)
                self.store.add_event("alert", f"{title}: {detail}", pihole)
                await self._send(title, detail, priority, ["warning"])
            return

        self._pending.pop(key, None)
        alert = self.active.pop(key, None)
        if alert:
            self.store.clear_alert(key)
            lasted = _duration(now - alert["since"])
            message = f"{recovered_detail or 'OK again'} (was down {lasted})"
            self.store.add_event("recovered", f"Recovered - {alert['title']}: {message}", pihole)
            await self._send(f"Recovered - {alert['title']}", message, LOW, ["white_check_mark"])

    async def _send(self, title: str, message: str, priority: int, tags: list[str]) -> None:
        try:
            await self.notifier.send(title, message, priority, tags)
        except Exception as e:  # a broken ntfy must never stop monitoring
            reason = _ntfy_reason(e)
            log.warning("could not send ntfy message %r: %s", title, reason)
            self.store.add_event("info", f"Could not send alert '{title}': {reason}")


def _ntfy_reason(e: Exception) -> str:
    if isinstance(e, httpx.HTTPStatusError):
        code = e.response.status_code
        if code in (401, 403):
            return f"ntfy refused it ({code}); set NTFY_TOKEN in .env to a token allowed to publish"
        return f"ntfy answered HTTP {code}"
    return str(e) or type(e).__name__


def _duration(seconds: float) -> str:
    s = int(seconds)
    if s < 120:
        return f"{s}s"
    if s < 7200:
        return f"{s // 60} min"
    if s < 2 * 86400:
        return f"{s // 3600}h {s % 3600 // 60}m"
    return f"{s // 86400} days"
