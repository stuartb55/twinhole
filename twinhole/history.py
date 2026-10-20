"""Long-term history: 10-minute buckets and daily top-25 snapshots, kept in SQLite."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

from .config import Settings
from .pihole import Pihole, PiholeError
from .store import DAY, Store

log = logging.getLogger(__name__)

TOP_COUNT = 25
CATCH_UP_DAYS = 7  # re-check this many past days for missing top lists each run


class History:
    def __init__(
        self, settings: Settings, piholes: list[Pihole], store: Store, clock: Callable[[], float] = time.time
    ):
        self.settings = settings
        self.piholes = piholes
        self.store = store
        self.clock = clock
        self.tz = ZoneInfo(settings.tz)

    def day_of(self, ts: float) -> date:
        return datetime.fromtimestamp(ts, self.tz).date()

    def day_bounds(self, day: date) -> tuple[int, int]:
        start = datetime.combine(day, datetime.min.time(), self.tz)
        end = datetime.combine(day + timedelta(days=1), datetime.min.time(), self.tz)
        return int(start.timestamp()), int(end.timestamp())

    async def run(self) -> None:
        """One scheduled pass: backfill (first time only), recent buckets, missing daily tops, pruning."""
        for p in self.piholes:
            try:
                await self.backfill(p)
                self.store.upsert_history(p.id, await p.history())
                await self.catch_up_tops(p)
            except PiholeError as e:
                log.info("history import skipped for %s: %s", p.name, e)
        self.prune()

    async def backfill(self, p: Pihole) -> None:
        key = f"backfill:{p.id}"
        if self.store.get_meta(key):
            return
        now = int(self.clock())
        buckets = await p.history_database(now - self.settings.backfill_days * DAY, now)
        count = self.store.upsert_history(p.id, buckets)
        today = self.day_of(now)
        days = sorted({self.day_of(b["timestamp"]) for b in buckets} - {today})
        for day in days:
            if not self._has_top(p, day):
                await self.snapshot_day(p, day)
        self.store.set_meta(key, str(now))
        self.store.add_event(
            "info", f"Imported {count} history buckets and {len(days)} days of top lists from {p.name}", p.id
        )

    async def catch_up_tops(self, p: Pihole) -> None:
        today = self.day_of(self.clock())
        for back in range(1, CATCH_UP_DAYS + 1):
            day = today - timedelta(days=back)
            if not self._has_top(p, day):
                await self.snapshot_day(p, day)

    async def snapshot_day(self, p: Pihole, day: date) -> None:
        start, end = self.day_bounds(day)
        domains = await p.top_domains_database(start, end, blocked=False, count=TOP_COUNT)
        blocked = await p.top_domains_database(start, end, blocked=True, count=TOP_COUNT)
        clients = await p.top_clients_database(start, end, count=TOP_COUNT)
        d = day.isoformat()
        self.store.replace_daily_top(p.id, d, "domains", [{"item": x["domain"], "count": x["count"]} for x in domains])
        self.store.replace_daily_top(p.id, d, "blocked", [{"item": x["domain"], "count": x["count"]} for x in blocked])
        self.store.replace_daily_top(
            p.id, d, "clients", [{"item": x["ip"], "label": x.get("name") or None, "count": x["count"]} for x in clients]
        )
        # Marked separately so a day with no queries isn't fetched again every run.
        self.store.set_meta(f"top:{p.id}:{d}", "1")

    def _has_top(self, p: Pihole, day: date) -> bool:
        return self.store.get_meta(f"top:{p.id}:{day.isoformat()}") is not None

    def prune(self) -> None:
        today = self.day_of(self.clock())
        if self.store.get_meta("pruned") == today.isoformat():
            return
        oldest = today - timedelta(days=self.settings.retention_days)
        self.store.prune(self.settings.retention_days, oldest.isoformat(), int(self.clock()))
        self.store.set_meta("pruned", today.isoformat())
