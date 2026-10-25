"""SQLite storage: 10-minute history buckets, daily top lists, health-check rollups,
events, active alerts and past outages."""

from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Iterable
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS history (
    pihole TEXT NOT NULL,
    ts INTEGER NOT NULL,
    total INTEGER NOT NULL,
    blocked INTEGER NOT NULL,
    cached INTEGER NOT NULL,
    forwarded INTEGER NOT NULL,
    PRIMARY KEY (pihole, ts)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS daily_top (
    pihole TEXT NOT NULL,
    day TEXT NOT NULL,          -- YYYY-MM-DD in the configured time zone
    kind TEXT NOT NULL,         -- domains | blocked | clients
    rank INTEGER NOT NULL,
    item TEXT NOT NULL,
    label TEXT,
    count INTEGER NOT NULL,
    PRIMARY KEY (pihole, day, kind, rank)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    pihole TEXT,
    kind TEXT NOT NULL,         -- alert | recovered | sync | action | info
    message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);

CREATE TABLE IF NOT EXISTS active_alerts (
    key TEXT PRIMARY KEY,
    since INTEGER NOT NULL,
    title TEXT NOT NULL,
    detail TEXT NOT NULL
);

-- twinhole's own health checks, rolled up into 10-minute buckets
CREATE TABLE IF NOT EXISTS checks (
    pihole TEXT NOT NULL,
    ts INTEGER NOT NULL,        -- start of the bucket
    total INTEGER NOT NULL,     -- checks run
    up INTEGER NOT NULL,        -- checks where the API and the IPv4 DNS lookup both worked
    dns_ms REAL NOT NULL,       -- sum of IPv4 DNS reply times (ms) over dns_n
    dns_n INTEGER NOT NULL,
    rec_ms REAL NOT NULL,       -- sum of recursion-check reply times (ms) over rec_n
    rec_n INTEGER NOT NULL,
    PRIMARY KEY (pihole, ts)
) WITHOUT ROWID;

-- alerts that have recovered, for "last outage" and similar
CREATE TABLE IF NOT EXISTS past_alerts (
    key TEXT NOT NULL,
    pihole TEXT,
    priority INTEGER NOT NULL,
    title TEXT NOT NULL,
    since INTEGER NOT NULL,
    until INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS past_alerts_until ON past_alerts (until);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

DAY = 86400


class Store:
    def __init__(self, path: str):
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.executescript(SCHEMA)

    def close(self) -> None:
        self._db.close()

    def _exec(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, tuple(params)).fetchall()

    def _many(self, sql: str, rows: Iterable[Iterable[Any]]) -> None:
        with self._lock:
            self._db.execute("BEGIN")
            try:
                self._db.executemany(sql, [tuple(r) for r in rows])
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    # --- meta ---------------------------------------------------------------

    def get_meta(self, key: str) -> str | None:
        rows = self._exec("SELECT value FROM meta WHERE key = ?", (key,))
        return rows[0]["value"] if rows else None

    def set_meta(self, key: str, value: str) -> None:
        self._exec("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))

    # --- history ------------------------------------------------------------

    def upsert_history(self, pihole: str, buckets: Iterable[dict[str, Any]]) -> int:
        rows = [
            (pihole, int(b["timestamp"]), b["total"], b["blocked"], b["cached"], b["forwarded"])
            for b in buckets
        ]
        self._many(
            "INSERT OR REPLACE INTO history (pihole, ts, total, blocked, cached, forwarded) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            rows,
        )
        return len(rows)

    def history_series(self, since: int, step: int, offset: int = 0) -> dict[str, list[dict[str, int]]]:
        """Totals per `step` seconds since `since`, grouped by Pi-hole.

        `offset` (the time zone's UTC offset in seconds) makes daily buckets start at local midnight.
        """
        rows = self._exec(
            "SELECT pihole, ((ts + ?) / ?) * ? - ? AS t, SUM(total) AS total, SUM(blocked) AS blocked, "
            "SUM(cached) AS cached, SUM(forwarded) AS forwarded "
            "FROM history WHERE ts >= ? GROUP BY pihole, t ORDER BY t",
            (offset, step, step, offset, since),
        )
        out: dict[str, list[dict[str, int]]] = {}
        for r in rows:
            out.setdefault(r["pihole"], []).append(
                {k: r[k] for k in ("t", "total", "blocked", "cached", "forwarded")}
            )
        return out

    def history_bounds(self) -> tuple[int | None, int | None]:
        row = self._exec("SELECT MIN(ts) AS lo, MAX(ts) AS hi FROM history")[0]
        return row["lo"], row["hi"]

    # --- daily top lists ----------------------------------------------------

    def replace_daily_top(self, pihole: str, day: str, kind: str, items: list[dict[str, Any]]) -> None:
        with self._lock:
            self._db.execute("BEGIN")
            try:
                self._db.execute(
                    "DELETE FROM daily_top WHERE pihole = ? AND day = ? AND kind = ?", (pihole, day, kind)
                )
                self._db.executemany(
                    "INSERT INTO daily_top (pihole, day, kind, rank, item, label, count) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    [
                        (pihole, day, kind, i, it["item"], it.get("label"), it["count"])
                        for i, it in enumerate(items)
                    ],
                )
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def top(self, kind: str, first_day: str, last_day: str, pihole: str | None, limit: int) -> list[dict]:
        """Sum the daily top lists over a day range. Items outside a day's top 25 count as 0 that day."""
        sql = (
            "SELECT item, MAX(label) AS label, SUM(count) AS count FROM daily_top "
            "WHERE kind = ? AND day BETWEEN ? AND ?"
        )
        params: list[Any] = [kind, first_day, last_day]
        if pihole:
            sql += " AND pihole = ?"
            params.append(pihole)
        sql += " GROUP BY item ORDER BY count DESC LIMIT ?"
        params.append(limit)
        return [dict(r) for r in self._exec(sql, params)]

    def top_days(self) -> list[str]:
        return [r["day"] for r in self._exec("SELECT DISTINCT day FROM daily_top ORDER BY day DESC")]

    # --- events and alerts --------------------------------------------------

    def add_event(self, kind: str, message: str, pihole: str | None = None, ts: int | None = None) -> None:
        self._exec(
            "INSERT INTO events (ts, pihole, kind, message) VALUES (?, ?, ?, ?)",
            (ts or int(time.time()), pihole, kind, message),
        )

    def events(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._exec(
            "SELECT ts, pihole, kind, message FROM events ORDER BY ts DESC, id DESC LIMIT ?", (limit,)
        )
        return [dict(r) for r in rows]

    def save_alert(self, key: str, since: int, title: str, detail: str) -> None:
        self._exec(
            "INSERT OR REPLACE INTO active_alerts (key, since, title, detail) VALUES (?, ?, ?, ?)",
            (key, since, title, detail),
        )

    def clear_alert(self, key: str) -> None:
        self._exec("DELETE FROM active_alerts WHERE key = ?", (key,))

    def active_alerts(self) -> dict[str, dict[str, Any]]:
        return {r["key"]: dict(r) for r in self._exec("SELECT * FROM active_alerts")}

    # --- health-check rollups and outages ---------------------------------------

    def record_check(
        self, pihole: str, ts: int, up: bool, dns_ms: float | None, rec_ms: float | None, bucket: int = 600
    ) -> None:
        self._exec(
            "INSERT INTO checks (pihole, ts, total, up, dns_ms, dns_n, rec_ms, rec_n) VALUES (?, ?, 1, ?, ?, ?, ?, ?) "
            "ON CONFLICT (pihole, ts) DO UPDATE SET total = total + 1, up = up + excluded.up, "
            "dns_ms = dns_ms + excluded.dns_ms, dns_n = dns_n + excluded.dns_n, "
            "rec_ms = rec_ms + excluded.rec_ms, rec_n = rec_n + excluded.rec_n",
            (pihole, ts - ts % bucket, int(up), dns_ms or 0, int(dns_ms is not None),
             rec_ms or 0, int(rec_ms is not None)),
        )

    def uptime(self, since: int) -> dict[str, dict[str, Any]]:
        rows = self._exec(
            "SELECT pihole, SUM(total) AS total, SUM(up) AS up, MIN(ts) AS first FROM checks WHERE ts >= ? GROUP BY pihole",
            (since,),
        )
        return {r["pihole"]: {"total": r["total"], "up": r["up"], "first": r["first"]} for r in rows}

    def latency_series(self, since: int, step: int) -> dict[str, list[dict[str, Any]]]:
        rows = self._exec(
            "SELECT pihole, (ts / ?) * ? AS t, SUM(dns_ms) AS dns_ms, SUM(dns_n) AS dns_n, "
            "SUM(rec_ms) AS rec_ms, SUM(rec_n) AS rec_n, SUM(total) AS total, SUM(up) AS up "
            "FROM checks WHERE ts >= ? GROUP BY pihole, t ORDER BY t",
            (step, step, since),
        )
        out: dict[str, list[dict[str, Any]]] = {}
        for r in rows:
            out.setdefault(r["pihole"], []).append({
                "t": r["t"],
                "dns_ms": round(r["dns_ms"] / r["dns_n"], 1) if r["dns_n"] else None,
                "rec_ms": round(r["rec_ms"] / r["rec_n"], 1) if r["rec_n"] else None,
                "up_pct": round(100 * r["up"] / r["total"], 2) if r["total"] else None,
            })
        return out

    def add_past_alert(self, key: str, pihole: str | None, priority: int, title: str, since: int, until: int) -> None:
        self._exec(
            "INSERT INTO past_alerts (key, pihole, priority, title, since, until) VALUES (?, ?, ?, ?, ?, ?)",
            (key, pihole, priority, title, since, until),
        )

    def last_past_alert(self, pihole: str, min_priority: int) -> dict[str, Any] | None:
        rows = self._exec(
            "SELECT * FROM past_alerts WHERE pihole = ? AND priority >= ? ORDER BY until DESC LIMIT 1",
            (pihole, min_priority),
        )
        return dict(rows[0]) if rows else None

    # --- retention ----------------------------------------------------------

    def prune(self, retention_days: int, oldest_day: str, now: int | None = None) -> None:
        cutoff = (now or int(time.time())) - retention_days * DAY
        self._exec("DELETE FROM history WHERE ts < ?", (cutoff,))
        self._exec("DELETE FROM events WHERE ts < ?", (cutoff,))
        self._exec("DELETE FROM checks WHERE ts < ?", (cutoff,))
        self._exec("DELETE FROM past_alerts WHERE until < ?", (cutoff,))
        self._exec("DELETE FROM daily_top WHERE day < ?", (oldest_day,))
