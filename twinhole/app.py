"""The twinhole web app: JSON API for the dashboard plus the background loops."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import config, devices, dnsprobe
from .alerts import URGENT, AlertManager, NoNotifier, Notifier, Ntfy
from .history import History
from .monitor import Monitor, Probe
from .pihole import Pihole, PiholeError
from .services import Editor, GravityRunner, PlanChanged, SyncService
from .store import DAY, Store
from .sync import RESOURCES, Change, describe, snapshot

log = logging.getLogger("twinhole")
STATIC = Path(__file__).parent / "static"

RANGES = {  # name -> (seconds back, bucket size)
    "24h": (DAY, 600),
    "7d": (7 * DAY, 3600),
    "30d": (30 * DAY, 4 * 3600),
    "1y": (365 * DAY, DAY),
    "all": (None, DAY),
}
KEY_SHAPES = {"groups": 1, "domains": 3, "lists": 2, "clients": 1, "hosts": 1, "cnames": 1}


class Twinhole:
    """Everything the app holds while running."""

    def __init__(
        self,
        settings: config.Settings,
        *,
        transports: dict[str, httpx.AsyncBaseTransport] | None = None,
        probe: Probe = dnsprobe.probe,
        notifier: Notifier | None = None,
        clock: Callable[[], float] = time.time,
    ):
        transports = transports or {}
        self.settings = settings
        self.clock = clock
        self.main = Pihole(settings.main, transport=transports.get(settings.main.id))
        self.secondary = Pihole(settings.secondary, transport=transports.get(settings.secondary.id))
        self.piholes = [self.main, self.secondary]
        self.store = Store(settings.db_path)
        if notifier is None:
            if settings.ntfy_url and settings.ntfy_topic:
                notifier = Ntfy(settings.ntfy_url, settings.ntfy_topic, settings.ntfy_token)
            else:
                notifier = NoNotifier()
        self.notifier = notifier
        self.alerts = AlertManager(self.store, notifier, clock)
        self.monitor = Monitor(settings, self.piholes, self.alerts, probe, clock)
        self.history = History(settings, self.piholes, self.store, clock)
        self.gravity = GravityRunner(self.store)
        self.sync = SyncService(settings, self.main, self.secondary, self.store, self.alerts, self.gravity)
        self.editor = Editor(self.main, self.secondary, self.store)
        self._tasks: list[asyncio.Task] = []
        self._oneoffs: set[asyncio.Task] = set()

    def spawn(self, coro: Awaitable[Any]) -> None:
        """Run a one-off background job (e.g. refresh after an edit), keeping a reference until done."""
        task = asyncio.ensure_future(coro)
        self._oneoffs.add(task)
        task.add_done_callback(self._oneoffs.discard)

    def by_target(self, target: str) -> list[Pihole]:
        if target == "both":
            return self.piholes
        found = [p for p in self.piholes if target in (p.id, p.cfg.role)]
        if not found:
            raise HTTPException(400, f"Unknown Pi-hole {target!r}")
        return found

    def start(self) -> None:
        s = self.settings
        self._tasks = [
            asyncio.create_task(_every(s.check_interval, self.monitor.run_cycle, "monitor")),
            asyncio.create_task(_every(s.history_interval, self.history.run, "history")),
            asyncio.create_task(_every(s.drift_interval, self.sync.check_drift, "drift", delay=15)),
        ]

    async def stop(self) -> None:
        tasks = [*self._tasks, *self._oneoffs]
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for p in self.piholes:
            await p.aclose()
        if isinstance(self.notifier, Ntfy):
            await self.notifier.aclose()
        self.store.close()


async def _every(seconds: int, fn: Callable[[], Awaitable[None]], name: str, delay: int = 0) -> None:
    await asyncio.sleep(delay)
    while True:
        try:
            await fn()
        except Exception:
            log.exception("%s loop failed; trying again in %ss", name, seconds)
        await asyncio.sleep(seconds)


def reliability(t: Twinhole, p: Pihole) -> dict[str, Any]:
    """Uptime over the last 30 days (from twinhole's own checks) and the last outage that recovered."""
    now = int(t.clock())
    u = t.store.uptime(now - 30 * DAY).get(p.id)
    return {
        "uptime_pct": round(100 * u["up"] / u["total"], 3) if u and u["total"] else None,
        "since": u["first"] if u else None,
        "last_outage": t.store.last_past_alert(p.id, URGENT),
    }


# --- request bodies ---------------------------------------------------------------


class ApplyBody(BaseModel):
    plan_id: str


class EditBody(BaseModel):
    resource: Literal["groups", "domains", "lists", "clients", "hosts", "cnames"]
    action: Literal["add", "update", "delete"]
    key: list[str]
    comment: str = ""
    enabled: bool = True
    groups: list[str] = Field(default_factory=lambda: ["Default"])


class BlockingBody(BaseModel):
    target: str = "both"
    enabled: bool
    minutes: int | None = Field(default=None, ge=1, le=24 * 60)


class GravityBody(BaseModel):
    target: str = "both"


def _validate_edit(body: EditBody) -> Change:
    key = tuple(k.strip() for k in body.key)
    if len(key) != KEY_SHAPES[body.resource] or not all(key):
        raise HTTPException(400, f"{body.resource} needs {KEY_SHAPES[body.resource]} key part(s)")
    if body.resource == "domains" and (key[0] not in ("allow", "deny") or key[1] not in ("exact", "regex")):
        raise HTTPException(400, "Domain type must be allow/deny and kind exact/regex")
    if body.resource == "lists" and key[0] not in ("block", "allow"):
        raise HTTPException(400, "Adlist type must be block or allow")
    if body.resource == "hosts":
        parts = key[0].split()
        if len(parts) < 2:
            raise HTTPException(400, "A local DNS record looks like '192.168.1.50 nas.lan'")
        key = (" ".join(parts),)
    if body.resource == "cnames" and len(key[0].split(",")) < 2:
        raise HTTPException(400, "A CNAME looks like 'files.lan,nas.lan'")

    if body.action == "delete":
        return Change(body.resource, "delete", key, None, None)
    if body.resource in ("hosts", "cnames"):
        if body.action == "update":
            raise HTTPException(400, "Local DNS and CNAME records can only be added or deleted")
        after: dict[str, Any] = {"raw": key[0]}
    elif body.resource == "groups":
        after = {"comment": body.comment, "enabled": body.enabled}
    elif body.resource == "clients":
        after = {"comment": body.comment, "groups": sorted(body.groups)}
    else:
        after = {"comment": body.comment, "groups": sorted(body.groups), "enabled": body.enabled}
    return Change(body.resource, body.action, key, after, None)


# --- the app ----------------------------------------------------------------------


def create_app(settings: config.Settings | None = None, *, background: bool = True, **kwargs: Any) -> FastAPI:
    settings = settings or config.load()
    if not logging.getLogger().handlers:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
        logging.getLogger("httpx").setLevel(logging.WARNING)  # one line per Pi-hole request is too chatty

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        th = Twinhole(settings, **kwargs)
        app.state.th = th
        log.info(
            "twinhole up: main %s (%s), secondary %s (%s), writes %s, ntfy %s",
            settings.main.name, settings.main.url, settings.secondary.name, settings.secondary.url,
            "ON" if settings.allow_writes else "off (read-only)",
            f"{settings.ntfy_url}/{settings.ntfy_topic}" if settings.ntfy_topic else "not configured",
        )
        if background:
            th.start()
        try:
            yield
        finally:
            await th.stop()

    app = FastAPI(title="twinhole", lifespan=lifespan, docs_url=None, redoc_url=None)

    def th() -> Twinhole:
        return app.state.th

    def require_writes() -> None:
        if not settings.allow_writes:
            raise HTTPException(
                403, "Read-only mode: set ALLOW_WRITES=true in .env and restart twinhole to make changes."
            )

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})

    @app.get("/healthz")
    async def healthz() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/api/status")
    async def status() -> dict[str, Any]:
        t = th()
        last = t.sync.last
        return {
            "now": int(t.clock()),
            "writes": settings.allow_writes,
            "piholes": [t.monitor.status[p.id] | {"reliability": reliability(t, p)} for p in t.piholes],
            "alerts": sorted(t.alerts.active.values(), key=lambda a: a["since"]),
            "sync": {k: last[k] for k in ("checked", "summary", "error", "auto")} | {"count": len(last["changes"])},
            "gravity": t.gravity.status(),
            "check_interval": settings.check_interval,
        }

    @app.get("/api/events")
    async def events(limit: int = 100) -> list[dict[str, Any]]:
        return th().store.events(min(max(limit, 1), 1000))

    @app.get("/api/history")
    async def history(range: str = "24h") -> dict[str, Any]:
        if range not in RANGES:
            raise HTTPException(400, f"range must be one of {', '.join(RANGES)}")
        t = th()
        back, step = RANGES[range]
        now = int(t.clock())
        offset = int(datetime.now(t.history.tz).utcoffset().total_seconds()) if step >= DAY else 0
        since = 0 if back is None else now - back
        series = t.store.history_series(since, step, offset)
        latency = t.store.latency_series(since, step)
        return {
            "range": range,
            "step": step,
            "piholes": [
                {"id": p.id, "name": p.name, "points": series.get(p.id, []), "latency": latency.get(p.id, [])}
                for p in t.piholes
            ],
        }

    @app.get("/api/top")
    async def top(days: int = 7, pihole: str | None = None, limit: int = 25) -> dict[str, Any]:
        t = th()
        last = t.history.day_of(t.clock()) - timedelta(days=1)
        first = last - timedelta(days=max(days, 1) - 1)
        args = (first.isoformat(), last.isoformat(), pihole or None, min(max(limit, 1), 100))
        return {
            "first_day": args[0],
            "last_day": args[1],
            "domains": t.store.top("domains", *args),
            "blocked": t.store.top("blocked", *args),
            "clients": t.store.top("clients", *args),
        }

    @app.get("/api/queries")
    async def queries(client: list[str] = Query(default=[])) -> dict[str, Any]:
        # client narrows the log to one device; Pi-hole filters on one IP per call, so a
        # device with several addresses means one call per address per Pi-hole.
        t = th()
        n = settings.query_log_size
        ips = list(dict.fromkeys(c.strip() for c in client if c.strip()))[:16] or [None]
        calls = [(p, ip) for p in t.piholes for ip in ips]
        results = await asyncio.gather(*(p.queries(n, ip) for p, ip in calls), return_exceptions=True)
        rows, errors = [], []
        for (p, _), res in zip(calls, results):
            if isinstance(res, PiholeError):
                msg = f"{p.name}: {res.message}"
                if msg not in errors:
                    errors.append(msg)
                continue
            if isinstance(res, BaseException):
                raise res
            for q in res:
                rows.append({
                    "time": q.get("time"),
                    "pihole": p.id,
                    "type": q.get("type"),
                    "domain": q.get("domain"),
                    "status": q.get("status"),
                    "client": (q.get("client") or {}).get("ip"),
                    "client_name": (q.get("client") or {}).get("name"),
                    "reply": (q.get("reply") or {}).get("type"),
                    "reply_ms": round(((q.get("reply") or {}).get("time") or 0) * 1000, 1),
                    "upstream": q.get("upstream"),
                })
        rows.sort(key=lambda r: r["time"] or 0, reverse=True)
        return {"queries": rows[:n], "errors": errors}

    @app.get("/api/devices")
    async def devices_view() -> dict[str, Any]:
        t = th()
        seen = await asyncio.gather(*(p.network_devices() for p in t.piholes), return_exceptions=True)
        per_pihole, errors = {}, []
        for p, res in zip(t.piholes, seen):
            if isinstance(res, PiholeError):
                errors.append(f"{p.name}: {res.message}")
            elif isinstance(res, BaseException):
                raise res
            else:
                per_pihole[p.id] = res
        # Group assignments come from the main Pi-hole; sync mirrors them to the secondary.
        try:
            clients, groups = await asyncio.gather(t.main.clients(), t.main.groups())
        except PiholeError as e:
            clients, groups = [], []
            errors.append(f"{t.main.name}: couldn't read groups ({e.message})")
        group_names = {g["id"]: g["name"] for g in groups}
        rows = devices.merge(per_pihole, t.clock())
        for row in rows:
            row["clients"] = devices.match_clients(row, clients, group_names)
        return {
            "now": int(t.clock()),
            "piholes": [{"id": p.id, "name": p.name} for p in t.piholes],
            "groups": sorted(group_names.values()),
            "devices": rows,
            "errors": errors,
        }

    @app.get("/api/sync")
    async def sync_state() -> dict[str, Any]:
        return th().sync.last

    @app.post("/api/sync/preview")
    async def sync_preview() -> dict[str, Any]:
        try:
            return await th().sync.preview()
        except PiholeError as e:
            raise HTTPException(502, e.message) from e

    @app.post("/api/sync/apply")
    async def sync_apply(body: ApplyBody) -> dict[str, Any]:
        require_writes()
        try:
            return await th().sync.apply(body.plan_id)
        except PlanChanged as e:
            raise HTTPException(409, str(e)) from e
        except PiholeError as e:
            raise HTTPException(502, e.message) from e

    @app.get("/api/manage")
    async def manage_view() -> dict[str, Any]:
        t = th()
        try:
            (m, _), (s, _) = await asyncio.gather(snapshot(t.main), snapshot(t.secondary))
        except PiholeError as e:
            raise HTTPException(502, e.message) from e
        out: dict[str, Any] = {"groups_available": sorted(k[0] for k in m["groups"])}
        for resource in RESOURCES:
            rows = []
            for key in sorted(set(m[resource]) | set(s[resource])):
                on_main, on_sec = key in m[resource], key in s[resource]
                props = m[resource][key] if on_main else s[resource][key]
                same = on_main and on_sec and _visible(m[resource][key]) == _visible(s[resource][key])
                rows.append({
                    "key": list(key),
                    "label": describe(resource, key),
                    **_visible(props),
                    "on_main": on_main,
                    "on_secondary": on_sec,
                    "same": same,
                })
            out[resource] = rows
        return out

    @app.post("/api/manage")
    async def manage_edit(body: EditBody) -> dict[str, Any]:
        require_writes()
        t = th()
        change = _validate_edit(body)
        results = await t.editor.edit(change)
        t.spawn(t.sync.check_drift())
        return {"results": results, "gravity_suggested": body.resource == "lists" and results[0]["ok"]}

    @app.post("/api/actions/blocking")
    async def blocking(body: BlockingBody) -> dict[str, Any]:
        require_writes()
        t = th()
        timer = body.minutes * 60 if body.minutes and not body.enabled else None
        results = []
        for p in t.by_target(body.target):
            try:
                await p.set_blocking(body.enabled, timer)
                results.append({"pihole": p.id, "ok": True, "error": None})
            except PiholeError as e:
                results.append({"pihole": p.id, "ok": False, "error": e.message})
        what = "enabled" if body.enabled else (f"paused for {body.minutes} min" if body.minutes else "disabled")
        names = ", ".join(p.name for p in t.by_target(body.target))
        t.store.add_event("action", f"Blocking {what} on {names}")
        t.spawn(t.monitor.run_cycle())
        return {"results": results}

    @app.post("/api/actions/gravity")
    async def gravity_start(body: GravityBody) -> dict[str, Any]:
        require_writes()
        t = th()
        started = {p.id: t.gravity.start(p, "started from the dashboard") for p in t.by_target(body.target)}
        return {"started": started}

    @app.get("/api/actions/gravity")
    async def gravity_status() -> dict[str, Any]:
        return th().gravity.status()

    app.mount("/static", RevalidatedStaticFiles(directory=STATIC), name="static")
    return app


class RevalidatedStaticFiles(StaticFiles):
    """Make browsers check for a newer app.js/style.css on each load (a cheap 304 when unchanged)."""

    def file_response(self, *args: Any, **kwargs: Any):
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "no-cache"
        return response


def _visible(props: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in props.items() if k not in ("raw", "id")}
