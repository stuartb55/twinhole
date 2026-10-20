"""Sync orchestration, write-through edits and gravity runs."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from typing import Any

from .alerts import DEFAULT, AlertManager
from .config import Settings
from .pihole import Pihole, PiholeError
from .store import Store
from .sync import Change, apply, apply_change, norm_cname, norm_host, plan, plan_id, snapshot, summarize

log = logging.getLogger(__name__)


class PlanChanged(Exception):
    """The Pi-holes changed between preview and Apply."""


class GravityRunner:
    def __init__(self, store: Store):
        self.store = store
        self.runs: dict[str, dict[str, Any]] = {}
        self._tasks: set[asyncio.Task] = set()

    def status(self) -> dict[str, dict[str, Any]]:
        return {pid: {**run, "log": list(run["log"])} for pid, run in self.runs.items()}

    def running(self, p: Pihole) -> bool:
        return bool(self.runs.get(p.id, {}).get("running"))

    def start(self, p: Pihole, reason: str) -> bool:
        if self.running(p):
            return False
        self.runs[p.id] = {
            "running": True, "started": int(time.time()), "finished": None,
            "ok": None, "error": None, "reason": reason, "log": deque(maxlen=400),
        }
        task = asyncio.create_task(self._run(p))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return True

    async def _run(self, p: Pihole) -> None:
        run = self.runs[p.id]
        self.store.add_event("action", f"Gravity started on {p.name} ({run['reason']})", p.id)
        try:
            async for line in p.run_gravity():
                run["log"].append(line)
            run["ok"] = True
            self.store.add_event("action", f"Gravity finished on {p.name}", p.id)
        except PiholeError as e:
            run["ok"], run["error"] = False, e.message
            self.store.add_event("action", f"Gravity failed on {p.name}: {e.message}", p.id)
        finally:
            run["running"], run["finished"] = False, int(time.time())


class SyncService:
    def __init__(
        self,
        settings: Settings,
        main: Pihole,
        secondary: Pihole,
        store: Store,
        alerts: AlertManager,
        gravity: GravityRunner,
    ):
        self.settings = settings
        self.main = main
        self.secondary = secondary
        self.store = store
        self.alerts = alerts
        self.gravity = gravity
        self._lock = asyncio.Lock()
        self.last: dict[str, Any] = {"checked": None, "plan_id": None, "summary": None, "changes": [], "error": None}

    async def _compute(self) -> tuple[list[Change], dict[str, int]]:
        try:
            (want, _), (have, group_ids) = await asyncio.gather(snapshot(self.main), snapshot(self.secondary))
        except PiholeError as e:
            self.last = {**self.last, "checked": int(time.time()), "error": e.message}
            raise
        changes = plan(want, have)
        self.last = {
            "checked": int(time.time()),
            "plan_id": plan_id(changes),
            "summary": summarize(changes),
            "changes": [c.as_dict() for c in changes],
            "error": None,
        }
        await self._observe_drift(changes)
        return changes, group_ids

    async def _observe_drift(self, changes: list[Change]) -> None:
        await self.alerts.observe(
            "sync:drift", bool(changes), pihole=None,
            title="Pi-holes out of sync",
            detail=f"{self.secondary.name} differs from {self.main.name}: {summarize(changes)}. "
            "Review it on the twinhole Sync page.",
            priority=DEFAULT, after_seconds=self.settings.drift_grace,
            recovered_detail="Both Pi-holes match again",
        )

    async def preview(self) -> dict[str, Any]:
        async with self._lock:
            await self._compute()
            return self.last

    async def check_drift(self) -> None:
        async with self._lock:
            try:
                await self._compute()
            except PiholeError as e:
                log.info("drift check skipped: %s", e)

    async def apply(self, expected_plan_id: str) -> dict[str, Any]:
        async with self._lock:
            changes, group_ids = await self._compute()
            if plan_id(changes) != expected_plan_id:
                raise PlanChanged("The Pi-holes changed since the preview. Review the new preview and apply again.")
            if not changes:
                return {"results": [], "gravity_started": False, "after": self.last}
            results = await apply(self.secondary, changes, group_ids)
            failed = sum(1 for r in results if not r["ok"])
            message = f"Synced {self.secondary.name} from {self.main.name}: {summarize(changes)}"
            if failed:
                message += f" ({failed} failed)"
            self.store.add_event("sync", message, self.secondary.id)
            gravity_started = False
            if any(r["resource"] == "lists" and r["ok"] for r in results):
                gravity_started = self.gravity.start(self.secondary, "adlists changed by sync")
            try:
                await self._compute()
            except PiholeError:
                pass
            return {"results": results, "gravity_started": gravity_started, "after": self.last}


class Editor:
    """Edits from the dashboard: main Pi-hole first, then the same change on the secondary."""

    def __init__(self, main: Pihole, secondary: Pihole, store: Store):
        self.main = main
        self.secondary = secondary
        self.store = store

    async def edit(self, change: Change) -> list[dict[str, Any]]:
        results = []
        for p in (self.main, self.secondary):
            try:
                await self._edit_one(p, change)
                results.append({"pihole": p.id, "name": p.name, "ok": True, "error": None})
            except PiholeError as e:
                results.append({"pihole": p.id, "name": p.name, "ok": False, "error": e.message})
                if p is self.main:
                    break  # don't change the secondary if the main Pi-hole refused
        verb = {"add": "Added", "update": "Updated", "delete": "Deleted"}[change.action]
        outcome = ", ".join(f"{r['name']} {'ok' if r['ok'] else 'failed: ' + r['error']}" for r in results)
        self.store.add_event("action", f"{verb} {change.label}: {outcome}")
        return results

    async def _edit_one(self, p: Pihole, change: Change) -> None:
        group_ids = {g["name"]: g["id"] for g in await p.groups()}
        wanted = (change.after or {}).get("groups") or []
        if p is self.secondary and any(name not in group_ids for name in wanted):
            group_ids = await self._copy_groups(wanted, group_ids)
        if change.action == "delete" and change.resource in ("hosts", "cnames"):
            change = await self._with_raw_entry(p, change)
        try:
            await apply_change(p, change, group_ids)
        except PiholeError as e:
            if change.action == "delete" and e.status == 404:
                return  # already absent on this Pi-hole
            if change.action == "add" and "already present" in e.message.lower():
                await apply_change(p, Change(change.resource, "update", change.key, change.after, None), group_ids)
                return
            raise

    async def _copy_groups(self, names: list[str], have: dict[str, int]) -> dict[str, int]:
        """Create groups the secondary doesn't have yet, copied from the main (e.g. made in Pi-hole's own UI)."""
        main_groups = {g["name"]: g for g in await self.main.groups()}
        for name in names:
            if name not in have and name in main_groups:
                g = main_groups[name]
                await self.secondary.add_group(name, g.get("comment"), bool(g.get("enabled", True)))
        return {g["name"]: g["id"] for g in await self.secondary.groups()}

    async def _with_raw_entry(self, p: Pihole, change: Change) -> Change:
        """Local DNS entries must be deleted by their exact stored text, which can differ in spacing."""
        entries, norm = (await p.hosts(), norm_host) if change.resource == "hosts" else (await p.cnames(), norm_cname)
        raw = next((e for e in entries if norm(e) == change.key[0]), change.key[0])
        return Change(change.resource, "delete", change.key, None, {"raw": raw})
