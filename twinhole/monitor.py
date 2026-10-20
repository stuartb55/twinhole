"""Health checks every CHECK_INTERVAL: API, DNS over IPv4/IPv6, blocking state, gravity age."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

from . import dnsprobe
from .alerts import DEFAULT, URGENT, AlertManager
from .config import Settings
from .pihole import Pihole, PiholeError

log = logging.getLogger(__name__)

SLOW_REFRESH = 600  # versions and the IPv6 address change rarely

Probe = Callable[[str, int, str, float], Awaitable[dnsprobe.ProbeResult]]


def pick_ipv6(interfaces: list[dict[str, Any]], ipv4: str) -> str | None:
    """The stable global IPv6 address on the interface that holds `ipv4`, if any."""
    for iface in interfaces:
        addrs = iface.get("addresses") or []
        if not any(a.get("family") == "inet" and a.get("address") == ipv4 for a in addrs):
            continue
        candidates = []
        for a in addrs:
            flags = set(a.get("flags") or [])
            if a.get("family") != "inet6" or a.get("scope") != "universe":
                continue
            if flags & {"temporary", "deprecated", "tentative", "dadfailed"}:
                continue
            try:
                ip = ipaddress.IPv6Address(a["address"])
            except ValueError:
                continue
            # Prefer globally routable addresses over ULAs (fc00::/7).
            candidates.append((ip.is_private, a["address"]))
        if candidates:
            return sorted(candidates)[0][1]
    return None


def _versions(raw: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for part in ("core", "web", "ftl"):
        info = raw.get(part) or {}
        local = (info.get("local") or {}).get("version")
        remote = (info.get("remote") or {}).get("version")
        out[part] = {"local": local, "remote": remote, "update": bool(local and remote and local != remote)}
    return out


class Monitor:
    def __init__(
        self,
        settings: Settings,
        piholes: list[Pihole],
        alerts: AlertManager,
        probe: Probe = dnsprobe.probe,
        clock: Callable[[], float] = time.time,
    ):
        self.settings = settings
        self.piholes = piholes
        self.alerts = alerts
        self.probe = probe
        self.clock = clock
        self._slow_due: dict[str, float] = {}
        self._ipv6: dict[str, str | None] = {}
        self.status: dict[str, dict[str, Any]] = {
            p.id: {
                "id": p.id,
                "name": p.name,
                "role": p.cfg.role,
                "url": p.cfg.url,
                "checked": None,
                "api": {"ok": None, "error": None},
                "dns": {"v4": None, "v6": None},
                "blocking": None,
                "blocking_timer": None,
                "gravity": None,
                "summary": None,
                "versions": None,
            }
            for p in piholes
        }

    async def run_cycle(self) -> None:
        await asyncio.gather(*(self._check(p) for p in self.piholes))

    def _ipv6_target(self, p: Pihole) -> str | None:
        if p.cfg.ipv6 == "off":
            return None
        if p.cfg.ipv6 == "auto":
            return self._ipv6.get(p.id)
        return p.cfg.ipv6

    async def _check(self, p: Pihole) -> None:
        s = self.settings
        now = self.clock()
        st = self.status[p.id]

        summary = blocking = None
        try:
            summary, blocking = await asyncio.gather(p.summary(), p.blocking())
            api_error = None
        except PiholeError as e:
            api_error = e.message

        if api_error is None and now >= self._slow_due.get(p.id, 0):
            await self._slow_refresh(p, st)
            self._slow_due[p.id] = now + SLOW_REFRESH

        v6 = self._ipv6_target(p)
        probes = [self.probe(p.cfg.dns_host, p.cfg.dns_port, s.dns_probe_domain, s.dns_timeout)]
        if v6:
            probes.append(self.probe(v6, p.cfg.dns_port, s.dns_probe_domain, s.dns_timeout))
        results = await asyncio.gather(*probes)
        r4 = results[0]
        r6 = results[1] if v6 else None

        st["checked"] = int(now)
        st["api"] = {"ok": api_error is None, "error": api_error}
        st["dns"] = {"v4": _probe_dict(r4), "v6": _probe_dict(r6) if r6 else None}
        if summary is not None and blocking is not None:
            q = summary.get("queries", {})
            st["summary"] = {
                "total": q.get("total"),
                "blocked": q.get("blocked"),
                "percent_blocked": q.get("percent_blocked"),
                "cached": q.get("cached"),
                "forwarded": q.get("forwarded"),
                "clients_active": (summary.get("clients") or {}).get("active"),
            }
            st["gravity"] = summary.get("gravity")
            st["blocking"] = blocking.get("blocking")
            st["blocking_timer"] = blocking.get("timer")

        await self._evaluate(p, now, api_error, r4, r6, summary, blocking)

    async def _slow_refresh(self, p: Pihole, st: dict[str, Any]) -> None:
        try:
            st["versions"] = _versions(await p.version())
        except PiholeError as e:
            log.info("version check failed for %s: %s", p.name, e)
        if p.cfg.ipv6 == "auto":
            try:
                self._ipv6[p.id] = pick_ipv6(await p.interfaces(), p.cfg.dns_host)
            except PiholeError as e:
                log.info("interface lookup failed for %s: %s", p.name, e)

    async def _evaluate(self, p, now, api_error, r4, r6, summary, blocking) -> None:
        s, a, name = self.settings, self.alerts, p.name
        await a.observe(
            f"{p.id}:api", api_error is not None, pihole=p.id,
            title=f"{name} is unreachable", detail=f"API not answering: {api_error}",
            priority=URGENT, after_count=s.fail_threshold, recovered_detail="API answering again",
        )
        await a.observe(
            f"{p.id}:dns4", not r4.ok, pihole=p.id,
            title=f"{name} DNS failing (IPv4)",
            detail=f"Lookup of {s.dns_probe_domain} via {r4.server}: {r4.error}",
            priority=URGENT, after_count=s.fail_threshold,
            recovered_detail=f"Resolving via {r4.server} again",
        )
        await a.observe(
            f"{p.id}:dns6", None if r6 is None else not r6.ok, pihole=p.id,
            title=f"{name} DNS failing (IPv6)",
            detail=f"Lookup of {s.dns_probe_domain} via {r6.server}: {r6.error}" if r6 else "",
            priority=URGENT, after_count=s.fail_threshold,
            recovered_detail=f"Resolving via {r6.server} again" if r6 else "",
        )

        blocking_off = None if blocking is None else blocking.get("blocking") != "enabled"
        timer = (blocking or {}).get("timer")
        await a.observe(
            f"{p.id}:blocking", blocking_off, pihole=p.id,
            title=f"{name} blocking is off",
            detail=f"Ad blocking has been {(blocking or {}).get('blocking', 'off')} for over "
            f"{s.blocking_grace // 60} min" + (f"; it re-enables in {int(timer) // 60} min" if timer else ""),
            priority=DEFAULT, after_seconds=s.blocking_grace, recovered_detail="Blocking enabled again",
        )

        gravity_stale = None
        age_days = 0
        if summary is not None:
            last = (summary.get("gravity") or {}).get("last_update")
            if last:
                age_days = (now - last) / 86400
                gravity_stale = now - last > s.gravity_max_age
        await a.observe(
            f"{p.id}:gravity", gravity_stale, pihole=p.id,
            title=f"{name} gravity is stale",
            detail=f"Blocklists last updated {age_days:.0f} days ago",
            priority=DEFAULT, recovered_detail="Blocklists updated",
        )


def _probe_dict(r: dnsprobe.ProbeResult) -> dict[str, Any]:
    return {"server": r.server, "ok": r.ok, "ms": None if r.ms is None else round(r.ms, 1), "error": r.error}
