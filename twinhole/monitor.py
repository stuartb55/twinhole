"""Health checks every CHECK_INTERVAL: API, DNS over IPv4/IPv6, blocking state, gravity age.

Less often it also checks the resolver behind each Pi-hole (Unbound, say): a lookup of a
random name that can't be cached proves it really recurses, and a lookup of a domain with
deliberately broken DNSSEC, which must fail, proves it validates.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import secrets
import time
from collections.abc import Awaitable, Callable
from typing import Any

from . import dnsprobe
from .alerts import DEFAULT, LOW, URGENT, AlertManager
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


def _upstreams(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Real upstream servers (not Pi-hole's cache or blocklist, which have port -1), busiest first."""
    out = []
    for u in raw:
        if (u.get("port") or -1) < 0:
            continue
        stats = u.get("statistics") or {}
        out.append({
            "server": f"{u.get('ip') or u.get('name')}#{u['port']}",
            "name": u.get("name") or u.get("ip"),
            "count": u.get("count") or 0,
            "ms": round((stats.get("response") or 0) * 1000, 1),
        })
    return sorted(out, key=lambda u: -u["count"])


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
        self._recursion_due: dict[str, float] = {}
        self._dnssec_due: dict[str, float] = {}
        self._ipv6: dict[str, str | None] = {}
        self.started = clock()
        self.last_cycle: float | None = None
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
                "resolver": {"recursion": None, "dnssec": None, "upstreams": None},
            }
            for p in piholes
        }

    async def run_cycle(self) -> None:
        await asyncio.gather(*(self._check(p) for p in self.piholes))
        self.last_cycle = self.clock()

    def stalled(self) -> bool:
        """True when no check cycle has finished for a while, e.g. the loop is stuck."""
        last = self.last_cycle or self.started
        return self.clock() - last > max(3 * self.settings.check_interval, 120)

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
        if api_error is None:
            try:
                st["resolver"]["upstreams"] = _upstreams(await p.upstreams())
            except PiholeError as e:
                log.info("upstream stats failed for %s: %s", p.name, e)

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
        rec_ms = await self._check_resolver(p, now, r4)
        self.alerts.store.record_check(
            p.id, int(now), api_error is None and r4.ok, r4.ms if r4.ok else None, rec_ms
        )

    def _due(self, due: dict[str, float], p: Pihole, now: float, interval: int) -> bool:
        if interval <= 0 or now < due.get(p.id, 0):
            return False
        due[p.id] = now + interval
        return True

    async def _check_resolver(self, p: Pihole, now: float, r4: dnsprobe.ProbeResult) -> float | None:
        """Run the resolver checks that are due. Returns the recursion check's reply time, if one ran and worked."""
        s, a, st = self.settings, self.alerts, self.status[p.id]["resolver"]
        rec_ms = None
        if not r4.ok:
            return None  # the DNS alert already covers a Pi-hole that doesn't answer at all

        if self._due(self._recursion_due, p, now, s.recursion_interval):
            name = f"twinhole-{secrets.token_hex(4)}.{s.dns_probe_domain}"
            r = await self.probe(p.cfg.dns_host, p.cfg.dns_port, name, s.recursion_timeout)
            # NXDOMAIN is the right answer: it came from the domain's own servers, so the
            # resolver went out and asked.
            ok = r.rcode in ("NOERROR", "NXDOMAIN")
            rec_ms = r.ms if ok else None
            st["recursion"] = {"ok": ok, "ms": None if r.ms is None else round(r.ms, 1),
                               "error": None if ok else r.error, "checked": int(now)}
            await a.observe(
                f"{p.id}:recursion", not ok, pihole=p.id,
                title=f"{p.name} can't resolve new names",
                detail=f"A lookup that has to go past Pi-hole's cache failed ({r.error}). "
                "Its upstream resolver (Unbound?) may be down.",
                priority=URGENT, after_count=s.fail_threshold,
                recovered_detail="Its resolver is answering new lookups again",
            )

        if self._due(self._dnssec_due, p, now, s.dnssec_interval):
            r = await self.probe(p.cfg.dns_host, p.cfg.dns_port, s.dnssec_probe_domain, s.recursion_timeout)
            # A validating resolver refuses this domain with SERVFAIL. An answer means it
            # isn't validating; anything else (a timeout, say) tells us nothing.
            validating = True if r.rcode == "SERVFAIL" else False if r.ok else None
            st["dnssec"] = {"ok": validating, "checked": int(now),
                            "detail": {True: "validating", False: "not validating"}.get(validating, r.error)}
            await a.observe(
                f"{p.id}:dnssec", None if validating is None else not validating, pihole=p.id,
                title=f"{p.name} isn't validating DNSSEC",
                detail=f"{s.dnssec_probe_domain} has broken DNSSEC on purpose and should fail, but it "
                "resolved. Check the resolver's DNSSEC settings and trust anchor.",
                priority=DEFAULT, recovered_detail="DNSSEC validation is working again",
            )
        return rec_ms

    async def _slow_refresh(self, p: Pihole, st: dict[str, Any]) -> None:
        try:
            st["versions"] = _versions(await p.version())
        except PiholeError as e:
            log.info("version check failed for %s: %s", p.name, e)
        else:
            v = st["versions"]
            updates = [f"{'FTL' if k == 'ftl' else k.title()} {v[k]['local']} → {v[k]['remote']}" for k in v if v[k]["update"]]
            await self.alerts.observe(
                f"{p.id}:update", bool(updates), pihole=p.id,
                title=f"{p.name} has a Pi-hole update",
                detail=", ".join(updates) + ". Update it with `pihole -up` (or pull a new image).",
                priority=LOW, recovered_detail="Up to date",
            )
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
