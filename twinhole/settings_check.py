"""Compare the two Pi-holes' DNS settings and alert when they differ.

Sync copies lists and records, not settings, so a changed upstream or DNSSEC switch on
one Pi-hole would otherwise go unnoticed. This only compares; it never changes anything.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from typing import Any

from .alerts import DEFAULT, AlertManager
from .config import Settings
from .pihole import Pihole, PiholeError

log = logging.getLogger(__name__)

# Settings that should be the same on both Pi-holes: (path in Pi-hole's config, label).
# Left out on purpose: anything tied to one machine (interfaces, ports, block reply
# addresses, DHCP, web server), local DNS records (sync copies those) and blocking state.
COMPARED: list[tuple[str, str]] = [
    ("dns.upstreams", "Upstream DNS servers"),
    ("dns.dnssec", "DNSSEC validation"),
    ("dns.revServers", "Conditional forwarding"),
    ("dns.domainNeeded", "Never forward non-FQDN names"),
    ("dns.bogusPriv", "Never forward reverse lookups for private ranges"),
    ("dns.expandHosts", "Expand host names"),
    ("dns.domain.name", "Local domain name"),
    ("dns.domain.local", "Local domain answered locally only"),
    ("dns.listeningMode", "Listening mode"),
    ("dns.queryLogging", "Query logging"),
    ("dns.cache.size", "Cache size"),
    ("dns.cache.optimizer", "Cache optimizer (seconds)"),
    ("dns.cache.upstreamBlockedTTL", "Cache time for upstream-blocked replies"),
    ("dns.blocking.mode", "Blocking mode"),
    ("dns.blocking.edns", "Blocking EDNS mode"),
    ("dns.blockTTL", "Blocked reply TTL"),
    ("dns.rateLimit.count", "Rate limit (queries)"),
    ("dns.rateLimit.interval", "Rate limit (seconds)"),
    ("dns.CNAMEdeepInspect", "Deep CNAME inspection"),
    ("dns.blockESNI", "Block ESNI"),
    ("dns.EDNS0ECS", "Use EDNS(0) client subnet"),
    ("dns.ignoreLocalhost", "Ignore queries from localhost"),
    ("dns.specialDomains.mozillaCanary", "Mozilla canary domain"),
    ("dns.specialDomains.iCloudPrivateRelay", "iCloud Private Relay domains"),
    ("dns.specialDomains.designatedResolver", "Designated resolver domain"),
    ("dns.replyWhenBusy", "Reply when busy"),
    ("dns.piholePTR", "Pi-hole PTR reply"),
    ("misc.privacylevel", "Privacy level"),
    ("misc.etc_dnsmasq_d", "Load /etc/dnsmasq.d"),
    ("misc.dnsmasq_lines", "Custom dnsmasq lines"),
    ("database.maxDBdays", "Query database retention (days)"),
]
UNORDERED = {"dns.upstreams", "dns.revServers"}  # order makes no difference to Pi-hole
_MISSING = object()


def _get(cfg: dict[str, Any], path: str) -> Any:
    node: Any = cfg
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return _MISSING
        node = node[part]
    return node


def _norm(path: str, value: Any) -> Any:
    if isinstance(value, str):
        value = value.strip()
    if path in UNORDERED and isinstance(value, list):
        return sorted(value, key=str)
    return value


def compare(main: dict[str, Any], secondary: dict[str, Any], ignore: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    """One row per compared setting that either Pi-hole has, with `same` set."""
    rows = []
    for path, label in COMPARED:
        if path in ignore or any(path.startswith(i + ".") for i in ignore):
            continue
        a, b = _get(main, path), _get(secondary, path)
        if a is _MISSING and b is _MISSING:
            continue  # neither Pi-hole's version has this setting
        a, b = (None if v is _MISSING else v for v in (a, b))
        rows.append({"path": path, "label": label, "main": a, "secondary": b, "same": _norm(path, a) == _norm(path, b)})
    return rows


class SettingsCheck:
    def __init__(
        self,
        settings: Settings,
        main: Pihole,
        secondary: Pihole,
        alerts: AlertManager,
        clock: Callable[[], float] = time.time,
    ):
        self.settings = settings
        self.main = main
        self.secondary = secondary
        self.alerts = alerts
        self.clock = clock
        self._lock = asyncio.Lock()
        self.last: dict[str, Any] = {"checked": None, "error": None, "rows": [], "differences": 0}

    async def run(self) -> dict[str, Any]:
        async with self._lock:
            try:
                a, b = await asyncio.gather(self.main.config(), self.secondary.config())
            except PiholeError as e:
                log.info("settings check skipped: %s", e)
                self.last = {**self.last, "checked": int(self.clock()), "error": e.message}
                return self.last  # can't tell, so the alert stays as it is
            rows = compare(a, b, self.settings.settings_ignore)
            differ = [r for r in rows if not r["same"]]
            self.last = {"checked": int(self.clock()), "error": None, "rows": rows, "differences": len(differ)}
            await self.alerts.observe(
                "settings:drift", bool(differ), pihole=None,
                title="Pi-hole settings differ",
                detail=f"{self.secondary.name} and {self.main.name} have different settings: "
                + "; ".join(f"{r['label']} ({_show(r['main'])} vs {_show(r['secondary'])})" for r in differ[:5])
                + (f"; and {len(differ) - 5} more" if len(differ) > 5 else "")
                + ". Compare them on the twinhole Sync page.",
                priority=DEFAULT, after_seconds=self.settings.drift_grace,
                recovered_detail="Both Pi-holes have the same settings again",
            )
            return self.last


def _show(value: Any) -> str:
    if value is None:
        return "not set"
    if isinstance(value, bool):
        return "on" if value else "off"
    if isinstance(value, list):
        return ", ".join(map(str, value)) or "none"
    return str(value) if value != "" else "empty"
