"""Async client for the Pi-hole v6 REST API.

Both Pi-holes are passwordless, so no session (SID) handling is needed.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import quote

import httpx

from .config import PiholeConfig

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


class PiholeError(Exception):
    def __init__(self, pihole: str, message: str, status: int | None = None):
        super().__init__(f"{pihole}: {message}")
        self.message = message
        self.status = status


def _seg(value: str) -> str:
    """Percent-encode one path segment (regexes, URLs and 'ip host' entries all need it)."""
    return quote(value, safe="")


class Pihole:
    # Waiting out FTL restarts: how often to look, how long a restart takes to begin, and the limit.
    settle_poll = 0.25
    settle_window = 4.0
    settle_timeout = 30.0

    def __init__(
        self,
        cfg: PiholeConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 10.0,
    ):
        self.cfg = cfg
        self._http = httpx.AsyncClient(
            base_url=cfg.url + "/api",
            timeout=timeout,
            transport=transport,
            follow_redirects=False,
            # Pi-hole's web server drops idle keep-alive connections without warning, and
            # reusing one fails with "Server disconnected". A fresh connection per call is cheap on a LAN.
            limits=httpx.Limits(max_keepalive_connections=0),
        )

    @property
    def id(self) -> str:
        return self.cfg.id

    @property
    def name(self) -> str:
        return self.cfg.name

    async def aclose(self) -> None:
        await self._http.aclose()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        kwargs: dict[str, Any] = {"params": params, "json": json}
        if timeout is not None:
            kwargs["timeout"] = timeout
        try:
            r = await self._http.request(method, path, **kwargs)
        except httpx.HTTPError as e:
            raise PiholeError(self.name, str(e) or type(e).__name__) from e
        if r.status_code == 204:
            return {}
        try:
            body = r.json()
        except ValueError:
            body = {}
        if r.status_code >= 400:
            err = body.get("error") if isinstance(body, dict) else None
            message = (err or {}).get("message") or f"HTTP {r.status_code}"
            hint = (err or {}).get("hint")
            if r.status_code == 404 and not err:
                message = "not found"
            raise PiholeError(self.name, f"{message}: {hint}" if hint else message, r.status_code)
        processed = body.get("processed") if isinstance(body, dict) else None
        if processed and processed.get("errors"):
            errors = "; ".join(f"{e.get('item')}: {e.get('error')}" for e in processed["errors"])
            raise PiholeError(self.name, errors, r.status_code)
        return body

    # --- read -------------------------------------------------------------

    async def summary(self) -> dict[str, Any]:
        return await self._request("GET", "/stats/summary")

    async def blocking(self) -> dict[str, Any]:
        return await self._request("GET", "/dns/blocking")

    async def version(self) -> dict[str, Any]:
        return (await self._request("GET", "/info/version"))["version"]

    async def interfaces(self) -> list[dict[str, Any]]:
        return (await self._request("GET", "/network/interfaces"))["interfaces"]

    async def history(self) -> list[dict[str, Any]]:
        return (await self._request("GET", "/history"))["history"]

    async def history_database(self, start: int, until: int) -> list[dict[str, Any]]:
        params = {"from": start, "until": until}
        return (await self._request("GET", "/history/database", params=params, timeout=120))["history"]

    async def top_domains_database(
        self, start: int, until: int, *, blocked: bool, count: int
    ) -> list[dict[str, Any]]:
        params = {"from": start, "until": until, "blocked": str(blocked).lower(), "count": count}
        return (await self._request("GET", "/stats/database/top_domains", params=params, timeout=60))["domains"]

    async def top_clients_database(self, start: int, until: int, *, count: int) -> list[dict[str, Any]]:
        params = {"from": start, "until": until, "count": count}
        return (await self._request("GET", "/stats/database/top_clients", params=params, timeout=60))["clients"]

    async def network_devices(self) -> list[dict[str, Any]]:
        params = {"max_devices": 1000, "max_addresses": 25}
        return (await self._request("GET", "/network/devices", params=params, timeout=30))["devices"]

    async def queries(self, length: int, client_ip: str | None = None) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"length": length}
        if client_ip:
            params["client_ip"] = client_ip
        return (await self._request("GET", "/queries", params=params))["queries"]

    async def groups(self) -> list[dict[str, Any]]:
        return (await self._request("GET", "/groups"))["groups"]

    async def domains(self) -> list[dict[str, Any]]:
        return (await self._request("GET", "/domains"))["domains"]

    async def lists(self) -> list[dict[str, Any]]:
        return (await self._request("GET", "/lists"))["lists"]

    async def clients(self) -> list[dict[str, Any]]:
        return (await self._request("GET", "/clients"))["clients"]

    async def hosts(self) -> list[str]:
        return (await self._request("GET", "/config/dns/hosts"))["config"]["dns"]["hosts"]

    async def cnames(self) -> list[str]:
        return (await self._request("GET", "/config/dns/cnameRecords"))["config"]["dns"]["cnameRecords"]

    # --- write ------------------------------------------------------------

    async def set_blocking(self, enabled: bool, timer: int | None = None) -> dict[str, Any]:
        return await self._request("POST", "/dns/blocking", json={"blocking": enabled, "timer": timer})

    async def add_group(self, name: str, comment: str | None, enabled: bool) -> None:
        await self._request("POST", "/groups", json={"name": name, "comment": comment, "enabled": enabled})

    async def update_group(self, name: str, comment: str | None, enabled: bool) -> None:
        body = {"name": name, "comment": comment, "enabled": enabled}
        await self._request("PUT", f"/groups/{_seg(name)}", json=body)

    async def delete_group(self, name: str) -> None:
        await self._request("DELETE", f"/groups/{_seg(name)}")

    async def add_domain(
        self, type_: str, kind: str, domain: str, comment: str | None, groups: list[int], enabled: bool
    ) -> None:
        body = {"domain": domain, "comment": comment, "groups": groups, "enabled": enabled}
        await self._request("POST", f"/domains/{type_}/{kind}", json=body)

    async def update_domain(
        self, type_: str, kind: str, domain: str, comment: str | None, groups: list[int], enabled: bool
    ) -> None:
        body = {"type": type_, "kind": kind, "comment": comment, "groups": groups, "enabled": enabled}
        await self._request("PUT", f"/domains/{type_}/{kind}/{_seg(domain)}", json=body)

    async def delete_domain(self, type_: str, kind: str, domain: str) -> None:
        await self._request("DELETE", f"/domains/{type_}/{kind}/{_seg(domain)}")

    async def add_list(
        self, type_: str, address: str, comment: str | None, groups: list[int], enabled: bool
    ) -> None:
        body = {"address": address, "comment": comment, "groups": groups, "enabled": enabled}
        await self._request("POST", "/lists", params={"type": type_}, json=body)

    async def update_list(
        self, type_: str, address: str, comment: str | None, groups: list[int], enabled: bool
    ) -> None:
        body = {"comment": comment, "groups": groups, "enabled": enabled, "type": type_}
        await self._request("PUT", f"/lists/{_seg(address)}", params={"type": type_}, json=body)

    async def delete_list(self, type_: str, address: str) -> None:
        await self._request("DELETE", f"/lists/{_seg(address)}", params={"type": type_})

    async def add_client(self, client: str, comment: str | None, groups: list[int]) -> None:
        await self._request("POST", "/clients", json={"client": client, "comment": comment, "groups": groups})

    async def update_client(self, client: str, comment: str | None, groups: list[int]) -> None:
        await self._request("PUT", f"/clients/{_seg(client)}", json={"comment": comment, "groups": groups})

    async def delete_client(self, client: str) -> None:
        await self._request("DELETE", f"/clients/{_seg(client)}")

    # Any change to local DNS or CNAME records makes FTL restart itself (web and DNS are
    # down for about a second), so each of these waits for it to come back.

    async def add_host(self, entry: str) -> None:
        await self._request("PUT", f"/config/dns/hosts/{_seg(entry)}")
        await self._settle()

    async def delete_host(self, entry: str) -> None:
        await self._request("DELETE", f"/config/dns/hosts/{_seg(entry)}")
        await self._settle()

    async def add_cname(self, entry: str) -> None:
        await self._request("PUT", f"/config/dns/cnameRecords/{_seg(entry)}")
        await self._settle()

    async def delete_cname(self, entry: str) -> None:
        await self._request("DELETE", f"/config/dns/cnameRecords/{_seg(entry)}")
        await self._settle()

    async def set_dns_records(self, hosts: list[str], cnames: list[str]) -> None:
        """Replace all local DNS and CNAME records at once: one FTL restart instead of one per record."""
        await self._request("PATCH", "/config", json={"config": {"dns": {"hosts": hosts, "cnameRecords": cnames}}})
        await self._settle()

    async def _settle(self) -> None:
        """Wait out the FTL restart a config change triggers: spot it going down, then wait for it back."""
        restart_window, timeout = self.settle_window, self.settle_timeout
        start = time.monotonic()
        went_down = False
        while time.monotonic() - start < timeout:
            try:
                r = await self._http.get("/info/login", timeout=1.0)
                up = r.status_code < 500
            except httpx.HTTPError:
                up = False
            if not up:
                went_down = True
            elif went_down or time.monotonic() - start > restart_window:
                return
            await asyncio.sleep(self.settle_poll)
        raise PiholeError(self.name, f"didn't come back within {timeout:.0f}s after a DNS config change")

    async def run_gravity(self) -> AsyncIterator[str]:
        """Run gravity and yield its output line by line (ANSI colours stripped)."""
        try:
            async with self._http.stream("POST", "/action/gravity", timeout=None) as r:
                if r.status_code >= 400:
                    await r.aread()
                    raise PiholeError(self.name, f"gravity failed: HTTP {r.status_code}", r.status_code)
                async for line in r.aiter_lines():
                    # Progress updates rewrite the line with \r; keep the final state.
                    text = ANSI.sub("", line).split("\r")[-1].rstrip()
                    if text:
                        yield text
        except httpx.HTTPError as e:
            raise PiholeError(self.name, str(e) or type(e).__name__) from e
