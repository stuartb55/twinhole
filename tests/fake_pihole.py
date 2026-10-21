"""An in-memory stand-in for the Pi-hole v6 API, served through httpx.MockTransport.

It mirrors the behaviour checked against real Pi-hole containers in tests/integration.
"""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import unquote

import httpx


def _err(status: int, key: str, message: str, hint: str | None = None) -> httpx.Response:
    return httpx.Response(status, json={"error": {"key": key, "message": message, "hint": hint}, "took": 0})


DUPLICATE = ("database_error", "Could not add to gravity database", "The item is already present")


class FakePihole:
    def __init__(self, ipv4: str = "192.168.1.118", ipv6: str | None = "2a00::118"):
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.down = False
        self.blocking = "enabled"
        self.blocking_timer: int | None = None
        self.gravity_last_update = int(time.time()) - 86400
        self.next_id = 1
        self.groups: dict[str, dict[str, Any]] = {
            "Default": {"name": "Default", "comment": "The default group", "enabled": True, "id": 0}
        }
        self.domains: dict[tuple[str, str, str], dict[str, Any]] = {}
        self.lists: dict[tuple[str, str], dict[str, Any]] = {}
        self.clients: dict[str, dict[str, Any]] = {}
        self.hosts: list[str] = []
        self.cnames: list[str] = []
        self.history: list[dict[str, int]] = []
        self.history_db: list[dict[str, int]] = []
        self.query_log: list[dict[str, Any]] = []
        self.devices: list[dict[str, Any]] = []  # the network table
        self.top: dict[str, list[dict[str, Any]]] = {"domains": [], "blocked": [], "clients": []}
        self.calls: list[tuple[str, str]] = []
        self.restarts = 0  # FTL restarts caused by local DNS / CNAME changes

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def _id(self) -> int:
        self.next_id += 1
        return self.next_id

    def group_ids(self, names: list[str]) -> list[int]:
        return [self.groups[n]["id"] for n in names]

    # --- seeding helpers --------------------------------------------------------

    def add_group(self, name: str, comment: str = "", enabled: bool = True) -> None:
        self.groups[name] = {"name": name, "comment": comment, "enabled": enabled, "id": self._id()}

    def add_domain(self, type_, kind, domain, comment=None, groups=("Default",), enabled=True) -> None:
        self.domains[(type_, kind, domain)] = {
            "domain": domain, "unicode": domain, "type": type_, "kind": kind, "comment": comment,
            "groups": self.group_ids(list(groups)), "enabled": enabled, "id": self._id(),
        }

    def add_list(self, type_, address, comment=None, groups=("Default",), enabled=True) -> None:
        self.lists[(type_, address)] = {
            "address": address, "type": type_, "comment": comment,
            "groups": self.group_ids(list(groups)), "enabled": enabled, "id": self._id(),
        }

    def add_client(self, client, comment=None, groups=("Default",)) -> None:
        self.clients[client] = {
            "client": client, "name": "", "comment": comment, "groups": self.group_ids(list(groups)), "id": self._id()
        }

    # --- request handling -------------------------------------------------------

    def handle(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("Connection refused", request=request)
        raw = request.url.raw_path.decode().split("?")[0]
        assert raw.startswith("/api/"), raw
        parts = [unquote(p) for p in raw[len("/api/"):].split("/")]
        method = request.method
        self.calls.append((method, "/".join(parts)))
        body = json.loads(request.content) if request.content else {}
        params = request.url.params
        head = parts[0]

        if head == "stats" and parts[1] == "summary":
            return httpx.Response(200, json={
                "queries": {"total": 1000, "blocked": 250, "percent_blocked": 25.0, "cached": 400, "forwarded": 350},
                "clients": {"active": 12, "total": 20},
                "gravity": {"domains_being_blocked": 100000, "last_update": self.gravity_last_update},
            })
        if head == "stats" and parts[1] == "database":
            if parts[2] == "top_domains":
                kind = "blocked" if params.get("blocked") == "true" else "domains"
                return httpx.Response(200, json={"domains": self.top[kind]})
            return httpx.Response(200, json={"clients": self.top["clients"]})
        if head == "dns" and parts[1] == "blocking":
            if method == "POST":
                self.blocking = "enabled" if body["blocking"] else "disabled"
                self.blocking_timer = body.get("timer")
            return httpx.Response(200, json={"blocking": self.blocking, "timer": self.blocking_timer})
        if head == "info" and parts[1] == "version":
            v = {"local": {"version": "v6.5"}, "remote": {"version": "v6.5"}}
            return httpx.Response(200, json={"version": {"core": v, "web": v, "ftl": v}})
        if head == "network" and parts[1] == "devices":
            return httpx.Response(200, json={"devices": self.devices})
        if head == "network" and parts[1] == "interfaces":
            addrs = [{"family": "inet", "address": self.ipv4, "scope": "universe", "flags": []}]
            if self.ipv6:
                addrs.append({"family": "inet6", "address": self.ipv6, "scope": "universe", "flags": []})
            addrs.append({"family": "inet6", "address": "fe80::1", "scope": "link", "flags": ["permanent"]})
            return httpx.Response(200, json={"interfaces": [{"name": "eth0", "addresses": addrs}]})
        if head == "history":
            if len(parts) > 1 and parts[1] == "database":
                lo, hi = int(params["from"]), int(params["until"])
                return httpx.Response(200, json={"history": [b for b in self.history_db if lo <= b["timestamp"] <= hi]})
            return httpx.Response(200, json={"history": self.history})
        if head == "queries":
            log = self.query_log
            if "client_ip" in params:
                log = [q for q in log if (q.get("client") or {}).get("ip") == params["client_ip"]]
            return httpx.Response(200, json={"queries": log[: int(params.get("length", 100))]})
        if head == "groups":
            return self._groups(method, parts, body)
        if head == "domains":
            return self._domains(method, parts, body)
        if head == "lists":
            return self._lists(method, parts, body, params.get("type"))
        if head == "clients":
            return self._clients(method, parts, body)
        if head == "config" and len(parts) == 1 and method == "PATCH":
            dns = body["config"]["dns"]
            self.hosts[:] = [" ".join(h.split()) for h in dns.get("hosts", self.hosts)]
            self.cnames[:] = dns.get("cnameRecords", self.cnames)
            self.restarts += 1
            return httpx.Response(200, json={"config": {"dns": dns}})
        if head == "config" and parts[1] == "dns":
            return self._config(method, parts)
        if head == "info" and parts[1] == "login":
            return httpx.Response(200, json={"dns": True})
        if head == "action" and parts[1] == "gravity":
            self.gravity_last_update = int(time.time())
            return httpx.Response(200, text="  [i] Neutrino emissions detected...\n  [✓] Done.\n")
        return httpx.Response(404, json={"error": {"key": "not_found", "message": "Not found", "hint": raw}})

    def _groups(self, method, parts, body) -> httpx.Response:
        if method == "GET":
            return httpx.Response(200, json={"groups": sorted(self.groups.values(), key=lambda g: g["id"])})
        if method == "POST":
            if body["name"] in self.groups:
                return _err(400, *DUPLICATE)
            self.add_group(body["name"], body.get("comment"), body.get("enabled", True))
            return httpx.Response(201, json={"groups": [self.groups[body["name"]]], "processed": {"errors": [], "success": []}})
        name = parts[1]
        if method == "PUT":  # like the real API, PUT creates a missing group
            g = self.groups.pop(name, None) or {"name": name, "id": self._id()}
            g.update(name=body.get("name", name), comment=body.get("comment"), enabled=body.get("enabled", True))
            self.groups[g["name"]] = g
            return httpx.Response(200, json={"groups": [g], "processed": {"errors": [], "success": []}})
        if name not in self.groups:
            return httpx.Response(404, json={"took": 0})
        gid = self.groups.pop(name)["id"]
        for item in [*self.domains.values(), *self.lists.values(), *self.clients.values()]:
            item["groups"] = [i for i in item["groups"] if i != gid]
        return httpx.Response(204)

    def _domains(self, method, parts, body) -> httpx.Response:
        if method == "GET":
            return httpx.Response(200, json={"domains": list(self.domains.values())})
        type_, kind = parts[1], parts[2]
        if method == "POST":
            key = (type_, kind, body["domain"])
            if key in self.domains:
                return _err(400, *DUPLICATE)
            self.domains[key] = {
                "domain": body["domain"], "unicode": body["domain"], "type": type_, "kind": kind,
                "comment": body.get("comment"), "groups": body.get("groups", [0]),
                "enabled": body.get("enabled", True), "id": self._id(),
            }
            return httpx.Response(201, json={"domains": [self.domains[key]], "processed": {"errors": [], "success": []}})
        key = (type_, kind, parts[3])
        if method == "PUT":
            d = self.domains.setdefault(key, {"domain": parts[3], "unicode": parts[3], "type": type_, "kind": kind, "id": self._id()})
            d.update(comment=body.get("comment"), groups=body.get("groups", [0]), enabled=body.get("enabled", True))
            return httpx.Response(200, json={"domains": [d], "processed": {"errors": [], "success": []}})
        if key not in self.domains:
            return httpx.Response(404, json={"took": 0})
        del self.domains[key]
        return httpx.Response(204)

    def _lists(self, method, parts, body, type_) -> httpx.Response:
        if method == "GET":
            return httpx.Response(200, json={"lists": list(self.lists.values())})
        if method == "POST":
            if " " in body["address"]:
                return _err(400, "bad_request", "Spaces and tabs are not allowed in domains and URLs", body["address"])
            key = (type_, body["address"])
            if key in self.lists:
                return _err(400, *DUPLICATE)
            self.lists[key] = {
                "address": body["address"], "type": type_, "comment": body.get("comment"),
                "groups": body.get("groups", [0]), "enabled": body.get("enabled", True), "id": self._id(),
            }
            return httpx.Response(201, json={"lists": [self.lists[key]], "processed": {"errors": [], "success": []}})
        key = (type_, parts[1])
        if key not in self.lists:
            return httpx.Response(404, json={"took": 0})
        if method == "PUT":
            self.lists[key].update(comment=body.get("comment"), groups=body.get("groups", [0]), enabled=body.get("enabled", True))
            return httpx.Response(200, json={"lists": [self.lists[key]], "processed": {"errors": [], "success": []}})
        del self.lists[key]
        return httpx.Response(204)

    def _clients(self, method, parts, body) -> httpx.Response:
        if method == "GET":
            return httpx.Response(200, json={"clients": list(self.clients.values())})
        if method == "POST":
            if body["client"] in self.clients:
                return _err(400, *DUPLICATE)
            self.clients[body["client"]] = {
                "client": body["client"], "name": "", "comment": body.get("comment"),
                "groups": body.get("groups", [0]), "id": self._id(),
            }
            return httpx.Response(201, json={"clients": [self.clients[body["client"]]], "processed": {"errors": [], "success": []}})
        client = parts[1]
        if client not in self.clients:
            return httpx.Response(404, json={"took": 0})
        if method == "PUT":
            self.clients[client].update(comment=body.get("comment"), groups=body.get("groups", [0]))
            return httpx.Response(200, json={"clients": [self.clients[client]], "processed": {"errors": [], "success": []}})
        del self.clients[client]
        return httpx.Response(204)

    def _config(self, method, parts) -> httpx.Response:
        name = parts[2]
        entries = self.hosts if name == "hosts" else self.cnames
        if method == "GET":
            return httpx.Response(200, json={"config": {"dns": {name: entries}}})
        value = parts[3]
        if method == "PUT":
            if value in entries:
                return _err(400, "bad_request", "Item already present", "Uniqueness of items is enforced")
            entries.append(value)
            self.restarts += 1
            return httpx.Response(201, json={"took": 0})
        if value not in entries:
            return httpx.Response(404, json={"took": 0})
        entries.remove(value)
        self.restarts += 1
        return httpx.Response(204)
