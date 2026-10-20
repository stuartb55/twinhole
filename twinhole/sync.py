"""One-way sync, main -> secondary, for groups, domains, adlists, clients, local DNS and CNAMEs.

Group membership is compared by group *name*, because the numeric IDs differ between
Pi-holes. The secondary is made a mirror: anything only it has is deleted (except the
built-in Default group, id 0).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from typing import Any

from .pihole import Pihole, PiholeError

RESOURCES = ("groups", "domains", "lists", "clients", "hosts", "cnames")
NOUNS = {
    "groups": ("group", "groups"),
    "domains": ("domain", "domains"),
    "lists": ("adlist", "adlists"),
    "clients": ("client", "clients"),
    "hosts": ("local DNS record", "local DNS records"),
    "cnames": ("CNAME", "CNAMEs"),
}
# Properties kept for writing but not compared.
_NOT_COMPARED = {"raw", "id"}

Key = tuple[str, ...]
Snapshot = dict[str, dict[Key, dict[str, Any]]]


@dataclass(frozen=True)
class Change:
    resource: str
    action: str  # add | update | delete
    key: Key
    after: dict[str, Any] | None  # wanted state (from main); None for delete
    before: dict[str, Any] | None  # current state on the target; None for add

    @property
    def label(self) -> str:
        return describe(self.resource, self.key)

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["key"] = list(self.key)
        d["label"] = self.label
        return d


def describe(resource: str, key: Key) -> str:
    if resource == "domains":
        type_, kind, domain = key
        return f"{domain} ({'allow' if type_ == 'allow' else 'block'}, {kind})"
    if resource == "lists":
        type_, address = key
        return f"{address} ({type_})"
    return key[0]


def _comment(value: Any) -> str:
    return value or ""


def norm_host(entry: str) -> str:
    return " ".join(entry.split())


def norm_cname(entry: str) -> str:
    return ",".join(part.strip() for part in entry.split(","))


async def snapshot(p: Pihole) -> tuple[Snapshot, dict[str, int]]:
    """Everything sync covers, keyed by identity, with group IDs replaced by names."""
    groups, domains, lists, clients, hosts, cnames = await asyncio.gather(
        p.groups(), p.domains(), p.lists(), p.clients(), p.hosts(), p.cnames()
    )
    names = {g["id"]: g["name"] for g in groups}

    def group_names(ids: Iterable[int]) -> list[str]:
        return sorted(names.get(i, f"#{i}") for i in ids)

    snap: Snapshot = {
        "groups": {
            (g["name"],): {"comment": _comment(g["comment"]), "enabled": bool(g["enabled"]), "id": g["id"]}
            for g in groups
        },
        "domains": {
            (d["type"], d["kind"], d["domain"]): {
                "comment": _comment(d["comment"]),
                "groups": group_names(d["groups"]),
                "enabled": bool(d["enabled"]),
            }
            for d in domains
        },
        "lists": {
            (lst["type"], lst["address"]): {
                "comment": _comment(lst["comment"]),
                "groups": group_names(lst["groups"]),
                "enabled": bool(lst["enabled"]),
            }
            for lst in lists
        },
        "clients": {
            (c["client"],): {"comment": _comment(c["comment"]), "groups": group_names(c["groups"])}
            for c in clients
        },
        "hosts": {(norm_host(h),): {"raw": h} for h in hosts},
        "cnames": {(norm_cname(c),): {"raw": c} for c in cnames},
    }
    return snap, {g["name"]: g["id"] for g in groups}


def _comparable(props: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in props.items() if k not in _NOT_COMPARED}


def plan(main: Snapshot, target: Snapshot) -> list[Change]:
    """The ordered changes that make `target` match `main`.

    Order: group adds/updates first (members need them), then everything else,
    and group deletes last (after their members are gone).
    """
    group_upserts: list[Change] = []
    middle: list[Change] = []
    group_deletes: list[Change] = []
    for resource in RESOURCES:
        want, have = main[resource], target[resource]
        out = group_upserts if resource == "groups" else middle
        for key in sorted(set(want) - set(have)):
            out.append(Change(resource, "add", key, want[key], None))
        for key in sorted(set(want) & set(have)):
            if _comparable(want[key]) != _comparable(have[key]):
                out.append(Change(resource, "update", key, want[key], have[key]))
        for key in sorted(set(have) - set(want)):
            if resource == "groups" and have[key].get("id") == 0:
                continue  # the built-in Default group can't be deleted
            (group_deletes if resource == "groups" else out).append(Change(resource, "delete", key, None, have[key]))
    return group_upserts + middle + group_deletes


def plan_id(changes: list[Change]) -> str:
    """Fingerprint of a plan, so Apply only runs what the user actually previewed."""
    payload = json.dumps(
        [[c.resource, c.action, list(c.key), c.after and _comparable(c.after)] for c in changes], sort_keys=True
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def summarize(changes: list[Change]) -> str:
    counts: dict[tuple[str, str], int] = {}
    for c in changes:
        counts[(c.resource, c.action)] = counts.get((c.resource, c.action), 0) + 1
    sign = {"add": "+", "delete": "-", "update": "~"}
    parts = []
    for resource in RESOURCES:
        for action in ("add", "delete", "update"):
            n = counts.get((resource, action))
            if n:
                one, many = NOUNS[resource]
                parts.append(f"{sign[action]}{n} {one if n == 1 else many}")
    return ", ".join(parts) or "in sync"


async def apply_change(p: Pihole, c: Change, group_ids: dict[str, int]) -> None:
    """Make one change on `p`. `group_ids` maps group names to IDs on `p`."""

    def ids(names: list[str]) -> list[int]:
        missing = [n for n in names if n not in group_ids]
        if missing:
            raise PiholeError(p.name, f"group {', '.join(missing)} doesn't exist on this Pi-hole")
        return [group_ids[n] for n in names]

    a = c.after or {}
    if c.resource == "groups":
        (name,) = c.key
        if c.action == "add":
            await p.add_group(name, a["comment"], a["enabled"])
        elif c.action == "update":
            await p.update_group(name, a["comment"], a["enabled"])
        else:
            await p.delete_group(name)
    elif c.resource == "domains":
        type_, kind, domain = c.key
        if c.action == "add":
            await p.add_domain(type_, kind, domain, a["comment"], ids(a["groups"]), a["enabled"])
        elif c.action == "update":
            await p.update_domain(type_, kind, domain, a["comment"], ids(a["groups"]), a["enabled"])
        else:
            await p.delete_domain(type_, kind, domain)
    elif c.resource == "lists":
        type_, address = c.key
        if c.action == "add":
            await p.add_list(type_, address, a["comment"], ids(a["groups"]), a["enabled"])
        elif c.action == "update":
            await p.update_list(type_, address, a["comment"], ids(a["groups"]), a["enabled"])
        else:
            await p.delete_list(type_, address)
    elif c.resource == "clients":
        (client,) = c.key
        if c.action == "add":
            await p.add_client(client, a["comment"], ids(a["groups"]))
        elif c.action == "update":
            await p.update_client(client, a["comment"], ids(a["groups"]))
        else:
            await p.delete_client(client)
    elif c.resource in ("hosts", "cnames"):
        add, delete = (p.add_host, p.delete_host) if c.resource == "hosts" else (p.add_cname, p.delete_cname)
        if c.action == "add":
            await add(a.get("raw") or c.key[0])
        elif c.action == "delete":
            await delete((c.before or {}).get("raw") or c.key[0])
        # hosts and CNAMEs have no properties, so there is nothing to update
    else:
        raise ValueError(f"unknown resource {c.resource!r}")


async def apply(p: Pihole, changes: list[Change], group_ids: dict[str, int]) -> list[dict[str, Any]]:
    """Apply changes in order, carrying on past failures. Returns one result per change.

    Local DNS and CNAME changes are written together in one go at the end, because each
    write restarts FTL on the target.
    """
    group_ids = dict(group_ids)
    dns_changes = [c for c in changes if c.resource in ("hosts", "cnames")]
    results = []
    for c in changes:
        if c in dns_changes:
            continue
        try:
            await apply_change(p, c, group_ids)
            results.append({**c.as_dict(), "ok": True, "error": None})
        except PiholeError as e:
            results.append({**c.as_dict(), "ok": False, "error": e.message})
            continue
        if c.resource == "groups" and c.action == "add":
            try:
                group_ids = {g["name"]: g["id"] for g in await p.groups()}
            except PiholeError:
                pass  # members of the new group will then fail with a clear message
    if dns_changes:
        results += await _apply_dns_records(p, dns_changes)
    return results


async def _apply_dns_records(p: Pihole, changes: list[Change]) -> list[dict[str, Any]]:
    try:
        hosts, cnames = await asyncio.gather(p.hosts(), p.cnames())
        wanted = {"hosts": list(hosts), "cnames": list(cnames)}
        for c in changes:
            entries = wanted[c.resource]
            if c.action == "add":
                entries.append((c.after or {}).get("raw") or c.key[0])
            elif c.action == "delete":
                raw = (c.before or {}).get("raw") or c.key[0]
                if raw in entries:
                    entries.remove(raw)
        await p.set_dns_records(wanted["hosts"], wanted["cnames"])
        error = None
    except PiholeError as e:
        error = e.message
    return [{**c.as_dict(), "ok": error is None, "error": error} for c in changes]
