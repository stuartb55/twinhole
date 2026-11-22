"""Why a domain is blocked (or not): the rules on each Pi-hole that match it, what they
add up to for each group, and the domain's recent queries.

Pi-hole decides in this order, and the first match wins (FTL's check_domain_blocked):
an allow rule (exact or regex), an exact deny rule, an allowlist adlist ("antigravity"),
a blocklist adlist, a regex deny rule. A rule only counts for devices in one of its
groups, and only while the rule and the group are enabled.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import urlsplit

from .pihole import Pihole, PiholeError
from .sync import Change

COMMENT = "Added from the twinhole lookup"
RECENT = 20  # recent queries asked of each Pi-hole

# (source, action) in the order Pi-hole checks them.
PRECEDENCE = [("exact", "allow"), ("regex", "allow"), ("exact", "block"), ("adlist", "allow"),
              ("adlist", "block"), ("regex", "block")]
_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")


def normalise(raw: str) -> str:
    """'https://WWW.Example.com/page' -> 'www.example.com'. Raises ValueError if it isn't a domain.
    International names come back in punycode (xn--...), the form Pi-hole stores and logs."""
    text = raw.strip().lower()
    if "://" in text:
        text = urlsplit(text).hostname or ""
    else:
        text = text.split("/", 1)[0]
    text = text.rstrip(".")
    if text.startswith("*."):
        text = text[2:]
    if not text or len(text) > 253:
        raise ValueError("Enter a domain, such as ads.example.com")
    try:
        ascii_name = text.encode("idna").decode() if not text.isascii() else text
    except UnicodeError as e:
        raise ValueError(f"{raw.strip()!r} isn't a valid domain") from e
    if not all(_LABEL.match(label) for label in ascii_name.split(".")):
        raise ValueError(f"{raw.strip()!r} isn't a valid domain")
    return ascii_name


def rules(found: dict[str, Any], groups: dict[int, dict[str, Any]]) -> list[dict[str, Any]]:
    """Pi-hole's search results as one list of rules, in the order Pi-hole checks them."""
    out = []
    for d in found.get("domains") or []:
        out.append({
            "source": d.get("kind") or "exact",
            "action": "allow" if d.get("type") == "allow" else "block",
            "entry": d.get("domain"),
            "list": None,
            "comment": d.get("comment") or "",
            "enabled": bool(d.get("enabled", True)),
            "group_ids": list(d.get("groups") or []),
        })
    for g in found.get("gravity") or []:
        out.append({
            "source": "adlist",
            "action": "allow" if g.get("type") == "allow" else "block",
            "entry": g.get("domain"),
            "list": g.get("address"),
            "comment": g.get("comment") or "",
            "enabled": bool(g.get("enabled", True)),
            "group_ids": list(g.get("groups") or []),
        })
    order = {k: i for i, k in enumerate(PRECEDENCE)}
    out.sort(key=lambda r: order.get((r["source"], r["action"]), len(order)))
    for r in out:
        r["groups"] = [groups[i]["name"] if i in groups else f"group {i}" for i in r["group_ids"]]
        r["active"] = r["enabled"] and any(groups.get(i, {}).get("enabled", True) for i in r["group_ids"])
    return out


def verdict(found_rules: list[dict[str, Any]], groups: dict[int, dict[str, Any]]) -> dict[str, Any]:
    """What happens to the domain for devices in each group that any rule mentions, plus Default.

    status is "blocked", "allowed" (an allow rule decided it) or "not_blocked" when every
    group agrees, or "mixed" when it depends on the device's group. `by` is the index of
    the rule that decides it for the Default group (or the first group listed).
    """
    ids = [0] + sorted({i for r in found_rules for i in r["group_ids"]} - {0})
    per_group = []
    for gid in ids:
        g = groups.get(gid, {"name": "Default" if gid == 0 else f"group {gid}", "enabled": True})
        if not g.get("enabled", True):
            continue
        by = next((n for n, r in enumerate(found_rules) if r["enabled"] and gid in r["group_ids"]), None)
        status = "not_blocked" if by is None else "allowed" if found_rules[by]["action"] == "allow" else "blocked"
        per_group.append({"group": g["name"], "status": status, "by": by})
    statuses = {g["status"] for g in per_group}
    status = statuses.pop() if len(statuses) == 1 else "mixed" if statuses else "not_blocked"
    return {"status": status, "by": per_group[0]["by"] if per_group else None, "groups": per_group}


async def look_up(p: Pihole, domain: str) -> dict[str, Any]:
    """One Pi-hole's view of the domain. A Pi-hole that can't be read gets an `error` instead."""
    out: dict[str, Any] = {"id": p.id, "name": p.name, "error": None, "rules": [], "verdict": None, "recent": []}
    found, group_list, recent = await asyncio.gather(
        p.search(domain), p.groups(), p.queries(RECENT, domain=domain), return_exceptions=True
    )
    for res in (found, group_list):
        if isinstance(res, BaseException):
            # An unexpected reply shape is reported like an unreachable Pi-hole, so the
            # other Pi-hole's answer still shows.
            out["error"] = res.message if isinstance(res, PiholeError) else f"unexpected reply ({type(res).__name__}: {res})"
            return out
    groups = {g["id"]: g for g in group_list}
    out["rules"] = rules(found, groups)
    out["verdict"] = verdict(out["rules"], groups)
    if not isinstance(recent, BaseException):
        out["recent"] = [{
            "time": q.get("time"),
            "pihole": p.id,
            "status": q.get("status"),
            "client": (q.get("client") or {}).get("ip"),
            "client_name": (q.get("client") or {}).get("name"),
            "type": q.get("type"),
        } for q in recent if (q.get("domain") or "").lower() == domain]
    return out


def plan_edits(domain: str, action: str, found_rules: list[dict[str, Any]]) -> tuple[list[Change], list[str]]:
    """The rule changes that allow or block `domain` (from the main Pi-hole's rules), and notes
    about anything they can't fix. New rules go in the Default group.

    Allow removes an exact block rule, then adds an exact allow rule if an adlist or regex
    would still block it. Block removes an exact allow rule and adds an exact block rule.
    """
    want, unwanted = ("allow", "block") if action == "allow" else ("block", "allow")
    exact = [r for r in found_rules if r["source"] == "exact" and r["entry"] == domain]
    changes = [
        Change("domains", "delete", (("deny" if unwanted == "block" else "allow"), "exact", domain), None, None)
        for r in exact if r["action"] == unwanted
    ]
    rest = [r for r in found_rules if r["active"] and not (r["source"] == "exact" and r["action"] == unwanted)]
    already = any(r["source"] == "exact" and r["action"] == want and r["active"] and 0 in r["group_ids"] for r in exact)
    notes = []
    if action == "allow":
        # Nothing to add when nothing else blocks it, or an allow rule already wins.
        needed = any(r["action"] == "block" for r in rest) and not any(
            r["action"] == "allow" and r["source"] in ("exact", "regex") for r in rest
        )
    else:
        needed = True
        allow_regex = [r["entry"] for r in rest if r["source"] == "regex" and r["action"] == "allow"]
        if allow_regex:
            notes.append(
                "A regex allow rule still wins over an exact block rule: "
                + ", ".join(allow_regex) + ". Change it on Manage → Domains to block this domain."
            )
    if needed and not already:
        type_ = "allow" if want == "allow" else "deny"
        after = {"comment": COMMENT, "groups": ["Default"], "enabled": True}
        changes.append(Change("domains", "add", (type_, "exact", domain), after, None))
    return changes, notes
