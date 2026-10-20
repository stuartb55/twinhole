"""Every device either Pi-hole has seen, merged by hardware address.

Pi-hole keeps a network table of devices (MAC, vendor, IPs, names, query counts).
Devices without a known MAC appear as "ip-<address>". Client entries (which put a
device into groups) are matched to devices by MAC, IP, host name or subnet.
"""

from __future__ import annotations

import ipaddress
from typing import Any

ACTIVE_SECONDS = 7 * 86400
LOCALHOST = "00:00:00:00:00:00"  # each Pi-hole's own lookups, not a device


def _is_mac(hwaddr: str) -> bool:
    return len(hwaddr) == 17 and hwaddr.count(":") == 5


def _ip_sort_key(item: tuple[str, int]) -> tuple[int, int]:
    ip, last_seen = item
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return (3, -last_seen)
    rank = 0 if addr.version == 4 else 2 if addr.is_link_local else 1
    return (rank, -last_seen)


def merge(per_pihole: dict[str, list[dict[str, Any]]], now: float) -> list[dict[str, Any]]:
    """One row per device, with per-Pi-hole query counts. Most active first."""
    found: dict[str, dict[str, Any]] = {}
    for pid, devices in per_pihole.items():
        for d in devices:
            hwaddr = (d.get("hwaddr") or "").lower()
            if not hwaddr or hwaddr == LOCALHOST:
                continue
            dev = found.setdefault(hwaddr, {
                "id": hwaddr, "mac": hwaddr if _is_mac(hwaddr) else None, "vendor": None,
                "first_seen": None, "last_query": 0, "queries": {}, "_ips": {}, "_name": (None, -1),
            })
            dev["vendor"] = dev["vendor"] or d.get("macVendor") or None
            if d.get("firstSeen"):
                dev["first_seen"] = min(dev["first_seen"] or d["firstSeen"], d["firstSeen"])
            last_query = d.get("lastQuery") or 0
            dev["last_query"] = max(dev["last_query"], last_query)
            dev["queries"][pid] = {"count": d.get("numQueries") or 0, "last_query": last_query}
            for ip in d.get("ips") or []:
                addr, seen = ip.get("ip"), ip.get("lastSeen") or 0
                if addr:
                    dev["_ips"][addr] = max(dev["_ips"].get(addr, 0), seen)
                if ip.get("name") and (ip.get("nameUpdated") or 0) > dev["_name"][1]:
                    dev["_name"] = (ip["name"], ip.get("nameUpdated") or 0)

    out = []
    for dev in found.values():
        ips = [ip for ip, _ in sorted(dev.pop("_ips").items(), key=_ip_sort_key)]
        name = dev.pop("_name")[0]
        recent = [pid for pid, q in dev["queries"].items() if now - q["last_query"] < ACTIVE_SECONDS]
        out.append({
            **dev,
            "name": name,
            "ips": ips,
            "total_queries": sum(q["count"] for q in dev["queries"].values()),
            "active": bool(recent),
            # Active, but only one of the two Pi-holes has heard from it lately.
            "only_uses": recent[0] if len(recent) == 1 and len(per_pihole) > 1 else None,
        })
    out.sort(key=lambda d: (not d["active"], -d["total_queries"]))
    return out


def match_clients(device: dict[str, Any], clients: list[dict[str, Any]], group_names: dict[int, str]) -> list[dict]:
    """Client entries that apply to this device. `exact` means the entry names this device alone."""
    ips = []
    for ip in device["ips"]:
        try:
            ips.append(ipaddress.ip_address(ip))
        except ValueError:
            pass
    ip_texts = {str(ip) for ip in ips}
    names = set()
    if device.get("name"):
        full = device["name"].lower()
        names = {full, full.split(".")[0]}

    matches = []
    for c in clients:
        ident = (c.get("client") or "").strip()
        low = ident.lower()
        exact = (device["mac"] is not None and low == device["mac"]) or low in ip_texts or low in names
        via_subnet = False
        if not exact and "/" in ident:
            try:
                net = ipaddress.ip_network(ident, strict=False)
                via_subnet = any(ip.version == net.version and ip in net for ip in ips)
            except ValueError:
                pass
        if exact or via_subnet:
            matches.append({
                "client": ident,
                "comment": c.get("comment") or "",
                "groups": sorted(group_names.get(g, f"#{g}") for g in c.get("groups") or []),
                "exact": exact,
            })
    return matches
