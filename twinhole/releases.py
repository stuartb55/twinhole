"""The latest upstream release of the resolver behind each Pi-hole, to tell when it's out of date.

Pi-hole reports its own updates in /info/version, but Unbound has nothing like that, so
twinhole asks NLnet Labs' GitHub releases. That's one unauthenticated request a day, well
inside GitHub's limit of 60 an hour.
"""

from __future__ import annotations

import re

import httpx

UNBOUND_LATEST = "https://api.github.com/repos/NLnetLabs/unbound/releases/latest"


def parse_version(text: str) -> tuple[int, ...] | None:
    """(1, 24, 2) from "1.24.2", "release-1.24.2" or "Unbound 1.24.2"; None if there's no version."""
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", text or "")
    return tuple(int(g) for g in m.groups() if g is not None) if m else None


async def latest_unbound(transport: httpx.AsyncBaseTransport | None = None) -> str:
    """The latest Unbound release, such as "1.24.2". Raises httpx.HTTPError or ValueError."""
    async with httpx.AsyncClient(timeout=10, transport=transport,
                                 headers={"Accept": "application/vnd.github+json"}) as http:
        r = await http.get(UNBOUND_LATEST)
        r.raise_for_status()
        tag = r.json().get("tag_name") or ""
    v = parse_version(tag)
    if not v:
        raise ValueError(f"no version in release tag {tag!r}")
    return ".".join(map(str, v))
