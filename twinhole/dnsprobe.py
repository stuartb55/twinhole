"""Real DNS lookups against each Pi-hole, to prove it actually resolves."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from dataclasses import dataclass

import dns.asyncquery
import dns.exception
import dns.message
import dns.rcode


@dataclass(frozen=True)
class ProbeResult:
    server: str
    ok: bool
    ms: float | None
    error: str | None = None
    rcode: str | None = None  # e.g. "NOERROR", "NXDOMAIN", "SERVFAIL"; None when nothing came back


async def probe(server: str, port: int, domain: str, timeout: float) -> ProbeResult:
    """Ask `server` for `domain`'s A record. Slower than `timeout` counts as a failure."""
    query = dns.message.make_query(domain, "A")
    start = time.perf_counter()
    try:
        address = await _address(server)
        reply = await dns.asyncquery.udp(query, address, timeout=timeout, port=port)
    except dns.exception.Timeout:
        return ProbeResult(server, False, None, f"no answer within {timeout * 1000:.0f} ms")
    except (OSError, dns.exception.DNSException) as e:
        return ProbeResult(server, False, None, str(e) or type(e).__name__)
    ms = (time.perf_counter() - start) * 1000
    rcode = dns.rcode.to_text(reply.rcode())
    if reply.rcode() != dns.rcode.NOERROR:
        return ProbeResult(server, False, ms, f"answered {rcode}", rcode)
    if not reply.answer:
        return ProbeResult(server, False, ms, "empty answer", rcode)
    return ProbeResult(server, True, ms, None, rcode)


async def _address(server: str) -> str:
    """dnspython needs an IP address; look host names up with the system resolver."""
    try:
        ipaddress.ip_address(server)
        return server
    except ValueError:
        infos = await asyncio.get_running_loop().getaddrinfo(server, None, type=socket.SOCK_DGRAM)
        return infos[0][4][0]


@dataclass(frozen=True)
class VersionResult:
    server: str
    version: str | None
    error: str | None = None


async def server_version(server: str, port: int, timeout: float) -> VersionResult:
    """Ask a DNS server its version with a CHAOS TXT version.server query, which Unbound
    answers unless `hide-version: yes` is set."""
    query = dns.message.make_query("version.server", "TXT", "CH")
    try:
        address = await _address(server)
        reply = await dns.asyncquery.udp(query, address, timeout=timeout, port=port)
    except dns.exception.Timeout:
        return VersionResult(server, None, "no answer")
    except (OSError, dns.exception.DNSException) as e:
        return VersionResult(server, None, str(e) or type(e).__name__)
    if reply.rcode() != dns.rcode.NOERROR:
        return VersionResult(server, None, f"answered {dns.rcode.to_text(reply.rcode())}")
    for rrset in reply.answer:
        for rdata in rrset:
            text = b"".join(getattr(rdata, "strings", ())).decode(errors="replace").strip()
            if text:
                return VersionResult(server, text)
    return VersionResult(server, None, "version hidden")
