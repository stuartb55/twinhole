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
    if reply.rcode() != dns.rcode.NOERROR:
        return ProbeResult(server, False, ms, f"answered {dns.rcode.to_text(reply.rcode())}")
    if not reply.answer:
        return ProbeResult(server, False, ms, "empty answer")
    return ProbeResult(server, True, ms)


async def _address(server: str) -> str:
    """dnspython needs an IP address; look host names up with the system resolver."""
    try:
        ipaddress.ip_address(server)
        return server
    except ValueError:
        infos = await asyncio.get_running_loop().getaddrinfo(server, None, type=socket.SOCK_DGRAM)
        return infos[0][4][0]
