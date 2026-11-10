"""Request checks that stand in for a login on a dashboard that has none.

twinhole has no password, so the only thing between a web page in your browser and
the write endpoints is the browser's same-origin rule. DNS rebinding gets round that:
a page re-points its own domain at twinhole's address, and the browser then treats
twinhole as that site. Every rebinding request still carries the attacker's domain in
its Host header, so twinhole only answers to names nobody outside your network can
point at it: IP addresses, single-label names, private suffixes (.lan, .local,
.home.arpa, .internal, Tailscale's .ts.net) and anything listed in ALLOWED_HOSTS.

Writes also need an Origin that matches the address the request came to, as a second
line against cross-site requests.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Receive, Scope, Send

PRIVATE_SUFFIXES = (".lan", ".local", ".home", ".home.arpa", ".internal", ".localdomain", ".ts.net")
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

SECURITY_HEADERS = [
    (b"content-security-policy",
     b"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
     b"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"same-origin"),
]


def host_name(host_header: str) -> str:
    """'192.168.1.33:8053' -> '192.168.1.33', '[::1]:8053' -> '::1', 'Box.lan.' -> 'box.lan'."""
    h = host_header.strip().lower()
    if h.startswith("["):
        return h[1:h.find("]")] if "]" in h else h
    if h.count(":") == 1:
        h = h.split(":")[0]
    return h.rstrip(".")


def allowed_host(name: str, extra: tuple[str, ...] = ()) -> bool:
    if not name:
        return False
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        pass
    if name in extra or "." not in name:  # "localhost", "ubuntuserver", Docker service names
        return True
    return name.endswith(PRIVATE_SUFFIXES)


class GuardMiddleware:
    def __init__(self, app: ASGIApp, allowed_hosts: tuple[str, ...] = ()):
        self.app = app
        self.extra = allowed_hosts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in scope["headers"]}
        host = headers.get("host", "")
        if not allowed_host(host_name(host), self.extra):
            response = PlainTextResponse(
                f"twinhole doesn't answer to the name {host_name(host)!r}. Use its IP address, "
                "or add the name to ALLOWED_HOSTS in .env and restart twinhole.",
                status_code=421,
            )
            await response(scope, receive, send)
            return
        if scope["method"] not in SAFE_METHODS and not _same_origin(headers, host):
            response = PlainTextResponse("Cross-site request refused", status_code=403)
            await response(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                message["headers"] = list(message.get("headers", [])) + SECURITY_HEADERS
            await send(message)

        await self.app(scope, receive, send_with_headers)


def _same_origin(headers: dict[str, str], host: str) -> bool:
    """A write is fine without an Origin (curl, scripts); with one, it must be this address."""
    if headers.get("sec-fetch-site") == "cross-site":
        return False
    origin = headers.get("origin")
    if not origin:
        return True
    if origin == "null":
        return False
    return urlsplit(origin).netloc.lower() == host.strip().lower()
