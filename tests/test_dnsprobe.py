import asyncio

import dns.message
import dns.rcode
import dns.rrset
import pytest

from twinhole.dnsprobe import server_version

pytestmark = pytest.mark.anyio


async def serve(reply_with):
    """A one-socket DNS server on localhost that answers with `reply_with(query)`."""

    class Protocol(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            self.transport = transport

        def datagram_received(self, data, addr):
            self.transport.sendto(reply_with(dns.message.from_wire(data)).to_wire(), addr)

    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(Protocol, local_addr=("127.0.0.1", 0))
    return transport, transport.get_extra_info("sockname")[1]


def unbound(query):
    reply = dns.message.make_response(query)
    reply.answer.append(dns.rrset.from_text("version.server.", 0, "CH", "TXT", '"unbound 1.22.0"'))
    return reply


def hidden(query):
    return dns.message.make_response(query)


def refused(query):
    reply = dns.message.make_response(query)
    reply.set_rcode(dns.rcode.REFUSED)
    return reply


@pytest.mark.parametrize("reply_with, version, error", [
    (unbound, "unbound 1.22.0", None),
    (hidden, None, "version hidden"),
    (refused, None, "answered REFUSED"),
])
async def test_server_version(reply_with, version, error):
    transport, port = await serve(reply_with)
    try:
        r = await server_version("127.0.0.1", port, 1.0)
    finally:
        transport.close()
    assert (r.version, r.error) == (version, error)
