"""Host and origin checks: the protection against DNS rebinding and cross-site writes."""

import pytest
from fastapi.testclient import TestClient

from twinhole.app import create_app
from twinhole.guard import allowed_host, host_name

BLOCK = {"target": "both", "enabled": False, "minutes": 5}


@pytest.mark.parametrize("header, name", [
    ("192.168.1.33:8053", "192.168.1.33"),
    ("[2a00::33]:8053", "2a00::33"),
    ("Box.LAN.", "box.lan"),
    ("ubuntuserver", "ubuntuserver"),
])
def test_host_name(header, name):
    assert host_name(header) == name


@pytest.mark.parametrize("name", [
    "192.168.1.33", "100.101.102.103", "2a00::33", "::1", "localhost", "ubuntuserver", "testserver",
    "pi.lan", "nas.local", "box.home.arpa", "ubuntuserver.tail742c31.ts.net", "twinhole.internal",
])
def test_names_nobody_outside_can_point_at_you_are_allowed(name):
    assert allowed_host(name)


@pytest.mark.parametrize("name", ["evil.example.com", "attacker.net", "192.168.1.33.nip.io", "lan.evil.com", ""])
def test_public_names_are_refused(name):
    assert not allowed_host(name)


def test_allowed_hosts_adds_your_own_names():
    assert not allowed_host("twinhole.example.org")
    assert allowed_host("twinhole.example.org", ("twinhole.example.org",))


@pytest.fixture
def client(settings, fakes, notifier, fake_dns):
    from dataclasses import replace

    app = create_app(
        replace(settings, allow_writes=True), background=False,
        transports={pid: f.transport for pid, f in fakes.items()},
        probe=fake_dns, version_query=fake_dns.version, latest_unbound=fake_dns.latest_unbound, notifier=notifier,
    )
    with TestClient(app) as c:
        yield c


def test_a_rebound_domain_gets_nothing(client, main_fake):
    # DNS rebinding: the browser sends the attacker's domain as the Host.
    r = client.post("/api/actions/blocking", json=BLOCK, headers={"Host": "evil.example.com"})
    assert r.status_code == 421 and "ALLOWED_HOSTS" in r.text
    assert main_fake.blocking == "enabled"
    assert client.get("/api/status", headers={"Host": "evil.example.com"}).status_code == 421


def test_writes_from_another_origin_are_refused(client, main_fake):
    h = {"Host": "192.168.1.33:8053", "Origin": "http://evil.example.com"}
    assert client.post("/api/actions/blocking", json=BLOCK, headers=h).status_code == 403
    h = {"Host": "192.168.1.33:8053", "Sec-Fetch-Site": "cross-site"}
    assert client.post("/api/actions/blocking", json=BLOCK, headers=h).status_code == 403
    assert main_fake.blocking == "enabled"


def test_writes_from_the_dashboard_itself_still_work(client, main_fake):
    h = {"Host": "192.168.1.33:8053", "Origin": "http://192.168.1.33:8053", "Sec-Fetch-Site": "same-origin"}
    assert client.post("/api/actions/blocking", json=BLOCK, headers=h).status_code == 200
    # And from scripts, which send no Origin.
    assert client.post("/api/actions/blocking", json={"target": "both", "enabled": True},
                       headers={"Host": "192.168.1.33:8053"}).status_code == 200


def test_pages_carry_security_headers_and_no_api_description(client):
    r = client.get("/")
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert client.get("/openapi.json").status_code == 404
