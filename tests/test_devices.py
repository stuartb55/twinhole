import pytest
from fastapi.testclient import TestClient

from twinhole.app import create_app
from twinhole.devices import count_active, match_clients, merge

NOW = 1_792_500_000
DAY = 86400


def dev(hwaddr, queries, last_query=NOW - 60, ips=(), vendor=None, first_seen=NOW - 30 * DAY):
    return {
        "hwaddr": hwaddr, "macVendor": vendor, "firstSeen": first_seen,
        "lastQuery": last_query, "numQueries": queries, "ips": list(ips),
    }


def ip(addr, name=None, last_seen=NOW - 60, name_updated=0):
    return {"ip": addr, "name": name, "lastSeen": last_seen, "nameUpdated": name_updated}


def test_merge_joins_both_piholes_by_mac():
    per = {
        "main": [dev("D0:11:E5:A7:C9:38", 900, ips=[ip("192.168.1.111", "mini.old", name_updated=1)], vendor="Apple, Inc.")],
        "sec": [dev("d0:11:e5:a7:c9:38", 100, ips=[ip("192.168.1.111", "mini.localdomain", name_updated=5), ip("fe80::1"), ip("2a00::5")])],
    }
    [d] = merge(per, NOW)
    assert d["mac"] == "d0:11:e5:a7:c9:38"
    assert d["name"] == "mini.localdomain"  # the most recently updated name wins
    assert d["vendor"] == "Apple, Inc."
    assert d["ips"] == ["192.168.1.111", "2a00::5", "fe80::1"]  # IPv4, then global IPv6, then link-local
    assert d["queries"] == {"main": {"count": 900, "last_query": NOW - 60}, "sec": {"count": 100, "last_query": NOW - 60}}
    assert d["total_queries"] == 1000
    assert d["only_uses"] is None


def test_merge_skips_localhost_and_keeps_devices_without_a_mac():
    per = {"main": [dev("00:00:00:00:00:00", 5000), dev("ip-100.64.0.7", 30, ips=[ip("100.64.0.7")])], "sec": []}
    [d] = merge(per, NOW)
    assert d["id"] == "ip-100.64.0.7" and d["mac"] is None


def test_merge_flags_devices_only_using_one_pihole_and_sorts_active_first():
    per = {
        "main": [dev("aa:aa:aa:aa:aa:01", 50), dev("aa:aa:aa:aa:aa:02", 9999, last_query=NOW - 30 * DAY)],
        "sec": [dev("aa:aa:aa:aa:aa:01", 7, last_query=NOW - 20 * DAY)],
    }
    rows = merge(per, NOW)
    assert [r["id"] for r in rows] == ["aa:aa:aa:aa:aa:01", "aa:aa:aa:aa:aa:02"]
    assert rows[0]["only_uses"] == "main"
    assert rows[1]["active"] is False and rows[1]["only_uses"] is None


def test_client_entries_match_by_mac_ip_name_and_subnet():
    [d] = merge({"main": [dev("aa:bb:cc:dd:ee:ff", 1, ips=[ip("192.168.1.42", "tablet.localdomain")])]}, NOW)
    clients = [
        {"client": "AA:BB:CC:DD:EE:FF", "comment": "by mac", "groups": [0, 2]},
        {"client": "192.168.1.42", "comment": "", "groups": [2]},
        {"client": "tablet", "comment": None, "groups": [2]},
        {"client": "192.168.1.0/24", "comment": "LAN", "groups": [0]},
        {"client": "10.0.0.0/8", "comment": "", "groups": [0]},
        {"client": "2a00::/16", "comment": "", "groups": [0]},
    ]
    matches = match_clients(d, clients, {0: "Default", 2: "kids"})
    assert [(m["client"], m["exact"]) for m in matches] == [
        ("AA:BB:CC:DD:EE:FF", True), ("192.168.1.42", True), ("tablet", True), ("192.168.1.0/24", False),
    ]
    assert matches[0]["groups"] == ["Default", "kids"]


@pytest.fixture
def client(settings, fakes, notifier, fake_dns):
    app = create_app(
        settings, background=False, transports={pid: f.transport for pid, f in fakes.items()},
        probe=fake_dns, version_query=fake_dns.version, latest_unbound=fake_dns.latest_unbound, notifier=notifier,
    )
    with TestClient(app) as c:
        yield c


def test_devices_endpoint_merges_and_shows_group_assignments(client, main_fake, sec_fake):
    main_fake.add_group("kids")
    main_fake.add_client("aa:bb:cc:dd:ee:ff", comment="Tablet", groups=["kids"])
    main_fake.devices = [dev("aa:bb:cc:dd:ee:ff", 40, last_query=0, ips=[ip("192.168.1.42", "tablet.lan")])]
    sec_fake.devices = [dev("aa:bb:cc:dd:ee:ff", 2, last_query=0)]
    body = client.get("/api/devices").json()
    assert body["groups"] == ["Default", "kids"]
    [d] = body["devices"]
    assert d["name"] == "tablet.lan" and d["total_queries"] == 42
    assert d["clients"] == [{"client": "aa:bb:cc:dd:ee:ff", "comment": "Tablet", "groups": ["kids"], "exact": True}]
    assert body["errors"] == []


def test_devices_endpoint_still_works_when_one_pihole_is_down(client, main_fake, sec_fake):
    sec_fake.devices = [dev("aa:bb:cc:dd:ee:01", 3)]
    main_fake.down = True
    body = client.get("/api/devices").json()
    assert [d["id"] for d in body["devices"]] == ["aa:bb:cc:dd:ee:01"]
    assert len(body["errors"]) == 2  # devices and groups both come partly from the main Pi-hole


def test_merge_marks_devices_that_never_queried_as_silent_and_inactive():
    # Pi-hole lists neighbours it saw via ARP/NDP even if they never asked it anything,
    # and may still stamp a recent lastQuery on them.
    per = {"main": [dev("ip-fe80::7427:50ff:fe3f:d864", 0, ips=[ip("fe80::7427:50ff:fe3f:d864")]), dev("aa:aa:aa:aa:aa:01", 5)]}
    rows = merge(per, NOW)
    assert [(r["id"], r["silent"], r["active"]) for r in rows] == [
        ("aa:aa:aa:aa:aa:01", False, True), ("ip-fe80::7427:50ff:fe3f:d864", True, False),
    ]


def test_merge_folds_ip_only_rows_into_the_device_with_that_address():
    per = {
        "main": [
            dev("aa:aa:aa:aa:aa:01", 10, ips=[ip("192.168.1.5"), ip("fe80::1")]),
            dev("ip-fe80::1", 3, last_query=NOW - 5, ips=[ip("fe80::1", "phone.lan", name_updated=9)]),
        ],
        "sec": [dev("ip-192.168.1.5", 4, ips=[ip("192.168.1.5")])],
    }
    [d] = merge(per, NOW)
    assert d["id"] == "aa:aa:aa:aa:aa:01" and d["name"] == "phone.lan"
    assert d["queries"] == {"main": {"count": 13, "last_query": NOW - 5}, "sec": {"count": 4, "last_query": NOW - 60}}
    assert d["total_queries"] == 17 and not d["silent"]


def test_count_active_counts_each_device_once_within_a_day():
    devices = [
        dev("aa:aa:aa:aa:aa:01", 50, ips=[ip("192.168.1.5"), ip("2a00::5"), ip("2a00::6"), ip("fe80::5")]),
        dev("ip-2a00::5", 9, ips=[ip("2a00::5")]),  # same phone, before Pi-hole learnt its MAC
        dev("aa:aa:aa:aa:aa:02", 8, last_query=NOW - 2 * DAY),  # not today
        dev("aa:aa:aa:aa:aa:03", 0),  # only seen on the network
        dev("ip-100.64.0.7", 3, ips=[ip("100.64.0.7")]),  # over Tailscale, no MAC
    ]
    assert count_active(devices, NOW) == 2
