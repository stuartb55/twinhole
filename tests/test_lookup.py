from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from twinhole import lookup
from twinhole.app import create_app

BLOCKLIST = "https://lists.example/hosts.txt"
ALLOWLIST = "https://lists.example/allow.txt"


@pytest.fixture
def make_client(settings, fakes, notifier, fake_dns):
    clients = []

    def make(**overrides):
        app = create_app(
            replace(settings, **overrides),
            background=False,
            transports={pid: f.transport for pid, f in fakes.items()},
            probe=fake_dns, version_query=fake_dns.version, latest_unbound=fake_dns.latest_unbound,
            notifier=notifier,
        )
        client = TestClient(app)
        client.__enter__()
        clients.append(client)
        return client

    yield make
    for c in clients:
        c.__exit__(None, None, None)


def seed(*fakes):
    for f in fakes:
        f.add_list("block", BLOCKLIST)
        f.add_list("allow", ALLOWLIST)
        f.gravity[("block", BLOCKLIST)] = ["tracker.example.net", "||adnet.example^"]
        f.gravity[("allow", ALLOWLIST)] = ["fine.example.net"]


@pytest.mark.parametrize("raw, want", [
    ("Ads.Example.com", "ads.example.com"),
    ("https://www.example.com/some/page?x=1", "www.example.com"),
    ("example.com/path", "example.com"),
    ("example.com.", "example.com"),
    ("*.example.com", "example.com"),
    ("bücher.example", "xn--bcher-kva.example"),
])
def test_normalise(raw, want):
    assert lookup.normalise(raw) == want


@pytest.mark.parametrize("raw", ["", "   ", "two words.com", "bad..dots", "-dash.example", "a" * 300])
def test_normalise_refuses_non_domains(raw):
    with pytest.raises(ValueError):
        lookup.normalise(raw)


def test_blocked_by_adlist_including_parent_domain(make_client, main_fake, sec_fake):
    seed(main_fake, sec_fake)
    c = make_client()
    r = c.get("/api/lookup", params={"domain": "ads.adnet.example"}).json()
    assert r["domain"] == "ads.adnet.example" and r["agree"]
    for p in r["piholes"]:
        assert p["verdict"]["status"] == "blocked"
        rule = p["rules"][p["verdict"]["by"]]
        assert (rule["source"], rule["entry"], rule["list"]) == ("adlist", "||adnet.example^", BLOCKLIST)


def test_allow_rules_win_in_pihole_order(make_client, main_fake, sec_fake):
    seed(main_fake, sec_fake)
    main_fake.add_domain("deny", "regex", r"(\.|^)example\.net$")
    c = make_client()
    # The allowlist adlist beats the regex block rule, which Pi-hole checks last.
    p = c.get("/api/lookup", params={"domain": "fine.example.net"}).json()["piholes"][0]
    assert p["verdict"]["status"] == "allowed"
    assert [(r["source"], r["action"]) for r in p["rules"]] == [("adlist", "allow"), ("regex", "block")]
    assert p["verdict"]["by"] == 0
    # An exact allow rule beats both the adlist and the regex.
    main_fake.add_domain("allow", "exact", "tracker.example.net")
    p = c.get("/api/lookup", params={"domain": "tracker.example.net"}).json()["piholes"][0]
    assert p["verdict"]["status"] == "allowed"
    assert p["rules"][p["verdict"]["by"]]["source"] == "exact"


def test_disagreement_and_groups(make_client, main_fake, sec_fake):
    main_fake.add_group("Kids")
    main_fake.add_domain("deny", "exact", "games.example", groups=("Kids",))
    c = make_client()
    r = c.get("/api/lookup", params={"domain": "games.example"}).json()
    main_view, sec_view = r["piholes"]
    assert main_view["verdict"]["status"] == "mixed"
    assert {g["group"]: g["status"] for g in main_view["verdict"]["groups"]} == {
        "Default": "not_blocked", "Kids": "blocked"
    }
    assert main_view["rules"][0]["groups"] == ["Kids"]
    assert sec_view["verdict"]["status"] == "not_blocked"
    assert not r["agree"]


def test_disabled_rules_and_groups_dont_count(make_client, main_fake):
    main_fake.add_domain("deny", "exact", "off.example", enabled=False)
    main_fake.add_group("Guests", enabled=False)
    main_fake.add_domain("deny", "exact", "guest.example", groups=("Guests",))
    c = make_client()
    off = c.get("/api/lookup", params={"domain": "off.example"}).json()["piholes"][0]
    assert off["verdict"]["status"] == "not_blocked" and off["rules"][0]["active"] is False
    guest = c.get("/api/lookup", params={"domain": "guest.example"}).json()["piholes"][0]
    assert guest["verdict"]["status"] == "not_blocked" and guest["rules"][0]["active"] is False


def test_recent_queries_and_unreachable_pihole(make_client, main_fake, sec_fake):
    main_fake.query_log = [
        {"time": 100, "domain": "a.example", "status": "GRAVITY", "type": "A", "client": {"ip": "192.168.1.5", "name": "phone"}},
        {"time": 90, "domain": "b.example", "status": "FORWARDED", "type": "A", "client": {"ip": "192.168.1.5"}},
    ]
    sec_fake.down = True
    c = make_client()
    r = c.get("/api/lookup", params={"domain": "a.example"}).json()
    assert [(q["status"], q["client_name"]) for q in r["recent"]] == [("GRAVITY", "phone")]
    assert r["piholes"][1]["error"] and r["piholes"][1]["verdict"] is None
    assert r["agree"]


def test_lookup_refuses_bad_domain(make_client):
    r = make_client().get("/api/lookup", params={"domain": "not a domain"})
    assert r.status_code == 400


def test_allow_removes_exact_block_then_adds_allow_only_if_needed(make_client, main_fake, sec_fake):
    for f in (main_fake, sec_fake):
        f.add_domain("deny", "exact", "ads.example")
    c = make_client(allow_writes=True)
    r = c.post("/api/lookup", json={"domain": "ads.example", "action": "allow"}).json()
    assert [ch["label"] for ch in r["changes"]] == ["ads.example (block, exact)"]
    for f in (main_fake, sec_fake):
        assert f.domains == {}
    assert r["lookup"]["piholes"][0]["verdict"]["status"] == "not_blocked"


def test_allow_adds_exact_allow_over_an_adlist(make_client, main_fake, sec_fake):
    seed(main_fake, sec_fake)
    c = make_client(allow_writes=True)
    r = c.post("/api/lookup", json={"domain": "tracker.example.net", "action": "allow"}).json()
    assert [(ch["action"], ch["label"]) for ch in r["changes"]] == [("add", "tracker.example.net (allow, exact)")]
    for f in (main_fake, sec_fake):
        d = f.domains[("allow", "exact", "tracker.example.net")]
        assert d["comment"] == lookup.COMMENT and d["groups"] == [0]
    assert all(p["verdict"]["status"] == "allowed" for p in r["lookup"]["piholes"])
    events = c.get("/api/events").json()
    assert any("tracker.example.net" in e["message"] for e in events)


def test_block_replaces_exact_allow_and_warns_about_regex_allow(make_client, main_fake, sec_fake):
    for f in (main_fake, sec_fake):
        f.add_domain("allow", "exact", "shop.example")
    main_fake.add_domain("allow", "regex", r"^shop\.")
    c = make_client(allow_writes=True)
    r = c.post("/api/lookup", json={"domain": "shop.example", "action": "block"}).json()
    assert [(ch["action"], ch["label"]) for ch in r["changes"]] == [
        ("delete", "shop.example (allow, exact)"), ("add", "shop.example (block, exact)"),
    ]
    assert r["notes"] and "^shop\\." in r["notes"][0]
    assert ("deny", "exact", "shop.example") in sec_fake.domains
    assert ("allow", "exact", "shop.example") not in sec_fake.domains


def test_lookup_edit_needs_writes(make_client):
    r = make_client(allow_writes=False).post("/api/lookup", json={"domain": "a.example", "action": "block"})
    assert r.status_code == 403
