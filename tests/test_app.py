from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from twinhole.app import create_app


@pytest.fixture
def make_client(settings, fakes, notifier, fake_dns):
    clients = []

    def make(**overrides):
        app = create_app(
            replace(settings, **overrides),
            background=False,
            transports={pid: f.transport for pid, f in fakes.items()},
            probe=fake_dns,
            notifier=notifier,
        )
        client = TestClient(app)
        client.__enter__()
        clients.append(client)
        return client

    yield make
    for c in clients:
        c.__exit__(None, None, None)


def test_dashboard_and_health(make_client):
    c = make_client()
    assert c.get("/healthz").json() == {"ok": True}
    page = c.get("/")
    assert page.status_code == 200 and "twinhole" in page.text


def test_read_only_mode_refuses_every_write(make_client):
    c = make_client(allow_writes=False)
    writes = [
        ("/api/sync/apply", {"plan_id": "x"}),
        ("/api/manage", {"resource": "domains", "action": "add", "key": ["deny", "exact", "a.example"]}),
        ("/api/actions/blocking", {"target": "both", "enabled": False, "minutes": 5}),
        ("/api/actions/gravity", {"target": "both"}),
    ]
    for path, body in writes:
        r = c.post(path, json=body)
        assert r.status_code == 403, path
        assert "ALLOW_WRITES" in r.json()["detail"]
    # Reading still works, including the sync preview.
    assert c.post("/api/sync/preview").status_code == 200


def test_sync_preview_then_apply(make_client, main_fake, sec_fake):
    main_fake.add_domain("deny", "exact", "ads.example")
    sec_fake.add_domain("deny", "exact", "stale.example")
    c = make_client(allow_writes=True)

    preview = c.post("/api/sync/preview").json()
    assert preview["summary"] == "+1 domain, -1 domain"
    assert [ch["action"] for ch in preview["changes"]] == ["add", "delete"]

    result = c.post("/api/sync/apply", json={"plan_id": preview["plan_id"]}).json()
    assert all(r["ok"] for r in result["results"])
    assert result["after"]["summary"] == "in sync"
    assert set(sec_fake.domains) == {("deny", "exact", "ads.example")}


def test_apply_refuses_a_plan_that_changed_since_preview(make_client, main_fake, sec_fake):
    main_fake.add_domain("deny", "exact", "ads.example")
    c = make_client(allow_writes=True)
    preview = c.post("/api/sync/preview").json()
    sec_fake.add_domain("deny", "exact", "surprise.example")
    r = c.post("/api/sync/apply", json={"plan_id": preview["plan_id"]})
    assert r.status_code == 409
    assert "surprise.example" not in str(main_fake.domains) and ("deny", "exact", "surprise.example") in sec_fake.domains


def test_sync_that_changes_adlists_rebuilds_gravity_on_the_secondary(make_client, main_fake, sec_fake):
    main_fake.add_list("block", "https://lists.example/hosts.txt")
    c = make_client(allow_writes=True)
    preview = c.post("/api/sync/preview").json()
    result = c.post("/api/sync/apply", json={"plan_id": preview["plan_id"]}).json()
    assert result["gravity_started"] is True


def test_edits_go_to_main_then_secondary(make_client, main_fake, sec_fake):
    c = make_client(allow_writes=True)
    r = c.post("/api/manage", json={
        "resource": "domains", "action": "add", "key": ["deny", "regex", r"(\.|^)tiktok\.com$"], "comment": "kids",
    }).json()
    assert [x["ok"] for x in r["results"]] == [True, True]
    key = ("deny", "regex", r"(\.|^)tiktok\.com$")
    assert main_fake.domains[key]["comment"] == "kids" and key in sec_fake.domains

    r = c.post("/api/manage", json={"resource": "hosts", "action": "add", "key": ["192.168.1.50   nas.lan"]}).json()
    assert main_fake.hosts == ["192.168.1.50 nas.lan"] == sec_fake.hosts


def test_edit_add_heals_an_item_already_on_the_secondary(make_client, main_fake, sec_fake):
    sec_fake.add_domain("deny", "exact", "ads.example", enabled=False)
    c = make_client(allow_writes=True)
    r = c.post("/api/manage", json={"resource": "domains", "action": "add", "key": ["deny", "exact", "ads.example"]})
    assert [x["ok"] for x in r.json()["results"]] == [True, True]
    assert sec_fake.domains[("deny", "exact", "ads.example")]["enabled"] is True


def test_deleting_an_item_only_on_the_secondary(make_client, sec_fake):
    sec_fake.hosts.append("192.168.1.99  old.lan")
    c = make_client(allow_writes=True)
    view = c.get("/api/manage").json()
    row = view["hosts"][0]
    assert (row["on_main"], row["on_secondary"]) == (False, True)
    r = c.post("/api/manage", json={"resource": "hosts", "action": "delete", "key": row["key"]}).json()
    assert [x["ok"] for x in r["results"]] == [True, True]
    assert sec_fake.hosts == []


def test_main_failure_leaves_secondary_untouched(make_client, main_fake, sec_fake):
    c = make_client(allow_writes=True)
    r = c.post("/api/manage", json={"resource": "lists", "action": "add", "key": ["block", "https://x.example/a b"]})
    results = r.json()["results"]
    assert len(results) == 1 and results[0]["ok"] is False
    assert sec_fake.lists == {}


def test_edit_validation(make_client):
    c = make_client(allow_writes=True)
    bad = [
        {"resource": "domains", "action": "add", "key": ["block", "exact", "a.example"]},
        {"resource": "hosts", "action": "add", "key": ["nas.lan"]},
        {"resource": "cnames", "action": "add", "key": ["files.lan"]},
        {"resource": "hosts", "action": "update", "key": ["1.2.3.4 a.lan"]},
    ]
    for body in bad:
        assert c.post("/api/manage", json=body).status_code == 400, body


def test_blocking_pause_on_one_pihole(make_client, main_fake, sec_fake):
    c = make_client(allow_writes=True)
    r = c.post("/api/actions/blocking", json={"target": "secondary", "enabled": False, "minutes": 5})
    assert r.status_code == 200
    assert (sec_fake.blocking, sec_fake.blocking_timer) == ("disabled", 300)
    assert main_fake.blocking == "enabled"


def test_query_log_merges_both_piholes_newest_first(make_client, main_fake, sec_fake):
    main_fake.query_log = [{"time": 100.0, "domain": "a.example", "status": "GRAVITY", "client": {"ip": "1.1.1.1"}}]
    sec_fake.query_log = [{"time": 200.0, "domain": "b.example", "status": "FORWARDED", "client": {"ip": "2.2.2.2"}}]
    c = make_client()
    rows = c.get("/api/queries").json()["queries"]
    assert [(r["domain"], r["pihole"]) for r in rows] == [("b.example", "192.168.1.33"), ("a.example", "192.168.1.118")]


def test_query_log_filters_to_a_devices_addresses(make_client, main_fake, sec_fake):
    main_fake.query_log = [
        {"time": 100.0, "domain": "a.example", "status": "GRAVITY", "client": {"ip": "1.1.1.1"}},
        {"time": 150.0, "domain": "other.example", "status": "FORWARDED", "client": {"ip": "9.9.9.9"}},
    ]
    sec_fake.query_log = [{"time": 200.0, "domain": "b.example", "status": "FORWARDED", "client": {"ip": "fd00::1"}}]
    rows = make_client().get("/api/queries", params={"client": ["1.1.1.1", "fd00::1"]}).json()["queries"]
    assert [r["domain"] for r in rows] == ["b.example", "a.example"]


def test_query_log_reports_an_unreachable_pihole(make_client, main_fake):
    main_fake.down = True
    body = make_client().get("/api/queries").json()
    assert body["errors"] and body["errors"][0].startswith("Main")


def test_edit_creates_a_group_the_secondary_is_missing(make_client, main_fake, sec_fake):
    main_fake.add_group("kids", comment="Children", enabled=True)  # made in .118's own UI, not synced yet
    c = make_client(allow_writes=True)
    r = c.post("/api/manage", json={"resource": "clients", "action": "add", "key": ["aa:bb:cc:dd:ee:ff"], "groups": ["kids"]})
    assert [x["ok"] for x in r.json()["results"]] == [True, True]
    assert sec_fake.groups["kids"]["comment"] == "Children"
    assert sec_fake.clients["aa:bb:cc:dd:ee:ff"]["groups"] == [sec_fake.groups["kids"]["id"]]
