from dataclasses import replace

import pytest

from twinhole.alerts import AlertManager
from twinhole.services import GravityRunner, SyncService

pytestmark = pytest.mark.anyio


@pytest.fixture
def make_service(settings, main, secondary, store, notifier, clock):
    def make(**overrides):
        s = replace(settings, **{"allow_writes": True, "auto_sync": True, **overrides})
        alerts = AlertManager(store, notifier, clock)
        return SyncService(s, main, secondary, store, alerts, GravityRunner(store))

    return make


async def test_applies_drift_by_itself(make_service, main_fake, sec_fake, store):
    main_fake.add_domain("deny", "exact", "ads.example")
    sec_fake.add_domain("deny", "exact", "stale.example")
    svc = make_service()
    await svc.check_drift()
    assert set(sec_fake.domains) == {("deny", "exact", "ads.example")}
    assert svc.last["changes"] == []
    assert svc.auto["held"] is None
    assert store.events(5)[0]["message"].startswith("Auto-synced")


async def test_does_nothing_unless_turned_on(make_service, main_fake, sec_fake):
    main_fake.add_domain("deny", "exact", "ads.example")
    svc = make_service(auto_sync=False)
    await svc.check_drift()
    assert sec_fake.domains == {}
    assert svc.last["summary"] == "+1 domain"


async def test_needs_writes_enabled(make_service, main_fake, sec_fake):
    main_fake.add_domain("deny", "exact", "ads.example")
    svc = make_service(allow_writes=False)
    await svc.check_drift()
    assert sec_fake.domains == {}
    assert svc.auto["enabled"] is False


async def test_holds_when_it_would_delete_too_much(make_service, main_fake, sec_fake, notifier):
    main_fake.add_domain("deny", "exact", "keep.example")
    for i in range(6):
        sec_fake.add_domain("deny", "exact", f"old{i}.example")
    svc = make_service()
    await svc.check_drift()
    assert len(sec_fake.domains) == 6  # untouched
    assert "delete 6 items" in svc.auto["held"]["reason"]
    assert [m["title"] for m in notifier.sent] == ["Auto-sync is waiting for you"]

    await svc.check_drift()  # still held: no second alert
    assert len(notifier.sent) == 1

    # Five deletions is within the limit.
    del sec_fake.domains[("deny", "exact", "old5.example")]
    await svc.check_drift()
    assert set(sec_fake.domains) == {("deny", "exact", "keep.example")}
    assert svc.auto["held"] is None
    assert notifier.sent[-1]["title"] == "Recovered - Auto-sync is waiting for you"


async def test_holds_when_an_adlist_would_go(make_service, main_fake, sec_fake):
    main_fake.add_domain("deny", "exact", "keep.example")
    sec_fake.add_list("block", "https://lists.example/hosts.txt")
    svc = make_service()
    await svc.check_drift()
    assert ("block", "https://lists.example/hosts.txt") in sec_fake.lists
    assert "remove 1 adlist" in svc.auto["held"]["reason"]


async def test_holds_when_main_looks_empty(make_service, main_fake, sec_fake):
    sec_fake.add_domain("deny", "exact", "ads.example")
    svc = make_service()
    await svc.check_drift()
    assert ("deny", "exact", "ads.example") in sec_fake.domains
    assert "looks empty" in svc.auto["held"]["reason"]


async def test_a_failed_read_never_syncs(make_service, main_fake, sec_fake):
    main_fake.add_domain("deny", "exact", "ads.example")
    main_fake.down = True
    svc = make_service()
    await svc.check_drift()
    assert sec_fake.domains == {}
    assert svc.last["error"]


async def test_manual_apply_clears_a_hold(make_service, main_fake, sec_fake):
    main_fake.add_domain("deny", "exact", "keep.example")
    sec_fake.add_list("block", "https://lists.example/hosts.txt")
    svc = make_service()
    await svc.check_drift()
    assert svc.auto["held"]
    preview = await svc.preview()
    await svc.apply(preview["plan_id"])
    assert svc.auto["held"] is None
    assert sec_fake.lists == {}
