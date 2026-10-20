"""Runs against two real, throwaway Pi-hole v6 containers.

    scripts/test-piholes.sh up
    uv run pytest -m integration
    scripts/test-piholes.sh down

These tests wipe and reseed the test containers, so they refuse to run against
anything but localhost.
"""

import asyncio
import time

import pytest

from twinhole import config, dnsprobe
from twinhole.alerts import AlertManager
from twinhole.history import History
from twinhole.monitor import Monitor
from twinhole.pihole import Pihole, PiholeError
from twinhole.services import Editor, GravityRunner
from twinhole.store import Store
from twinhole.sync import Change, apply, plan, snapshot, summarize

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

ENV = {
    "PIHOLE_MAIN_URL": "http://127.0.0.1:18081",
    "PIHOLE_MAIN_ID": "test-ph1",
    "PIHOLE_MAIN_NAME": "Test main",
    "PIHOLE_MAIN_DNS": "127.0.0.1:15301",
    "PIHOLE_SECONDARY_URL": "http://127.0.0.1:18082",
    "PIHOLE_SECONDARY_ID": "test-ph2",
    "PIHOLE_SECONDARY_NAME": "Test secondary",
    "PIHOLE_SECONDARY_DNS": "127.0.0.1:15302",
}


@pytest.fixture(autouse=True)
def no_restart_wait():
    """Real Pi-holes do restart after DNS config changes, so keep the real wait."""


@pytest.fixture
def settings(tmp_path):
    s = config.load(ENV | {"DB_PATH": str(tmp_path / "it.db")})
    assert all("127.0.0.1" in p.url for p in s.piholes), "integration tests only run against localhost"
    return s


@pytest.fixture
async def piholes(settings):
    ps = [Pihole(settings.main), Pihole(settings.secondary)]
    try:
        for p in ps:
            await p.groups()
    except PiholeError:
        pytest.skip("test Pi-holes not running: scripts/test-piholes.sh up")
    for p in ps:
        await wipe(p)
    yield ps
    for p in ps:
        await wipe(p)
        await p.aclose()


async def wipe(p: Pihole) -> None:
    for d in await p.domains():
        await p.delete_domain(d["type"], d["kind"], d["domain"])
    for lst in await p.lists():
        if "StevenBlack" not in lst["address"]:  # keep the image's default list
            await p.delete_list(lst["type"], lst["address"])
    for c in await p.clients():
        await p.delete_client(c["client"])
    if await p.hosts() or await p.cnames():
        await p.set_dns_records([], [])
    for g in await p.groups():
        if g["id"] != 0:
            await p.delete_group(g["name"])


def ids(groups, *names):
    by_name = {g["name"]: g["id"] for g in groups}
    return [by_name[n] for n in names]


async def test_sync_makes_a_real_secondary_mirror_the_main(piholes):
    main, sec = piholes
    # Secondary gets its groups first so the IDs differ from the main's.
    await sec.add_group("old", "to be removed", True)
    await sec.add_group("kids", "", True)
    for name, enabled in (("kids", True), ("iot", False)):
        await main.add_group(name, f"{name} devices", enabled)
    mg, sg = await main.groups(), await sec.groups()
    assert ids(mg, "kids") != ids(sg, "kids")

    await main.add_domain("deny", "regex", r"(\.|^)tiktok\.com$", "kids rule", ids(mg, "kids"), True)
    await main.add_domain("allow", "exact", "good.example", None, ids(mg, "Default", "iot"), True)
    await main.add_domain("deny", "exact", "toggle.example", None, ids(mg, "Default"), False)
    await main.add_list("block", "https://lists.example/hosts.txt?a=1&b=two", "q", ids(mg, "Default", "kids"), True)
    await main.add_list("allow", "https://lists.example/allow.txt", None, ids(mg, "Default"), False)
    await main.add_client("192.168.50.0/24", "LAN", ids(mg, "kids"))
    await main.add_client("AA:BB:CC:DD:EE:FF", None, ids(mg, "Default"))
    await main.add_host("192.168.1.50 nas.lan")
    await main.add_host("192.168.1.51 printer.lan printer")
    await main.add_cname("files.lan,nas.lan")

    await sec.add_domain("deny", "exact", "toggle.example", "different", ids(sg, "Default"), True)
    await sec.add_domain("deny", "exact", "only-on-secondary.example", None, ids(sg, "old"), True)
    await sec.add_list("block", "https://lists.example/stale.txt", None, ids(sg, "Default"), True)
    await sec.add_client("10.0.0.9", "gone", ids(sg, "Default"))
    await sec.add_host("192.168.1.99 old.lan")
    await sec.add_cname("old.lan,nas.lan")

    (want, _), (have, group_ids) = await snapshot(main), await snapshot(sec)
    changes = plan(want, have)
    assert summarize(changes) == (
        "+1 group, -1 group, ~1 group, +2 domains, -1 domain, ~1 domain, +2 adlists, -1 adlist, "
        "+2 clients, -1 client, +2 local DNS records, -1 local DNS record, +1 CNAME, -1 CNAME"
    )
    results = await apply(sec, changes, group_ids)
    assert [r for r in results if not r["ok"]] == []

    (want, _), (have, _) = await snapshot(main), await snapshot(sec)
    assert plan(want, have) == []
    tiktok = next(d for d in await sec.domains() if d["kind"] == "regex")
    assert tiktok["domain"] == r"(\.|^)tiktok\.com$" and tiktok["comment"] == "kids rule"


async def test_write_through_edits_on_real_piholes(piholes, settings, tmp_path):
    main, sec = piholes
    editor = Editor(main, sec, Store(str(tmp_path / "e.db")))
    key = ("deny", "regex", r"^ads?\d*\.example$")
    add = Change("domains", "add", key, {"comment": "", "groups": ["Default"], "enabled": True}, None)
    assert [r["ok"] for r in await editor.edit(add)] == [True, True]
    toggle = Change("domains", "update", key, {"comment": "off", "groups": ["Default"], "enabled": False}, None)
    assert [r["ok"] for r in await editor.edit(toggle)] == [True, True]
    for p in piholes:
        assert [d["enabled"] for d in await p.domains()] == [False]

    # Adding something the secondary already has heals it instead of failing.
    await sec.add_domain("deny", "exact", "dup.example", "stale", [0], False)
    dup = Change("domains", "add", ("deny", "exact", "dup.example"), {"comment": "", "groups": ["Default"], "enabled": True}, None)
    assert [r["ok"] for r in await editor.edit(dup)] == [True, True]

    # Deleting something only the secondary has works (404 on main is fine).
    await sec.add_host("192.168.1.98 lonely.lan")
    gone = Change("hosts", "delete", ("192.168.1.98 lonely.lan",), None, None)
    assert [r["ok"] for r in await editor.edit(gone)] == [True, True]
    assert await sec.hosts() == []


async def test_monitor_and_history_against_real_piholes(piholes, settings, tmp_path):
    store = Store(str(tmp_path / "m.db"))
    sent = []

    class Rec:
        async def send(self, title, message, priority, tags):
            sent.append(title)

    mon = Monitor(settings, piholes, AlertManager(store, Rec()))
    await mon.run_cycle()
    for st in mon.status.values():
        assert st["api"]["ok"], st
        assert st["dns"]["v4"]["ok"], st["dns"]
        assert st["dns"]["v6"] is None  # 127.0.0.1 isn't on the container's interfaces
        assert st["versions"]["ftl"]["local"].startswith("v6")
        assert st["blocking"] == "enabled"

    h = History(settings, piholes, store)
    await h.run()
    assert store.get_meta("backfill:test-ph1")
    await piholes[0].queries(10)
    for d in await piholes[0].network_devices():
        assert {"hwaddr", "numQueries", "lastQuery", "ips"} <= set(d)


async def test_dns_probe_reports_failures():
    ok = await dnsprobe.probe("127.0.0.1", 15301, "example.com", 2.0)
    assert ok.ok and ok.ms is not None
    bad = await dnsprobe.probe("127.0.0.1", 15399, "example.com", 0.5)
    assert not bad.ok and bad.error


async def test_gravity_streams_output(piholes, tmp_path):
    runner = GravityRunner(Store(str(tmp_path / "g.db")))
    sec = piholes[1]
    assert runner.start(sec, "test")
    assert not runner.start(sec, "test")  # one run at a time
    deadline = time.time() + 240
    while runner.running(sec) and time.time() < deadline:
        await asyncio.sleep(1)
    run = runner.status()[sec.id]
    assert run["ok"] is True, run
    assert any("gravity" in line.lower() or "list" in line.lower() for line in run["log"])
