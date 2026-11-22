from dataclasses import replace

import pytest

from twinhole import config
from twinhole.alerts import AlertManager
from twinhole.settings_check import SettingsCheck, compare


@pytest.fixture
def make_check(settings, main, secondary, store, notifier, clock):
    def make(**overrides):
        alerts = AlertManager(store, notifier, clock)
        return SettingsCheck(replace(settings, **overrides), main, secondary, alerts, clock), alerts

    return make


def test_compare_ignores_order_of_upstreams_and_missing_settings():
    a = {"dns": {"upstreams": ["127.0.0.1#5335", "::1#5335"], "dnssec": True}}
    b = {"dns": {"upstreams": ["::1#5335", "127.0.0.1#5335"], "dnssec": False}}
    rows = {r["path"]: r for r in compare(a, b)}
    assert rows["dns.upstreams"]["same"]
    assert not rows["dns.dnssec"]["same"]
    assert "dns.cache.size" not in rows  # neither Pi-hole has it


def test_compare_setting_only_one_side_has():
    rows = {r["path"]: r for r in compare({"dns": {"domain": {"name": "lan", "local": True}}}, {"dns": {"domain": {"name": "lan"}}})}
    assert rows["dns.domain.name"]["same"]
    assert rows["dns.domain.local"] == {
        "path": "dns.domain.local", "label": "Local domain answered locally only",
        "main": True, "secondary": None, "same": False,
    }


def test_ignore_list_skips_settings_and_their_children():
    a = {"dns": {"dnssec": True, "cache": {"size": 1, "optimizer": 1}}}
    b = {"dns": {"dnssec": False, "cache": {"size": 2, "optimizer": 2}}}
    paths = {r["path"] for r in compare(a, b, ("dns.dnssec", "dns.cache"))}
    assert paths == set()


def test_settings_ignore_env():
    s = config.load({
        "PIHOLE_MAIN_URL": "http://192.168.1.118", "PIHOLE_SECONDARY_URL": "http://192.168.1.33",
        "SETTINGS_IGNORE": "dns.cache.size, misc.privacylevel",
    })
    assert s.settings_ignore == ("dns.cache.size", "misc.privacylevel")


@pytest.mark.anyio
async def test_alerts_after_the_grace_period_and_recovers(make_check, main_fake, sec_fake, notifier, clock):
    check, alerts = make_check()
    last = await check.run()
    assert last["differences"] == 0 and last["error"] is None and last["rows"]

    sec_fake.config["dns"]["upstreams"] = ["8.8.8.8"]
    sec_fake.config["dns"]["dnssec"] = True
    last = await check.run()
    assert last["differences"] == 2
    assert not notifier.sent  # waits for drift_grace, like sync drift

    clock.advance(check.settings.drift_grace)
    await check.run()
    assert notifier.sent[-1]["title"] == "Pi-hole settings differ"
    assert "Upstream DNS servers (127.0.0.1#5335 vs 8.8.8.8)" in notifier.sent[-1]["message"]
    assert "DNSSEC validation (off vs on)" in notifier.sent[-1]["message"]

    sec_fake.config["dns"]["upstreams"] = ["127.0.0.1#5335"]
    sec_fake.config["dns"]["dnssec"] = False
    await check.run()
    assert notifier.sent[-1]["title"] == "Recovered - Pi-hole settings differ"
    assert "settings:drift" not in alerts.active


@pytest.mark.anyio
async def test_local_dns_records_and_machine_settings_are_not_compared(make_check, main_fake, sec_fake):
    check, _ = make_check()
    main_fake.hosts.append("192.168.1.50 nas.lan")
    sec_fake.config["dns"]["interface"] = "wlan0"
    sec_fake.config["webserver"]["port"] = "8080"
    assert (await check.run())["differences"] == 0


@pytest.mark.anyio
async def test_unreadable_pihole_keeps_the_alert_as_it_is(make_check, sec_fake, notifier, clock):
    check, alerts = make_check(drift_grace=0)
    sec_fake.config["dns"]["dnssec"] = True
    await check.run()
    assert "settings:drift" in alerts.active
    sec_fake.down = True
    last = await check.run()
    assert last["error"] and last["differences"] == 1  # the last comparison is kept
    assert "settings:drift" in alerts.active
    assert len(notifier.sent) == 1


def test_status_and_api(settings, fakes, notifier, fake_dns, sec_fake):
    from fastapi.testclient import TestClient

    from twinhole.app import create_app

    app = create_app(
        settings, background=False, transports={pid: f.transport for pid, f in fakes.items()},
        probe=fake_dns, version_query=fake_dns.version, latest_unbound=fake_dns.latest_unbound, notifier=notifier,
    )
    sec_fake.config["dns"]["blocking"]["mode"] = "NXDOMAIN"
    with TestClient(app) as c:
        assert c.get("/api/status").json()["settings"] == {"checked": None, "error": None, "differences": 0}
        r = c.post("/api/settings/check").json()
        assert [(x["label"], x["main"], x["secondary"]) for x in r["rows"] if not x["same"]] == [
            ("Blocking mode", "NULL", "NXDOMAIN")
        ]
        assert c.get("/api/settings").json()["differences"] == 1
        assert c.get("/api/status").json()["settings"]["differences"] == 1
