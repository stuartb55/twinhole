import pytest

from twinhole.alerts import AlertManager
from twinhole.monitor import Monitor, pick_ipv6

pytestmark = pytest.mark.anyio


def test_pick_ipv6_prefers_stable_global_address_on_the_lan_interface():
    interfaces = [
        {"name": "tailscale0", "addresses": [
            {"family": "inet", "address": "100.64.0.1", "scope": "universe", "flags": []},
            {"family": "inet6", "address": "fd7a:115c:a1e0::1", "scope": "universe", "flags": []},
        ]},
        {"name": "eth0", "addresses": [
            {"family": "inet", "address": "192.168.1.118", "scope": "universe", "flags": []},
            {"family": "inet6", "address": "fd00::118", "scope": "universe", "flags": []},
            {"family": "inet6", "address": "2a00:23c8::dead", "scope": "universe", "flags": ["temporary"]},
            {"family": "inet6", "address": "2a00:23c8::118", "scope": "universe", "flags": []},
            {"family": "inet6", "address": "fe80::1", "scope": "link", "flags": []},
        ]},
    ]
    assert pick_ipv6(interfaces, "192.168.1.118") == "2a00:23c8::118"
    assert pick_ipv6(interfaces, "10.0.0.1") is None


def make(settings, main, secondary, store, notifier, fake_dns, clock):
    return Monitor(settings, [main, secondary], AlertManager(store, notifier, clock), fake_dns, clock)


async def test_healthy_cycle_checks_ipv4_and_ipv6_and_records_status(
    settings, main, secondary, store, notifier, fake_dns, clock
):
    mon = make(settings, main, secondary, store, notifier, fake_dns, clock)
    await mon.run_cycle()
    assert set(fake_dns.asked) == {"192.168.1.118", "2a00::118", "192.168.1.33", "2a00::33"}
    st = mon.status["192.168.1.118"]
    assert st["api"]["ok"] and st["dns"]["v4"]["ok"] and st["dns"]["v6"]["ok"]
    assert st["blocking"] == "enabled"
    assert st["versions"]["core"]["local"] == "v6.5"
    assert notifier.sent == []


async def test_unreachable_pihole_alerts_after_two_checks(
    settings, main, secondary, main_fake, store, notifier, fake_dns, clock
):
    mon = make(settings, main, secondary, store, notifier, fake_dns, clock)
    main_fake.down = True
    fake_dns.failing = {"192.168.1.118"}
    await mon.run_cycle()
    assert notifier.sent == []
    clock.advance(30)
    await mon.run_cycle()
    titles = sorted(m["title"] for m in notifier.sent)
    assert titles == ["Main DNS failing (IPv4)", "Main is unreachable"]
    assert all(m["priority"] == 5 for m in notifier.sent)


async def test_ipv6_failure_alone_is_reported(settings, main, secondary, store, notifier, fake_dns, clock):
    mon = make(settings, main, secondary, store, notifier, fake_dns, clock)
    fake_dns.failing = {"2a00::33"}
    for _ in range(2):
        await mon.run_cycle()
        clock.advance(30)
    assert [m["title"] for m in notifier.sent] == ["Secondary DNS failing (IPv6)"]


async def test_short_pause_is_quiet_but_long_one_alerts(
    settings, main, secondary, main_fake, store, notifier, fake_dns, clock
):
    mon = make(settings, main, secondary, store, notifier, fake_dns, clock)
    main_fake.blocking, main_fake.blocking_timer = "disabled", 300
    for _ in range(10):  # 5 minutes
        await mon.run_cycle()
        clock.advance(30)
    main_fake.blocking, main_fake.blocking_timer = "enabled", None
    await mon.run_cycle()
    assert notifier.sent == []

    main_fake.blocking = "disabled"
    for _ in range(22):  # 11 minutes
        await mon.run_cycle()
        clock.advance(30)
    assert [m["title"] for m in notifier.sent] == ["Main blocking is off"]
    assert notifier.sent[0]["priority"] == 3


async def test_stale_gravity_alerts(settings, main, secondary, sec_fake, store, notifier, fake_dns, clock):
    sec_fake.gravity_last_update = int(clock()) - 9 * 86400
    mon = make(settings, main, secondary, store, notifier, fake_dns, clock)
    await mon.run_cycle()
    assert [m["title"] for m in notifier.sent] == ["Secondary gravity is stale"]
    assert "9 days" in notifier.sent[0]["message"]
