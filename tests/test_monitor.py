import httpx
import pytest

from twinhole.alerts import LOW, AlertManager
from twinhole.monitor import Monitor, pick_ipv6
from twinhole.pihole import Pihole

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
    return Monitor(settings, [main, secondary], AlertManager(store, notifier, clock), fake_dns, clock, fake_dns.version)


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


async def test_resolver_checks_record_recursion_dnssec_and_upstreams(
    settings, main, secondary, store, notifier, fake_dns, clock
):
    mon = make(settings, main, secondary, store, notifier, fake_dns, clock)
    await mon.run_cycle()
    res = mon.status["192.168.1.118"]["resolver"]
    assert res["recursion"]["ok"] is True
    assert res["dnssec"]["ok"] is True
    assert res["upstreams"] == [{"server": "127.0.0.1#5335", "name": "localhost", "count": 350, "ms": 25.5}]
    random_names = [d for d in fake_dns.domains if d.startswith("twinhole-")]
    assert len(random_names) == 2 and random_names[0] != random_names[1]
    assert random_names[0].endswith(".example.com")
    assert notifier.sent == []


async def test_resolver_checks_run_on_their_own_schedule(
    settings, main, secondary, store, notifier, fake_dns, clock
):
    mon = make(settings, main, secondary, store, notifier, fake_dns, clock)
    await mon.run_cycle()
    clock.advance(30)
    await mon.run_cycle()
    assert sum(d.startswith("twinhole-") for d in fake_dns.domains) == 2  # once per Pi-hole, not per cycle
    clock.advance(300)
    await mon.run_cycle()
    assert sum(d.startswith("twinhole-") for d in fake_dns.domains) == 4
    assert fake_dns.domains.count("dnssec-failed.org") == 2


async def test_dead_resolver_alerts_after_two_recursion_checks(
    settings, main, secondary, store, notifier, fake_dns, clock
):
    mon = make(settings, main, secondary, store, notifier, fake_dns, clock)
    fake_dns.no_recursion = {"192.168.1.118"}
    await mon.run_cycle()
    assert notifier.sent == []
    clock.advance(300)
    await mon.run_cycle()
    assert [m["title"] for m in notifier.sent] == ["Main can't resolve new names"]
    assert mon.status["192.168.1.118"]["resolver"]["recursion"]["ok"] is False

    fake_dns.no_recursion = set()
    clock.advance(300)
    await mon.run_cycle()
    assert notifier.sent[-1]["title"] == "Recovered - Main can't resolve new names"


async def test_dnssec_off_alerts(settings, main, secondary, store, notifier, fake_dns, clock):
    mon = make(settings, main, secondary, store, notifier, fake_dns, clock)
    fake_dns.no_dnssec = {"192.168.1.33"}
    await mon.run_cycle()
    assert [m["title"] for m in notifier.sent] == ["Secondary isn't validating DNSSEC"]
    assert mon.status["192.168.1.33"]["resolver"]["dnssec"]["ok"] is False


async def test_resolver_checks_skip_a_pihole_whose_dns_is_down(
    settings, main, secondary, store, notifier, fake_dns, clock
):
    mon = make(settings, main, secondary, store, notifier, fake_dns, clock)
    fake_dns.failing = {"192.168.1.118"}
    await mon.run_cycle()
    assert mon.status["192.168.1.118"]["resolver"]["recursion"] is None
    assert mon.status["192.168.1.118"]["resolver"]["dnssec"] is None


async def test_checks_are_rolled_up_for_uptime_and_latency(
    settings, main, secondary, main_fake, store, notifier, fake_dns, clock
):
    mon = make(settings, main, secondary, store, notifier, fake_dns, clock)
    clock.t = 1_792_500_000 - 1_792_500_000 % 600  # start of a bucket
    for _ in range(3):
        await mon.run_cycle()
        clock.advance(30)
    main_fake.down = True
    fake_dns.failing = {"192.168.1.118"}
    await mon.run_cycle()

    up = store.uptime(0)
    assert up["192.168.1.118"]["total"] == 4 and up["192.168.1.118"]["up"] == 3
    assert up["192.168.1.33"] == {"total": 4, "up": 4, "first": clock.t - 90}
    (bucket,) = store.latency_series(0, 600)["192.168.1.118"]
    assert bucket["dns_ms"] == 3.2 and bucket["rec_ms"] == 40.0 and bucket["up_pct"] == 75.0


async def test_recovered_urgent_alerts_become_the_last_outage(
    settings, main, secondary, main_fake, store, notifier, fake_dns, clock
):
    mon = make(settings, main, secondary, store, notifier, fake_dns, clock)
    main_fake.down = True
    for _ in range(2):
        await mon.run_cycle()
        clock.advance(30)
    assert store.last_past_alert("192.168.1.118", 5) is None
    main_fake.down = False
    await mon.run_cycle()
    outage = store.last_past_alert("192.168.1.118", 5)
    assert outage["title"] == "Main is unreachable"
    assert outage["until"] - outage["since"] == 60


async def test_pihole_update_sends_one_low_priority_notice(
    settings, main, secondary, main_fake, store, notifier, fake_dns, clock, monkeypatch
):
    real = main_fake.handle

    def newer(request):
        if request.url.path == "/api/info/version":
            v = {"local": {"version": "v6.5"}, "remote": {"version": "v6.6"}}
            same = {"local": {"version": "v6.5"}, "remote": {"version": "v6.5"}}
            return httpx.Response(200, json={"version": {"core": v, "web": same, "ftl": same}})
        return real(request)

    monkeypatch.setattr(main_fake, "handle", newer)
    main = Pihole(settings.main, transport=main_fake.transport)
    mon = make(settings, main, secondary, store, notifier, fake_dns, clock)
    await mon.run_cycle()
    clock.advance(600)
    await mon.run_cycle()
    assert [(m["title"], m["priority"]) for m in notifier.sent] == [("Main has a Pi-hole update", LOW)]
    assert "Core v6.5 → v6.6" in notifier.sent[0]["message"]


async def test_stalled_when_no_cycle_finishes(settings, main, secondary, store, notifier, fake_dns, clock):
    mon = make(settings, main, secondary, store, notifier, fake_dns, clock)
    assert not mon.stalled()
    clock.advance(200)
    assert mon.stalled()  # never finished a cycle
    await mon.run_cycle()
    assert not mon.stalled()
    clock.advance(121)
    assert mon.stalled()


async def test_resolver_version_is_asked_of_the_pihole_host_on_the_local_upstream_port(
    settings, main, secondary, sec_fake, store, notifier, fake_dns, clock
):
    sec_fake.upstreams.append({"ip": "192.168.1.1", "name": "router", "port": 53, "count": 5,
                               "statistics": {"response": 0.005, "variance": 0}})
    fake_dns.versions = {"192.168.1.118#5335": "unbound 1.22.0"}
    mon = make(settings, main, secondary, store, notifier, fake_dns, clock)
    await mon.run_cycle()
    # The router isn't on the Pi-hole's machine, so it isn't asked.
    assert sorted(fake_dns.version_asked) == ["192.168.1.118#5335", "192.168.1.33#5335"]
    v = mon.status["192.168.1.118"]["resolver"]["version"]
    assert (v["name"], v["version"], v["server"], v["error"]) == ("Unbound", "1.22.0", "192.168.1.118#5335", None)
    v = mon.status["192.168.1.33"]["resolver"]["version"]
    assert v["version"] is None and v["error"] == "no answer"

    # Asked again only with the other slow checks.
    clock.advance(30)
    await mon.run_cycle()
    assert len(fake_dns.version_asked) == 2


async def test_no_resolver_version_without_a_local_upstream(
    settings, main, secondary, main_fake, store, notifier, fake_dns, clock
):
    main_fake.upstreams = [{"ip": "1.1.1.1", "name": "one.one.one.one", "port": 53, "count": 9,
                            "statistics": {"response": 0.01, "variance": 0}}]
    mon = make(settings, main, secondary, store, notifier, fake_dns, clock)
    await mon.run_cycle()
    assert mon.status["192.168.1.118"]["resolver"]["version"] is None
    assert fake_dns.version_asked == ["192.168.1.33#5335"]
