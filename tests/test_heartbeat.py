import httpx
import pytest

from twinhole.heartbeat import Heartbeat

pytestmark = pytest.mark.anyio


async def test_calls_the_url_at_most_once_per_interval(clock):
    calls = []
    hb = Heartbeat("https://hc.example/ping/abc", 60, clock,
                   httpx.MockTransport(lambda r: calls.append(str(r.url)) or httpx.Response(200)))
    await hb.beat()
    clock.advance(30)
    await hb.beat()
    assert calls == ["https://hc.example/ping/abc"]
    clock.advance(31)
    await hb.beat()
    assert len(calls) == 2 and hb.status()["error"] is None
    await hb.aclose()


async def test_a_failed_call_is_noted_not_raised(clock):
    hb = Heartbeat("https://hc.example/ping/abc", 60, clock, httpx.MockTransport(lambda r: httpx.Response(503)))
    await hb.beat()
    assert hb.status()["error"] and hb.status()["last_ok"] is None
    await hb.aclose()


async def test_off_without_a_url(clock):
    hb = Heartbeat("", 60, clock)
    await hb.beat()
    assert hb.status() == {"enabled": False, "last_ok": None, "error": None}


async def test_the_monitor_beats_after_each_cycle(settings, main, secondary, store, notifier, fake_dns, clock):
    from twinhole.alerts import AlertManager
    from twinhole.monitor import Monitor

    calls = []
    hb = Heartbeat("https://hc.example/ping/abc", 60, clock,
                   httpx.MockTransport(lambda r: calls.append(1) or httpx.Response(200)))
    mon = Monitor(settings, [main, secondary], AlertManager(store, notifier, clock), fake_dns, clock,
                  fake_dns.version, fake_dns.latest_unbound, hb)
    await mon.run_cycle()
    assert calls == [1]
    await hb.aclose()
