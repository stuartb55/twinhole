import httpx
import pytest

from twinhole.alerts import LOW, URGENT, AlertManager, Ntfy

pytestmark = pytest.mark.anyio


async def observe(mgr, bad, **kw):
    args = dict(pihole="p1", title="Main is unreachable", detail="timeout", priority=URGENT, after_count=2)
    args.update(kw)
    await mgr.observe("p1:api", bad, **args)


async def test_fires_once_after_threshold_then_recovers_once(store, notifier, clock):
    mgr = AlertManager(store, notifier, clock)
    await observe(mgr, True)
    assert notifier.sent == []
    await observe(mgr, True)
    await observe(mgr, True)
    assert [m["title"] for m in notifier.sent] == ["Main is unreachable"]
    assert notifier.sent[0]["priority"] == URGENT

    clock.advance(300)
    await observe(mgr, False)
    await observe(mgr, False)
    assert [m["title"] for m in notifier.sent] == ["Main is unreachable", "Recovered - Main is unreachable"]
    assert notifier.sent[1]["priority"] == LOW
    assert "was down" in notifier.sent[1]["message"]


async def test_a_single_blip_does_not_alert(store, notifier, clock):
    mgr = AlertManager(store, notifier, clock)
    await observe(mgr, True)
    await observe(mgr, False)
    await observe(mgr, True)
    assert notifier.sent == []


async def test_waits_for_duration(store, notifier, clock):
    mgr = AlertManager(store, notifier, clock)
    kw = dict(after_count=1, after_seconds=600, title="Blocking is off")
    await observe(mgr, True, **kw)
    clock.advance(300)
    await observe(mgr, True, **kw)
    assert notifier.sent == []
    clock.advance(301)
    await observe(mgr, True, **kw)
    assert [m["title"] for m in notifier.sent] == ["Blocking is off"]


async def test_unknown_changes_nothing(store, notifier, clock):
    mgr = AlertManager(store, notifier, clock)
    await observe(mgr, True)
    await observe(mgr, True)
    await observe(mgr, None)
    assert "p1:api" in mgr.active
    assert len(notifier.sent) == 1


async def test_active_alerts_survive_a_restart(store, notifier, clock):
    mgr = AlertManager(store, notifier, clock)
    await observe(mgr, True)
    await observe(mgr, True)

    restarted = AlertManager(store, notifier, clock)
    await observe(restarted, True)
    await observe(restarted, True)
    assert len(notifier.sent) == 1  # no repeat after restart
    await observe(restarted, False)
    assert notifier.sent[-1]["title"].startswith("Recovered")


async def test_broken_ntfy_does_not_stop_monitoring(store, notifier, clock):
    notifier.fail = True
    mgr = AlertManager(store, notifier, clock)
    await observe(mgr, True)
    await observe(mgr, True)
    assert "p1:api" in mgr.active
    assert any("Could not send" in e["message"] for e in store.events())


async def test_ntfy_publishes_json_with_token_and_explains_refusals(store, clock):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(403 if request.headers.get("authorization") != "Bearer tk" else 200)

    good = Ntfy("https://ntfy.example", "pihole", "tk", transport=httpx.MockTransport(handler))
    await good.send("Main is unreachable", "timeout", URGENT, ["warning"])
    body = seen[-1].read()
    assert b'"topic":"pihole"' in body.replace(b" ", b"") and b'"priority":5' in body.replace(b" ", b"")

    anonymous = Ntfy("https://ntfy.example", "pihole", "", transport=httpx.MockTransport(handler))
    mgr = AlertManager(store, anonymous, clock)
    await observe(mgr, True, after_count=1)
    assert "set NTFY_TOKEN" in store.events()[0]["message"]


async def test_unsent_alerts_are_retried_in_order_once_ntfy_is_back(store, notifier, clock):
    notifier.fail = True
    mgr = AlertManager(store, notifier, clock)
    await observe(mgr, True, after_count=1)
    clock.advance(60)
    await observe(mgr, False)
    assert len(mgr.outbox) == 2 and notifier.sent == []
    await mgr.flush()  # still down: nothing lost
    assert len(mgr.outbox) == 2

    notifier.fail = False
    clock.advance(60)
    await mgr.flush()
    assert [m["title"] for m in notifier.sent] == ["Main is unreachable", "Recovered - Main is unreachable"]
    assert "sent late" in notifier.sent[0]["message"]
    assert mgr.outbox == []
    assert any("Sent alert 'Main is unreachable' late" in e["message"] for e in store.events())


async def test_a_new_alert_waits_behind_older_unsent_ones(store, notifier, clock):
    notifier.fail = True
    mgr = AlertManager(store, notifier, clock)
    await observe(mgr, True, after_count=1)
    notifier.fail = False
    await mgr.observe("p2:api", True, pihole="p2", title="Second is unreachable", detail="x", priority=URGENT)
    assert [m["title"] for m in notifier.sent] == ["Main is unreachable", "Second is unreachable"]


async def test_gives_up_on_a_message_after_a_day(store, notifier, clock):
    notifier.fail = True
    mgr = AlertManager(store, notifier, clock)
    await observe(mgr, True, after_count=1)
    clock.advance(25 * 3600)
    await mgr.flush()
    assert mgr.outbox == []
    assert any("Gave up sending" in e["message"] for e in store.events())
