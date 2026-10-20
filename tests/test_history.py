from datetime import date

import pytest

from twinhole.history import History

pytestmark = pytest.mark.anyio


def bucket(ts, total=10, blocked=2):
    return {"timestamp": ts, "total": total, "blocked": blocked, "cached": 3, "forwarded": 5}


def test_day_bounds_follow_london_time_including_dst(settings, store, main, secondary):
    h = History(settings, [main, secondary], store)
    start, end = h.day_bounds(date(2026, 10, 25))  # clocks go back: a 25-hour day
    assert end - start == 25 * 3600
    start, end = h.day_bounds(date(2026, 7, 1))
    assert end - start == 24 * 3600
    assert h.day_of(start).isoformat() == "2026-07-01"


async def test_backfill_runs_once_and_imports_history_and_daily_tops(
    settings, store, main, secondary, main_fake, clock
):
    now = int(clock())
    main_fake.history_db = [bucket(now - 3 * 86400), bucket(now - 2 * 86400), bucket(now - 600)]
    main_fake.top["blocked"] = [{"domain": "ads.example", "count": 40}]
    main_fake.top["clients"] = [{"ip": "192.168.1.111", "name": "mini.lan", "count": 99}]
    h = History(settings, [main, secondary], store, clock)

    await h.backfill(main)
    calls_after_first = len(main_fake.calls)
    await h.backfill(main)
    assert len(main_fake.calls) == calls_after_first  # second run is a no-op

    series = store.history_series(0, 600)
    assert len(series["192.168.1.118"]) == 3
    days = store.top_days()
    assert len(days) == 2  # today's partial day isn't snapshotted
    top = store.top("blocked", days[-1], days[0], None, 10)
    assert top == [{"item": "ads.example", "label": None, "count": 80}]
    clients = store.top("clients", days[-1], days[0], "192.168.1.118", 10)
    assert clients[0]["label"] == "mini.lan"


async def test_recent_import_replaces_the_partial_bucket(settings, store, main, secondary, main_fake, clock):
    h = History(settings, [main, secondary], store, clock)
    ts = int(clock()) // 600 * 600
    main_fake.history = [bucket(ts, total=5)]
    await h.run()
    main_fake.history = [bucket(ts, total=50)]
    await h.run()
    assert store.history_series(0, 600)["192.168.1.118"][0]["total"] == 50


async def test_daily_series_buckets_start_at_local_midnight(store):
    # 2026-07-01 23:30 London (BST, UTC+1) belongs to 1 July, not 2 July.
    ts = 1782945000  # 2026-07-01 22:30 UTC
    store.upsert_history("p", [bucket(ts)])
    series = store.history_series(0, 86400, offset=3600)
    assert series["p"][0]["t"] == 1782860400  # 2026-07-01 00:00 BST
