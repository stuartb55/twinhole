from __future__ import annotations

from dataclasses import replace

import pytest

from twinhole import config
from twinhole.dnsprobe import ProbeResult
from twinhole.pihole import Pihole
from twinhole.store import Store

from .fake_pihole import FakePihole


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def no_restart_wait(monkeypatch):
    """The fake Pi-hole doesn't restart, so don't sit through the restart-detection window."""
    monkeypatch.setattr(Pihole, "settle_window", 0.0)


@pytest.fixture
def settings(tmp_path) -> config.Settings:
    s = config.load({
        "PIHOLE_MAIN_URL": "http://192.168.1.118",
        "PIHOLE_MAIN_NAME": "Main",
        "PIHOLE_SECONDARY_URL": "http://192.168.1.33",
        "PIHOLE_SECONDARY_NAME": "Secondary",
    })
    return replace(s, db_path=str(tmp_path / "twinhole.db"))


@pytest.fixture
def fakes() -> dict[str, FakePihole]:
    return {
        "192.168.1.118": FakePihole("192.168.1.118", "2a00::118"),
        "192.168.1.33": FakePihole("192.168.1.33", "2a00::33"),
    }


@pytest.fixture
def main_fake(fakes) -> FakePihole:
    return fakes["192.168.1.118"]


@pytest.fixture
def sec_fake(fakes) -> FakePihole:
    return fakes["192.168.1.33"]


@pytest.fixture
def main(settings, main_fake) -> Pihole:
    return Pihole(settings.main, transport=main_fake.transport)


@pytest.fixture
def secondary(settings, sec_fake) -> Pihole:
    return Pihole(settings.secondary, transport=sec_fake.transport)


@pytest.fixture
def store(settings) -> Store:
    s = Store(settings.db_path)
    yield s
    s.close()


class RecordingNotifier:
    def __init__(self):
        self.sent: list[dict] = []
        self.fail = False

    async def send(self, title, message, priority, tags):
        if self.fail:
            raise RuntimeError("ntfy is down")
        self.sent.append({"title": title, "message": message, "priority": priority})


@pytest.fixture
def notifier() -> RecordingNotifier:
    return RecordingNotifier()


class FakeDNS:
    """Stands in for dnsprobe.probe; set `failing` to the servers that should fail."""

    def __init__(self):
        self.failing: set[str] = set()
        self.asked: list[str] = []

    async def __call__(self, server, port, domain, timeout):
        self.asked.append(server)
        if server in self.failing:
            return ProbeResult(server, False, None, "no answer within 1000 ms")
        return ProbeResult(server, True, 3.2)


@pytest.fixture
def fake_dns() -> FakeDNS:
    return FakeDNS()


class Clock:
    def __init__(self, t: float = 1_792_500_000):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture
def clock() -> Clock:
    return Clock()
