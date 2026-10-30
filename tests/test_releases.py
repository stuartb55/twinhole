import httpx
import pytest

from twinhole.releases import UNBOUND_LATEST, latest_unbound, parse_version

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize("text, version", [
    ("release-1.24.2", (1, 24, 2)),
    ("Unbound 1.22.0", (1, 22, 0)),
    ("1.9", (1, 9)),
    ("nightly", None),
])
def test_parse_version(text, version):
    assert parse_version(text) == version


def test_versions_compare_numerically():
    assert parse_version("1.9.6") < parse_version("1.10.0")


async def test_latest_unbound_reads_the_release_tag():
    def handle(request):
        assert str(request.url) == UNBOUND_LATEST
        return httpx.Response(200, json={"tag_name": "release-1.24.2", "name": "1.24.2"})

    assert await latest_unbound(httpx.MockTransport(handle)) == "1.24.2"


async def test_latest_unbound_raises_on_errors():
    with pytest.raises(httpx.HTTPStatusError):
        await latest_unbound(httpx.MockTransport(lambda r: httpx.Response(403, json={})))
    with pytest.raises(ValueError):
        await latest_unbound(httpx.MockTransport(lambda r: httpx.Response(200, json={"tag_name": "x"})))
