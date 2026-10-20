"""Fill the throwaway test Pi-holes with sample data and some drift, for trying the UI.

    scripts/test-piholes.sh up
    uv run python -m scripts.seed_test_piholes
"""

import asyncio

from twinhole.config import PiholeConfig
from twinhole.pihole import Pihole


def test_pihole(n: int) -> Pihole:
    return Pihole(PiholeConfig(f"test-ph{n}", "", f"Test {n}", f"http://127.0.0.1:1808{n}", "127.0.0.1", 15300 + n, "off"))


async def wipe(p: Pihole) -> None:
    for d in await p.domains():
        await p.delete_domain(d["type"], d["kind"], d["domain"])
    for lst in await p.lists():
        if "StevenBlack" not in lst["address"]:
            await p.delete_list(lst["type"], lst["address"])
    for c in await p.clients():
        await p.delete_client(c["client"])
    for g in await p.groups():
        if g["id"] != 0:
            await p.delete_group(g["name"])
    await p.set_dns_records([], [])


async def main() -> None:
    main, sec = test_pihole(1), test_pihole(2)
    for p in (main, sec):
        await wipe(p)
    await main.add_group("kids", "Children's devices", True)
    await main.add_group("iot", "Smart home", True)
    await sec.add_group("old-group", "Left over", True)
    mg = {g["name"]: g["id"] for g in await main.groups()}
    sg = {g["name"]: g["id"] for g in await sec.groups()}

    for p, g in ((main, mg), (sec, sg)):
        await p.add_domain("deny", "regex", r"(\.|^)doubleclick\.net$", "ads", [g["Default"]], True)
        await p.add_domain("allow", "exact", "s.youtube.com", "history needs it", [g["Default"]], p is main)
        await p.add_list("block", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt", "HaGeZi Pro", [g["Default"]], True)
    await main.add_domain("deny", "exact", "tiktok.com", "kids", [mg["kids"]], True)
    await main.add_domain("deny", "regex", r"(\.|^)mov$", None, [mg["Default"]], True)
    await main.add_client("192.168.1.0/24", "Whole LAN", [mg["Default"], mg["kids"]])
    await main.set_dns_records(["192.168.1.50 nas.lan", "192.168.1.60 printer.lan"], ["files.lan,nas.lan"])

    await sec.add_domain("deny", "exact", "stale.example", "removed on main", [sg["old-group"]], True)
    await sec.set_dns_records(["192.168.1.50 nas.lan", "192.168.1.99 old.lan"], [])

    for name in ("example.com", "doubleclick.net", "ads.doubleclick.net", "tiktok.com", "nas.lan", "github.com"):
        for port in (15301, 15302):
            await asyncio.create_subprocess_exec("dig", "+short", "-p", str(port), "@127.0.0.1", name, stdout=-3)
    for p in (main, sec):
        await p.aclose()
    print("seeded")


asyncio.run(main())
