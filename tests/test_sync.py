import pytest

from twinhole.sync import apply, plan, plan_id, snapshot, summarize

pytestmark = pytest.mark.anyio


async def test_identical_piholes_need_no_changes(main, secondary, main_fake, sec_fake):
    for f in (main_fake, sec_fake):
        f.add_domain("deny", "exact", "ads.example")
    (m, _), (s, _) = await snapshot(main), await snapshot(secondary)
    assert plan(m, s) == []


async def test_groups_are_matched_by_name_not_id(main, secondary, main_fake, sec_fake):
    main_fake.add_group("kids")  # id 2 on main
    sec_fake.add_group("spare")
    sec_fake.add_group("kids")  # id 3 on secondary
    main_fake.add_domain("deny", "exact", "tiktok.com", groups=["kids"])
    sec_fake.add_domain("deny", "exact", "tiktok.com", groups=["kids"])
    (m, _), (s, _) = await snapshot(main), await snapshot(secondary)
    changes = plan(m, s)
    assert [(c.resource, c.action, c.key) for c in changes] == [("groups", "delete", ("spare",))]


async def test_missing_comment_matches_empty_comment(main, secondary, main_fake, sec_fake):
    main_fake.add_domain("deny", "exact", "ads.example", comment=None)
    sec_fake.add_domain("deny", "exact", "ads.example", comment="")
    (m, _), (s, _) = await snapshot(main), await snapshot(secondary)
    assert plan(m, s) == []


async def test_default_group_is_never_deleted(main, secondary, main_fake, sec_fake):
    main_fake.groups["Everyone"] = main_fake.groups.pop("Default") | {"name": "Everyone"}
    (m, _), (s, _) = await snapshot(main), await snapshot(secondary)
    actions = [(c.resource, c.action, c.key) for c in plan(m, s)]
    assert ("groups", "delete", ("Default",)) not in actions


async def test_plan_orders_group_creation_first_and_group_deletion_last(main, secondary, main_fake, sec_fake):
    main_fake.add_group("iot")
    main_fake.add_list("block", "https://lists.example/iot.txt", groups=["iot"])
    sec_fake.add_group("old")
    sec_fake.add_domain("deny", "exact", "old.example", groups=["old"])
    (m, _), (s, _) = await snapshot(main), await snapshot(secondary)
    changes = plan(m, s)
    assert (changes[0].resource, changes[0].action, changes[0].key) == ("groups", "add", ("iot",))
    assert (changes[-1].resource, changes[-1].action, changes[-1].key) == ("groups", "delete", ("old",))


async def test_local_dns_entries_compare_ignoring_spacing(main, secondary, main_fake, sec_fake):
    main_fake.hosts.append("192.168.1.50 nas.lan")
    sec_fake.hosts.append("192.168.1.50   nas.lan")
    main_fake.cnames.append("files.lan,nas.lan")
    sec_fake.cnames.append("files.lan, nas.lan")
    (m, _), (s, _) = await snapshot(main), await snapshot(secondary)
    assert plan(m, s) == []


async def test_apply_makes_the_secondary_a_mirror(main, secondary, main_fake, sec_fake):
    main_fake.add_group("kids", comment="Children's devices")
    main_fake.add_group("iot", enabled=False)
    main_fake.add_domain("deny", "regex", r"(\.|^)tiktok\.com$", comment="no", groups=["kids"])
    main_fake.add_domain("allow", "exact", "good.example", groups=["Default", "iot"])
    main_fake.add_domain("deny", "exact", "toggle.example", enabled=False)
    main_fake.add_list("block", "https://lists.example/hosts.txt?x=1", groups=["Default", "kids"])
    main_fake.add_list("allow", "https://lists.example/allow.txt", enabled=False)
    main_fake.add_client("192.168.1.0/24", comment="LAN", groups=["kids"])
    main_fake.hosts.extend(["192.168.1.50 nas.lan", "192.168.1.51 printer.lan"])
    main_fake.cnames.append("files.lan,nas.lan")

    # Drift on the secondary: stale extras, a changed comment, a wrong toggle.
    sec_fake.add_group("old")
    sec_fake.add_domain("deny", "exact", "toggle.example", enabled=True)
    sec_fake.add_domain("deny", "exact", "only-on-secondary.example", groups=["old"])
    sec_fake.add_list("block", "https://lists.example/stale.txt")
    sec_fake.add_client("10.0.0.9", comment="gone")
    sec_fake.hosts.append("192.168.1.99 old.lan")
    sec_fake.cnames.append("old.lan,nas.lan")

    (m, _), (s, gids) = await snapshot(main), await snapshot(secondary)
    changes = plan(m, s)
    assert summarize(changes) == (
        "+2 groups, -1 group, +2 domains, -1 domain, ~1 domain, +2 adlists, -1 adlist, "
        "+1 client, -1 client, +2 local DNS records, -1 local DNS record, +1 CNAME, -1 CNAME"
    )

    results = await apply(secondary, changes, gids)
    assert all(r["ok"] for r in results), [r for r in results if not r["ok"]]

    (m, _), (s, _) = await snapshot(main), await snapshot(secondary)
    assert plan(m, s) == []
    assert "old" not in sec_fake.groups
    assert sec_fake.restarts == 1  # all local DNS and CNAME changes in one config write


async def test_apply_carries_on_after_a_failure(main, secondary, main_fake, sec_fake):
    main_fake.add_list("block", "https://lists.example/bad list.txt")  # the real API rejects spaces
    main_fake.add_domain("deny", "exact", "fine.example")
    (m, _), (s, gids) = await snapshot(main), await snapshot(secondary)
    results = await apply(secondary, plan(m, s), gids)
    by_resource = {r["resource"]: r for r in results}
    assert by_resource["lists"]["ok"] is False
    assert "Spaces" in by_resource["lists"]["error"]
    assert by_resource["domains"]["ok"] is True


async def test_plan_id_changes_when_the_plan_changes(main, secondary, main_fake, sec_fake):
    main_fake.add_domain("deny", "exact", "a.example")
    (m, _), (s, _) = await snapshot(main), await snapshot(secondary)
    first = plan_id(plan(m, s))
    assert first == plan_id(plan(m, s))
    main_fake.add_domain("deny", "exact", "b.example")
    (m, _), (s, _) = await snapshot(main), await snapshot(secondary)
    assert plan_id(plan(m, s)) != first
