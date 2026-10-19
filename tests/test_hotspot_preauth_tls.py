import pytest
from app.services.hotspot_preauth_tls import build_plan, guard_rules, rollback_rsc, UnsafePreauthTlsPlan


def garden():
    return [
        {"dst-host": "portal.example.com", "action": "allow"},
        {"dst-host": "*.cdn.example.com", "action": "allow"},
        {"dst-host": "assets.cdn.example.com", "action": "allow"},
        {"dst-address": "192.0.2.40", "action": "allow"},
        {"disabled": "true", "action": "allow"},
    ]


def test_preserves_concrete_hosts_wildcard_answers_and_ip_gardens():
    plan = build_plan(garden(), [{"dst-address": "198.51.100.0/24", "action": "accept"}])
    assert plan.lookup_hosts == ("assets.cdn.example.com", "portal.example.com")
    assert set(plan.networks) == {"192.0.2.40/32", "198.51.100.0/24"}
    rows = plan.dns_rows(marker="test", address_list="portals")
    assert {(r["name"], r["match-subdomain"]) for r in rows} == {("cdn.example.com", "yes"), ("portal.example.com", "no")}
    assert all(r["type"] == "FWD" and "forward-to" not in r for r in rows)


@pytest.mark.parametrize("host", ["*", "*example.com", "foo.*.example.com", ":regex", 'a.example.com;evil', "localhost"])
def test_refuses_patterns_that_cannot_preserve_portal_access(host):
    with pytest.raises(UnsafePreauthTlsPlan):
        build_plan([{"dst-host": host}], [])


@pytest.mark.parametrize("row", [{}, {"src-address": "192.0.2.1"}, {"dst-address": "0.0.0.0/0"}, {"dst-address": "192.0.2.1-192.0.2.5"}])
def test_refuses_unbounded_or_unsupported_allow(row):
    with pytest.raises(UnsafePreauthTlsPlan):
        build_plan([*garden(), row], [])


def test_ignores_disabled_or_deny_rules_without_overwriting_their_policy():
    plan = build_plan([*garden(), {"action": "deny", "dst-host": "*"}, {"disabled": True}], [])
    assert "*" not in plan.lookup_hosts


def test_never_shadows_existing_dns_or_regex_rules():
    plan = build_plan(garden(), [])
    for existing in ([{"name": "portal.example.com", "type": "A"}], [{"regexp": "example"}], [{"name": "example.com", "match-subdomain": "true"}], [{"name": "private.cdn.example.com", "type": "A"}]):
        with pytest.raises(UnsafePreauthTlsPlan):
            plan.dns_rows(marker="test", address_list="portals", existing=existing)


def test_guard_changes_only_unauthenticated_nonlocal_https_and_grants_no_forward_access():
    deny, nat = guard_rules(marker="test", address_list="portals", before_filter_id="*F")
    assert deny["action"] == "drop" and "reject-with" not in deny
    assert deny["chain"] == "hs-unauth"
    assert nat["chain"] == "pre-hotspot" and nat["action"] == "accept"
    for rule in (deny, nat):
        assert rule["protocol"] == "tcp" and rule["dst-port"] == "443"
        assert rule["hotspot"] == "from-client,!auth,!local-dst"
        assert rule["dst-address-list"] == "!portals" and rule["disabled"] == "yes"


def test_cleanup_targets_only_managed_objects_and_removes_nat_before_deny():
    source = rollback_rsc(marker="test", address_list="portals")
    assert source.splitlines()[0].startswith('/ip firewall nat remove [find where comment="test"]')
    assert '/ip dns static remove [find where comment="test"]' in source
    assert 'find where list="portals" and dynamic=no' in source
    assert source.count('/ip firewall address-list remove $i') == 2
    with pytest.raises(UnsafePreauthTlsPlan):
        rollback_rsc(marker='test"] evil', address_list="portals")
