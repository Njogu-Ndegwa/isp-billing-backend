"""PPPoE expired redirect: the RouterOS side, against a stateful fake router.

What must hold on a real router (bench checklist in the PR):
* applying is idempotent - a second apply on an unchanged router writes nothing;
* our rules sit ahead of every static rule in their chain but never touch the
  hotspot's dynamic rules, the anti-tunnel output rule, LB mangle/routes or the
  PPPoE NAT;
* the walled pool never overlaps an address, pool or route on the router;
* expiry keeps the secret, moves it to the walled profile and THEN kicks the
  session (so the redial lands walled); routers with the feature off still
  remove the secret first, as before;
* paying puts the plan profile back and kicks, through the normal provisioning;
* turning the feature off removes every walled-state object and releases
  walled customers the old way.
"""

import copy

import pytest

from app.services import mikrotik_background, pppoe_provisioning
from app.services import pppoe_expired_redirect as rx
from tests.fake_routeros import FakeRouterOS, typical_router_menus


def _ensure(api, config=None, router_id=42):
    out = rx.ensure_expired_infra(api, router_id=router_id, config=config or {})
    assert out.get("success"), out
    return out


# ---------------------------------------------------------------------------
# provisioning
# ---------------------------------------------------------------------------


def test_apply_creates_the_walled_state_with_tagged_objects():
    api = FakeRouterOS(typical_router_menus())
    out = _ensure(api)
    cfg = out["config"]

    assert cfg["cidr"] == "10.254.252.0/22"
    assert cfg["proxy_port"] == 3346 and cfg["proxy_enabled_by_us"] is True
    assert cfg["access_syntax"] == rx.SYNTAX_REDIRECT_TO

    pool = api.rows("/ip/pool", name=rx.EXPIRED_POOL)[0]
    assert pool["ranges"] == "10.254.252.2-10.254.255.254"

    profile = api.rows("/ppp/profile", name=rx.EXPIRED_PROFILE)[0]
    assert profile["remote-address"] == rx.EXPIRED_POOL
    assert profile["local-address"] == "10.254.252.1"
    assert profile["address-list"] == rx.EXPIRED_LIST
    assert profile["rate-limit"] == "512k/1M"
    assert profile["dns-server"] == "8.8.8.8"  # copied from the PPPoE server profile
    assert "redirect-to=$url" in profile["on-up"]
    assert "r=42" in profile["on-up"]

    proxy = api.menus["/ip/proxy"][0]
    assert proxy["enabled"] == "yes" and proxy["port"] == "3346"

    access = api.rows("/ip/proxy/access", comment=rx.COMMENT_REDIRECT)[0]
    assert access["src-address"] == "10.254.252.0/22"
    assert access["local-port"] == "3346"
    assert access["action"] == "deny"
    assert access["redirect-to"] == "https://isp-frontend-two.vercel.app/expired.html?r=42"

    nat = {r["comment"]: r for r in api.menus["/ip/firewall/nat"] if r.get("comment", "").startswith(rx.COMMENT_PREFIX)}
    assert nat[rx.COMMENT_REDIRECT] == {
        **nat[rx.COMMENT_REDIRECT],
        "chain": "dstnat", "src-address-list": rx.EXPIRED_LIST, "protocol": "tcp", "dst-port": "80",
        "dst-address-list": f"!{rx.ALLOW_LIST}", "action": "redirect", "to-ports": "3346",
    }
    assert nat[f"{rx.COMMENT_PREFIX}_NAT"]["src-address"] == "10.254.252.0/22"

    lists = api.menus["/ip/firewall/address-list"]
    assert {"list": rx.EXPIRED_LIST, "address": "10.254.252.0/22"}.items() <= next(
        r for r in lists if r["list"] == rx.EXPIRED_LIST).items()
    allowed = {r["address"] for r in lists if r["list"] == rx.ALLOW_LIST}
    assert {"isp-frontend-two.vercel.app", "isp.bitwavetechnologies.com", "76.76.21.0/24"} <= allowed


def test_rules_lead_their_chains_and_leave_hotspot_lb_and_anti_tunnel_alone():
    before = typical_router_menus()
    api = FakeRouterOS(before)
    _ensure(api)

    filt = api.menus["/ip/firewall/filter"]
    # Hotspot dynamic rule untouched and still first.
    assert filt[0]["dynamic"] == "true" and filt[0]["jump-target"] == "hs-unauth"
    forward = [r for r in filt if r.get("chain") == "forward" and r.get("dynamic") != "true"]
    assert [r["comment"] for r in forward[:6]] == [
        f"{rx.COMMENT_PREFIX}_DNS_UDP", f"{rx.COMMENT_PREFIX}_DNS_TCP", f"{rx.COMMENT_PREFIX}_ALLOW_HOSTS",
        f"{rx.COMMENT_PREFIX}_ALLOW_PORTAL", f"{rx.COMMENT_PREFIX}_REJECT_TCP", f"{rx.COMMENT_PREFIX}_REJECT",
    ]
    # ...so they run before FastTrack and before the PPPoE bypass accepts.
    assert forward[6]["comment"].startswith("PPPoE bypass FastTrack")
    reject_tcp = forward[4]
    assert reject_tcp["reject-with"] == "tcp-reset" and reject_tcp["protocol"] == "tcp"
    # Every walled rule matches only the walled address list.
    for r in forward[:6]:
        assert r["src-address-list"] == rx.EXPIRED_LIST

    inp = [r for r in filt if r.get("chain") == "input"]
    assert [r["comment"] for r in inp[:4]] == [
        f"{rx.COMMENT_PREFIX}_INPUT_PROXY", f"{rx.COMMENT_PREFIX}_INPUT_DNS_UDP",
        f"{rx.COMMENT_PREFIX}_INPUT_DNS_TCP", f"{rx.COMMENT_PREFIX}_PROXY_GUARD",
    ]
    assert inp[3]["action"] == "drop" and "src-address-list" not in inp[3]  # nobody else uses our proxy

    # Pre-existing rules: same content, same relative order.
    def foreign(menu):
        return [r for r in api.menus[menu] if not str(r.get("comment", "")).startswith(rx.COMMENT_PREFIX)]

    for menu in ("/ip/firewall/filter", "/ip/firewall/nat"):
        assert foreign(menu) == before[menu]
    assert api.menus["/ip/firewall/mangle"] == before["/ip/firewall/mangle"]
    assert api.menus["/ip/route"] == before["/ip/route"]
    anti_tunnel = next(r for r in filt if r.get("comment") == "ISP_BILLING_PROXY_RELAY_BLOCK")
    assert anti_tunnel == before["/ip/firewall/filter"][-1]
    # The existing PPPoE profile/pool/secrets were not modified.
    assert api.rows("/ppp/profile", name="pppoe_10M_10M") == [before["/ppp/profile"][1]]
    assert api.menus["/ppp/secret"] == before["/ppp/secret"]

    # The dstnat redirect sits ahead of the reseller's port forward, after
    # the hotspot's dynamic jump.
    nat = api.menus["/ip/firewall/nat"]
    dst = [r for r in nat if r.get("chain") == "dstnat"]
    assert dst[0]["dynamic"] == "true"
    assert dst[1]["comment"] == rx.COMMENT_REDIRECT
    assert dst[2]["comment"] == "reseller port forward"


def test_second_apply_writes_nothing():
    api = FakeRouterOS(typical_router_menus())
    first = _ensure(api)
    snapshot = copy.deepcopy(api.menus)
    api.calls.clear()

    second = _ensure(api, config=first["config"])

    assert second["writes"] == 0
    assert api.writes() == []
    assert api.menus == snapshot
    assert second["config"] == first["config"]


def test_apply_repairs_a_deleted_rule_and_a_rule_pushed_below_fasttrack():
    api = FakeRouterOS(typical_router_menus())
    cfg = _ensure(api)["config"]
    filt = api.menus["/ip/firewall/filter"]
    filt[:] = [r for r in filt if r.get("comment") != f"{rx.COMMENT_PREFIX}_REJECT_TCP"]
    # Someone moved the ALLOW rule to the end of the chain.
    allow = next(r for r in filt if r.get("comment") == f"{rx.COMMENT_PREFIX}_ALLOW_HOSTS")
    filt.remove(allow)
    filt.append(allow)

    out = _ensure(api, config=cfg)

    assert out["writes"] > 0
    forward = [r.get("comment") for r in api.menus["/ip/firewall/filter"]
               if r.get("chain") == "forward" and r.get("dynamic") != "true"]
    assert forward[:6] == [
        f"{rx.COMMENT_PREFIX}_DNS_UDP", f"{rx.COMMENT_PREFIX}_DNS_TCP", f"{rx.COMMENT_PREFIX}_ALLOW_HOSTS",
        f"{rx.COMMENT_PREFIX}_ALLOW_PORTAL", f"{rx.COMMENT_PREFIX}_REJECT_TCP", f"{rx.COMMENT_PREFIX}_REJECT",
    ]
    assert forward.count(f"{rx.COMMENT_PREFIX}_ALLOW_HOSTS") == 1
    assert _ensure(api, config=out["config"])["writes"] == 0


def test_pool_skips_subnets_already_on_the_router():
    menus = typical_router_menus()
    # A second-hand router: a LAN inside our first choice and One ISP's /16.
    menus["/ip/address"].append({".id": "*5", "address": "10.254.253.1/24", "network": "10.254.253.0",
                                 "interface": "ether5"})
    menus["/ip/pool"].append({".id": "*12", "name": "EXPIRED_POOL", "ranges": "10.255.0.2-10.255.255.254"})
    api = FakeRouterOS(menus)

    cfg = _ensure(api)["config"]

    assert cfg["cidr"] == "10.253.252.0/22"
    assert api.rows("/ip/pool", name=rx.EXPIRED_POOL)[0]["ranges"] == "10.253.252.2-10.253.255.254"


def test_pool_moves_when_a_route_lands_on_it_later():
    api = FakeRouterOS(typical_router_menus())
    cfg = _ensure(api)["config"]
    api.menus["/ip/route"].append({".id": "*22", "dst-address": "10.254.0.0/16", "gateway": "ether2"})
    api.menus["/ip/proxy/access"].insert(0, {
        ".id": "*U1", "src-address": "10.254.252.9", "comment": f"{rx.COMMENT_USER} 10.254.252.9 jane",
        "action": "deny", "redirect-to": "x"})

    out = _ensure(api, config=cfg)

    assert out["config"]["cidr"] == "10.253.252.0/22"
    assert out["config"]["moved_from"] == "10.254.252.0/22"
    assert api.rows("/ip/firewall/address-list", list=rx.EXPIRED_LIST)[0]["address"] == "10.253.252.0/22"
    assert api.rows("/ip/proxy/access", comment=f"{rx.COMMENT_USER} 10.254.252.9 jane") == []


def test_no_free_pool_is_an_error_not_a_clash():
    menus = typical_router_menus()
    for i, cidr in enumerate(rx.EXPIRED_CIDR_CANDIDATES):
        menus["/ip/route"].append({".id": f"*R{i}", "dst-address": cidr, "gateway": "ether3"})
    api = FakeRouterOS(menus)

    out = rx.ensure_expired_infra(api, router_id=1)

    assert "No free subnet" in out["error"]
    assert api.writes() == []


def test_an_enabled_proxy_is_reused_and_not_guarded():
    menus = typical_router_menus()
    menus["/ip/proxy"] = [{"enabled": "true", "port": "8080"}]
    api = FakeRouterOS(menus)

    cfg = _ensure(api)["config"]

    assert cfg["proxy_port"] == 8080 and cfg["proxy_enabled_by_us"] is False
    assert api.menus["/ip/proxy"][0] == {"enabled": "true", "port": "8080"}
    assert f"{rx.COMMENT_PREFIX}_PROXY_GUARD" not in api.comments("/ip/firewall/filter")
    assert api.rows("/ip/firewall/nat", comment=rx.COMMENT_REDIRECT)[0]["to-ports"] == "8080"


def test_proxy_access_falls_back_to_action_data_syntax():
    def reject(command, args):
        if command == "/ip/proxy/access/add" and "redirect-to" in args:
            return "unknown parameter redirect-to"
        return None

    api = FakeRouterOS(typical_router_menus(), reject=reject)
    cfg = _ensure(api)["config"]

    assert cfg["access_syntax"] == rx.SYNTAX_ACTION_DATA
    access = api.rows("/ip/proxy/access", comment=rx.COMMENT_REDIRECT)[0]
    assert access["action"] == "redirect" and access["action-data"].endswith("?r=42")
    profile = api.rows("/ppp/profile", name=rx.EXPIRED_PROFILE)[0]
    assert "action=redirect action-data=$url" in profile["on-up"]
    api.calls.clear()
    assert _ensure(api, config=cfg)["writes"] == 0


def test_profile_without_address_list_support_still_applies():
    def reject(command, args):
        if command.startswith("/ppp/profile/") and "address-list" in args:
            return "unknown parameter address-list"
        return None

    api = FakeRouterOS(typical_router_menus(), reject=reject)
    cfg = _ensure(api)["config"]

    assert cfg["profile_address_list"] is False
    assert "address-list" not in api.rows("/ppp/profile", name=rx.EXPIRED_PROFILE)[0]
    # The static pool entry still puts every walled session in the list.
    assert api.rows("/ip/firewall/address-list", list=rx.EXPIRED_LIST)[0]["address"] == "10.254.252.0/22"
    assert _ensure(api, config=cfg)["writes"] == 0


def test_on_up_script_identifies_the_session_and_cleans_up_after_itself():
    up = rx.render_on_up(42, 3346, rx.SYNTAX_REDIRECT_TO)
    down = rx.render_on_down()

    assert ':local url "https://isp-frontend-two.vercel.app/expired.html?r=42"' in up
    assert '&u=' in up and '^[A-Za-z0-9._@-]+\\$' in up  # only URL-safe usernames are added
    assert "local-port=3346" in up and "place-before=[:pick $f 0]" in up
    assert f'comment~("^{rx.COMMENT_USER} " . $a . " ")' in up  # stale rule for this IP removed first
    assert f'("{rx.COMMENT_USER} " . $"remote-address" . " " . $user)' in down


# ---------------------------------------------------------------------------
# expiry
# ---------------------------------------------------------------------------


ROUTER_INFO = {"id": 42, "ip": "10.0.3.17", "username": "u", "password": "p", "port": 8728, "name": "R42"}


@pytest.fixture
def fake_router(monkeypatch):
    api = FakeRouterOS(typical_router_menus())
    factory = lambda *a, **k: api  # noqa: E731
    monkeypatch.setattr(mikrotik_background, "MikroTikAPI", factory)
    monkeypatch.setattr(pppoe_provisioning, "MikroTikAPI", factory)
    return api


def _secret(api, name):
    rows = api.rows("/ppp/secret", name=name)
    return rows[0] if rows else None


def test_expiry_with_redirect_keeps_the_secret_walls_it_and_then_kicks(fake_router):
    info = {**ROUTER_INFO, "pppoe_expired_redirect": True, "pppoe_expired_redirect_config": {}}

    out = mikrotik_background._cleanup_single_router_pppoe_sync(
        info, [{"id": 7, "pppoe_username": "jane", "pppoe_password": "pw-jane"}],
    )

    assert [r["id"] for r in out["removed"]] == [7]
    assert out["removed"][0]["details"]["walled"] is True
    assert out["removed"][0]["details"]["disconnected"] == 1
    assert out["redirect_config"]["cidr"] == "10.254.252.0/22"
    jane = _secret(fake_router, "jane")
    assert jane is not None and jane["profile"] == rx.EXPIRED_PROFILE and jane["password"] == "pw-jane"
    assert fake_router.rows("/ppp/active", name="jane") == []
    assert _secret(fake_router, "otis")["profile"] == "pppoe_10M_10M"   # untouched
    # Profile set BEFORE the kick: the instant redial lands walled.
    order = [c for c, a in fake_router.calls if c in ("/ppp/secret/set", "/ppp/active/remove")]
    assert order == ["/ppp/secret/set", "/ppp/active/remove"]
    assert "/ppp/secret/remove" not in [c for c, _ in fake_router.calls]


def test_expiry_without_redirect_still_removes_the_secret_first(fake_router):
    out = mikrotik_background._cleanup_single_router_pppoe_sync(
        dict(ROUTER_INFO), [{"id": 7, "pppoe_username": "jane"}],
    )

    assert [r["id"] for r in out["removed"]] == [7]
    assert "walled" not in out["removed"][0]["details"]
    assert _secret(fake_router, "jane") is None
    assert not fake_router.rows("/ppp/profile", name=rx.EXPIRED_PROFILE)
    order = [c for c, _ in fake_router.calls if c in ("/ppp/secret/remove", "/ppp/active/remove")]
    assert order == ["/ppp/secret/remove", "/ppp/active/remove"]


def test_expiry_falls_back_to_removal_when_the_walled_state_cannot_be_ensured(fake_router):
    for i, cidr in enumerate(rx.EXPIRED_CIDR_CANDIDATES):
        fake_router.menus["/ip/route"].append({".id": f"*R{i}", "dst-address": cidr, "gateway": "x"})
    info = {**ROUTER_INFO, "pppoe_expired_redirect": True}

    out = mikrotik_background._cleanup_single_router_pppoe_sync(info, [{"id": 7, "pppoe_username": "jane"}])

    assert [r["id"] for r in out["removed"]] == [7]
    assert "No free subnet" in out["redirect_error"]
    assert _secret(fake_router, "jane") is None  # expired customers never keep access


def test_paused_customers_are_removed_not_walled(fake_router):
    info = {**ROUTER_INFO, "pppoe_expired_redirect": True}

    out = mikrotik_background._cleanup_single_router_pppoe_sync(info, [
        {"id": 7, "pppoe_username": "jane", "paused": True},
        {"id": 8, "pppoe_username": "otis", "pppoe_password": "pw-otis"},
    ])

    by_id = {r["id"]: r for r in out["removed"]}
    assert set(by_id) == {7, 8}
    assert _secret(fake_router, "jane") is None
    assert _secret(fake_router, "otis")["profile"] == rx.EXPIRED_PROFILE


def test_missing_secret_is_recreated_walled_at_expiry_but_not_by_the_safety_net(fake_router):
    info = {**ROUTER_INFO, "pppoe_expired_redirect": True}
    gone = [{"id": 9, "pppoe_username": "mia", "pppoe_password": "pw-mia", "name": "Mia"}]

    safety = mikrotik_background._cleanup_single_router_pppoe_sync(
        {**info, "create_missing_walled": False}, copy.deepcopy(gone))
    assert safety["removed"][0]["details"] == {"walled": False, "action": "absent", "disconnected": 0}
    assert _secret(fake_router, "mia") is None

    expiry = mikrotik_background._cleanup_single_router_pppoe_sync(info, copy.deepcopy(gone))
    assert expiry["removed"][0]["details"]["action"] == "created_walled"
    mia = _secret(fake_router, "mia")
    assert mia["profile"] == rx.EXPIRED_PROFILE and mia["comment"].startswith("CID:9|Mia")


def test_failed_wall_keeps_the_customer_for_retry(fake_router):
    def reject(command, args):
        return "timeout" if command == "/ppp/secret/set" else None

    fake_router.reject = reject
    info = {**ROUTER_INFO, "pppoe_expired_redirect": True}

    out = mikrotik_background._cleanup_single_router_pppoe_sync(info, [{"id": 7, "pppoe_username": "jane"}])

    assert out["removed"] == [] and [r["id"] for r in out["failed"]] == [7]
    assert fake_router.rows("/ppp/active", name="jane")  # not kicked onto the plan profile again


# ---------------------------------------------------------------------------
# renewal
# ---------------------------------------------------------------------------


def test_payment_restores_the_plan_profile_and_kicks_the_walled_session(fake_router):
    _ensure(fake_router)
    rx.wall_pppoe_users(fake_router, [{"id": 7, "pppoe_username": "jane"}])
    # The CPE redialled into the walled profile.
    fake_router.menus["/ppp/active"].append({".id": "*99", "name": "jane", "address": "10.254.252.5"})
    fake_router.calls.clear()

    out = pppoe_provisioning._provision_pppoe_sync({
        "router_ip": "10.0.3.17", "router_username": "u", "router_password": "p", "router_port": 8728,
        "pppoe_username": "jane", "pppoe_password": "pw-jane", "bandwidth_limit": "10Mbps",
        "comment": "CID:7|Jane|2026-10-29",
    })

    assert out.get("success"), out
    assert _secret(fake_router, "jane")["profile"] == "pppoe_10M_10M"
    assert fake_router.rows("/ppp/active", name="jane") == []  # kicked: redials with full access
    # The walled state itself stays for the next expiry.
    assert fake_router.rows("/ppp/profile", name=rx.EXPIRED_PROFILE)


# ---------------------------------------------------------------------------
# toggle off
# ---------------------------------------------------------------------------


def test_teardown_releases_walled_customers_and_removes_every_object():
    before = typical_router_menus()
    api = FakeRouterOS(before)
    cfg = _ensure(api)["config"]
    rx.wall_pppoe_users(api, [{"id": 7, "pppoe_username": "jane"}])
    api.menus["/ppp/active"].append({".id": "*99", "name": "jane", "address": "10.254.252.5"})
    api.menus["/ip/proxy/access"].insert(0, {
        ".id": "*U1", "src-address": "10.254.252.5", "comment": f"{rx.COMMENT_USER} 10.254.252.5 jane",
        "action": "deny", "redirect-to": "x"})

    out = rx.teardown_expired_infra(api, cfg)

    assert out["success"] and out["secrets_removed"] == ["jane"]
    assert _secret(api, "jane") is None and api.rows("/ppp/active", name="jane") == []
    for menu in ("/ip/firewall/filter", "/ip/firewall/nat", "/ip/proxy/access", "/ip/firewall/address-list"):
        assert not [r for r in api.menus[menu] if str(r.get("comment", "")).startswith(rx.COMMENT_PREFIX)]
    assert not api.rows("/ppp/profile", name=rx.EXPIRED_PROFILE)
    assert not api.rows("/ip/pool", name=rx.EXPIRED_POOL)
    assert api.menus["/ip/proxy"][0]["enabled"] == "no"
    # Everything that was there before is still there.
    for menu in ("/ip/firewall/filter", "/ip/firewall/nat", "/ip/firewall/mangle", "/ip/pool", "/ppp/profile"):
        assert api.menus[menu] == before[menu]
    assert _secret(api, "otis") == before["/ppp/secret"][1]


def test_teardown_leaves_a_proxy_we_did_not_enable():
    menus = typical_router_menus()
    menus["/ip/proxy"] = [{"enabled": "true", "port": "8080"}]
    api = FakeRouterOS(menus)
    cfg = _ensure(api)["config"]

    rx.teardown_expired_infra(api, cfg)

    assert api.menus["/ip/proxy"][0]["enabled"] == "true"
