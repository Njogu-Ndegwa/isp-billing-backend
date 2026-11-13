"""Running the setup code a second time on the same MikroTik must converge.

Incident 2026-11-12 (SPEEDNET, user 768): the reseller set up one MikroTik as
router 711, it was force-deleted, and the next day the same box was set up
again as router 714. STEP 8 created the API account with a bare
``:do { /user add name=bitwave-api ... } on-error={}``; the account already
existed, the add failed silently, the router kept 711's password while the
server stored 714's, and every API login was refused with "invalid user name
or password" -- no check-in, watchdog or expiry reaper, no portal redirect,
no payment delivery.

These tests run the generated steps on ``tests/rsc_sim.py`` (a small
RouterOS-script runner) against a fresh router and against a router that
already carries the earlier setup's state.
"""

from datetime import datetime

import pytest

from app.db.models import ProvisioningToken
from app.services import provisioning, router_diagnosis
from app.services import standard_runtime_enrol as enrol
from app.services.mikrotik_api import api_credentials_rejected
from tests.rsc_sim import RscSim


def _token(**kw) -> ProvisioningToken:
    base = dict(
        token="abc123",
        router_name="SPEEDNET #2",
        identity="Router-1700",
        vpn_type="wireguard",
        wireguard_ip="10.0.7.14",
        router_admin_password="NewPassword714xyz",
        server_public_ip="91.98.238.12",
        wg_private_key="cm91dGVyLXByaXZhdGUta2V5LWZvci10ZXN0cy0xMjM=",
        server_wg_pubkey="insurance-server-public",
        management_tunnel="wireguard",
        payment_methods=["mpesa"],
    )
    base.update(kw)
    return ProvisioningToken(**base)


def _api_users(sim):
    return [r for r in sim.rows("/user") if r.get("name") == provisioning.API_USERNAME]


# ---------------------------------------------------------------------------
# STEP 8: the API account
# ---------------------------------------------------------------------------


def test_fresh_router_gets_the_api_user_with_this_setups_password():
    sim = RscSim({"/user": [{"name": "admin", "group": "full"}]})
    sim.run(provisioning._rsc_identity_and_user(_token()))
    [user] = _api_users(sim)
    assert user["password"] == "NewPassword714xyz"
    assert user["group"] == "full"
    assert sim.rows("/system identity") == [{"name": "Router-1700"}]
    assert ("info", "Provisioning: API user bitwave-api created") in sim.logs
    assert not [l for l in sim.logs if l[0] == "error"]


def _router_set_up_before():
    # What router 711's setup left behind on the box.
    return {"/user": [
        {"name": "admin", "group": "full"},
        {"name": "bitwave-api", "password": "OldPassword711abc", "group": "read",
         "comment": "Bitwave backend API account", "disabled": "yes"},
    ]}


def test_rerun_resets_the_existing_api_user_to_this_setups_password():
    sim = RscSim(_router_set_up_before())
    sim.run(provisioning._rsc_identity_and_user(_token()))
    [user] = _api_users(sim)                       # still exactly one account
    assert user["password"] == "NewPassword714xyz"  # what the server stores
    assert user["group"] == "full"
    assert user["disabled"] == "no"
    assert any("already existed -- password reset" in msg for _, msg in sim.logs)
    # The other accounts are untouched.
    assert {"name": "admin", "group": "full"} in sim.rows("/user")


def test_the_old_step_8_kept_the_stale_password():
    # Documents the bug the new STEP 8 replaces (the exact line at 2f61881).
    old = (':do { /user add name=bitwave-api password="NewPassword714xyz" group=full '
           'comment="Bitwave backend API account" } on-error={}')
    sim = RscSim(_router_set_up_before()).run(old)
    [user] = _api_users(sim)
    assert user["password"] == "OldPassword711abc"


def test_rerun_is_idempotent_when_run_twice_with_the_same_token():
    sim = RscSim()
    step = provisioning._rsc_identity_and_user(_token())
    sim.run(step).run(step)
    [user] = _api_users(sim)
    assert user["password"] == "NewPassword714xyz"


def test_every_token_type_uses_the_add_or_set_api_user_step(monkeypatch):
    monkeypatch.setattr(provisioning.settings, "SSTP_SERVER", "91.98.238.12:4443")
    monkeypatch.setattr(provisioning.settings, "SSTP_SERVER_VPN_IP", "10.251.0.1")
    tokens = [
        _token(),
        _token(vpn_type="l2tp", management_tunnel="sstp", wireguard_ip="10.0.100.77",
               sstp_username="sstp-Router-1700", sstp_password="SstpPw"),
        _token(management_tunnel=None),
        _token(vpn_type="l2tp", management_tunnel=None, wireguard_ip="10.0.100.77",
               l2tp_username="l2tp-Router-1700", l2tp_password="L2tpPw"),
    ]
    for token in tokens:
        script = provisioning.generate_rsc_script(token)
        assert ":if ([:len [/user find where name=bitwave-api]] = 0) do={" in script
        assert "/user set [find where name=bitwave-api] password=\"NewPassword714xyz\"" in script
        # Never again a bare add that swallows "already exists".
        assert "/user add name=bitwave-api" in script
        assert ':do { /user add name=bitwave-api' not in script


# ---------------------------------------------------------------------------
# Tunnel addresses: a re-run with a new token must not leave the old address
# ---------------------------------------------------------------------------


def _address_lines(step: str) -> str:
    return "\n".join(l for l in step.splitlines() if l.startswith(":do { /ip address"))


def test_rerun_drops_the_old_tunnel_address_and_keeps_others(monkeypatch):
    monkeypatch.setattr(provisioning.settings, "INSURANCE_WG_SUBNET", "10.251.0.0/16")
    token = _token()
    new = provisioning.derive_insurance_ip(token.wireguard_ip, "10.251.0.0/16") + "/16"
    sim = RscSim({"/ip address": [
        {"address": "10.251.7.11/16", "interface": "wg-hz"},       # router 711's tunnel address
        {"address": "192.168.88.1/24", "interface": "bridge"},     # reseller's LAN: untouched
    ]})
    sim.run(_address_lines(provisioning._rsc_vpn_hetzner_wireguard(token)))
    assert [r["address"] for r in sim.rows("/ip address") if r["interface"] == "wg-hz"] == [new]
    assert {"address": "192.168.88.1/24", "interface": "bridge"} in sim.rows("/ip address")


def test_fresh_router_gets_the_tunnel_address(monkeypatch):
    monkeypatch.setattr(provisioning.settings, "INSURANCE_WG_SUBNET", "10.251.0.0/16")
    token = _token()
    sim = RscSim().run(_address_lines(provisioning._rsc_vpn_hetzner_wireguard(token)))
    assert [r["interface"] for r in sim.rows("/ip address")] == ["wg-hz"]
    assert not sim.logs


def test_rerun_moves_the_loopback_pin_to_the_new_management_ip():
    sim = RscSim({
        "/interface bridge": [{"name": "lo-mgmt"}, {"name": "bridge"}],
        "/ip address": [{"address": "10.0.7.11/32", "interface": "lo-mgmt"},
                        {"address": "192.168.88.1/24", "interface": "bridge"}],
    })
    pin = provisioning._rsc_mgmt_loopback_pin(_token())
    sim.run(pin).run(pin)
    assert [r["address"] for r in sim.rows("/ip address") if r["interface"] == "lo-mgmt"] == ["10.0.7.14/32"]
    assert len(sim.rows("/ip address")) == 2
    assert len(sim.rows("/interface bridge")) == 2


def test_fresh_router_gets_the_loopback_pin():
    sim = RscSim().run(provisioning._rsc_mgmt_loopback_pin(_token()))
    assert sim.rows("/interface bridge")[0]["name"] == "lo-mgmt"
    assert [r["address"] for r in sim.rows("/ip address")] == ["10.0.7.14/32"]


# ---------------------------------------------------------------------------
# Detector: router answers but refuses our password
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("error, rejected", [
    ("API login rejected by 10.0.7.14:8728: invalid user name or password (6)", True),
    ("API login rejected by 10.0.7.14:8728: cannot log in", True),
    ("API login rejected by 10.0.7.14:8728 (check the router's API username/password)", False),
    ("Connection to 10.0.7.14:8728 timed out after 6s (router unreachable or API service down)", False),
    ("Circuit breaker open for 10.0.7.14:8728 after repeated failures", False),
    (None, False),
])
def test_api_credentials_rejected(error, rejected):
    assert api_credentials_rejected(error) is rejected


class _RejectingApi:
    def __init__(self, *a, **kw):
        self.last_connect_error = "API login rejected by 10.0.7.14:8728: invalid user name or password (6)"

    def connect(self):
        return False

    def disconnect(self):
        pass


class _DeadApi(_RejectingApi):
    def __init__(self, *a, **kw):
        self.last_connect_error = "Connection to 10.0.7.14:8728 timed out after 6s"


def _candidate():
    return enrol.Candidate(714, "SPEEDNET #2", "Router-1700", "10.0.7.14", "bitwave-api",
                           "NewPassword714xyz", 8728, True, True)


def test_installer_flags_credentials_mismatch(caplog):
    with caplog.at_level("WARNING"):
        out = enrol.probe_and_install_sync(_candidate(), api_factory=_RejectingApi)
    assert out.checkin.reason == out.watchdog.reason == enrol.CREDENTIALS_MISMATCH_REASON
    assert not out.checkin.installed and not out.watchdog.installed
    assert "[API-CREDS-MISMATCH] router 714" in caplog.text
    assert "re-run setup" in caplog.text
    # A mismatch is not a hardware/setup decision: looked at again soon.
    assert enrol.recheck_after(enrol.CREDENTIALS_MISMATCH_REASON) == enrol.RECHECK_TRANSIENT


def test_installer_still_says_unreachable_for_a_dead_router(caplog):
    with caplog.at_level("WARNING"):
        out = enrol.probe_and_install_sync(_candidate(), api_factory=_DeadApi)
    assert out.checkin.reason == "unreachable"
    assert "API-CREDS-MISMATCH" not in caplog.text


def test_diagnosis_names_the_mismatch_and_says_re_run_setup():
    d = router_diagnosis.classify(5, 5, "rejected", "wireguard", None, datetime(2026, 11, 12, 9, 0),
                                  tcp_times=[0.1] * 5)
    assert d["ailment"] == "login_rejected"
    assert d["title"] == "API credentials mismatch"
    assert "re-run setup" in d["action"]
