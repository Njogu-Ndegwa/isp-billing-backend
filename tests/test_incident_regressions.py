"""Regression pins converted from docs/agent-memory/incidents/ notes.

One class per incident. Only invariants NOT already pinned elsewhere are added
here; each class documents what the neighbouring suites already cover:

* 2026-07-15-pull-channel-free-internet-expiry.md
    - pull SERVICE behavior (PULL-EXPIRES honored on serve, expiry beats the
      mtime TTL, background pruner) is pinned by tests/test_pull_service.py;
      header rendering by tests/test_pull_provisioning.py.
    - the APP-side guards in hotspot_provisioning (never hand an expired
      customer to the pull channel, bound the command to the paid window,
      clear the queue after a successful push) had no tests -> pinned below.
* 2026-06-01-pppoe-orphan-secret.md
    - deletion-side invariants (deprovision before DB delete, refuse delete on
      router-cleanup failure, orphan endpoint refusal without force) are
      pinned by tests/test_pppoe_cleanup.py -> only the missing force=true
      path and the partial-failure-is-an-error rule are added below.
* 2026-06-03-expired-hotspot-active-status.md
    - fully covered by tests/test_expired_hotspot_cleanup.py (failure keeps
      ACTIVE, success flips INACTIVE, batching, active-list visibility).
      Nothing added here on purpose.
"""

import calendar
from datetime import datetime, timedelta

from fastapi import HTTPException

from app.db.models import ConnectionType, CustomerStatus
from tests.factories import make_customer, make_plan, make_reseller, make_router


class TestPullChannelFreeInternetExpiry:
    """docs/agent-memory/incidents/2026-07-15-pull-channel-free-internet-expiry.md

    The pull channel was add-only: a queued provisioning command kept being
    re-applied by the on-router pull-agent every 30s after the customer's plan
    expired (free internet), and a successful tunnel push never cleared the
    queued copy.
    """

    async def _seed(self, db, *, expiry):
        reseller = await make_reseller(db)
        plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
        router = await make_router(
            db, reseller,
            identity=f"Router-{2000 + reseller.id}",
            pull_channel_enabled=True,
        )
        customer = await make_customer(
            db, reseller, plan, router,
            status=CustomerStatus.ACTIVE,
            expiry=expiry,
        )
        payload = {
            "username": f"cust{customer.id}",
            "password": "pw12345",
            "mac_address": customer.mac_address,
            "bandwidth_limit": "5M/5M",
            "time_limit": "1d",
            "comment": f"CID:{customer.id}|Test|2026",
            "router_ip": router.ip_address,
            "router_username": router.username,
            "router_password": router.password,
            "router_port": router.port,
        }
        return reseller, router, customer, payload

    def _patch_pull_io(self, monkeypatch):
        import app.services.pull_provisioning as pull_mod

        handoffs = []
        clears = []

        async def fake_handoff(identity, key, rsc):
            handoffs.append({"identity": identity, "key": key, "rsc": rsc})
            return {"queued": True}

        async def fake_clear(identity, key):
            clears.append({"identity": identity, "key": key})
            return {"cleared": True}

        monkeypatch.setattr(pull_mod, "handoff_to_pull_service", fake_handoff)
        monkeypatch.setattr(pull_mod, "clear_pull_service", fake_clear)
        return handoffs, clears

    async def test_expired_customer_is_never_handed_to_pull_channel(
        self, db, monkeypatch
    ):
        """An already-expired customer must not be queued at all — the exact
        Guest-9251 shape: expired, router offline, command re-served forever."""
        import app.services.hotspot_provisioning as hsp

        _, router, customer, payload = await self._seed(
            db, expiry=datetime.utcnow() - timedelta(hours=2)
        )
        handoffs, _ = self._patch_pull_io(monkeypatch)
        monkeypatch.setattr(hsp, "derive_router_status", lambda r: "offline")
        pushes = []

        async def fake_push(hotspot_payload, verify_only=False):
            pushes.append(hotspot_payload)
            return {"success": False, "error": "router unavailable"}

        monkeypatch.setattr(hsp, "_run_mikrotik_operation", fake_push)

        result = await hsp.provision_hotspot_customer(
            customer_id=customer.id,
            router_id=router.id,
            hotspot_payload=payload,
        )

        assert handoffs == []
        assert len(pushes) == 1  # status is advisory; paid delivery is still attempted
        assert result["success"] is False

    async def test_pull_command_is_bounded_by_customer_expiry(self, db, monkeypatch):
        """A queued command must carry the customer's real expiry as a
        PULL-EXPIRES header so the pull service stops serving it at plan end."""
        import app.services.hotspot_provisioning as hsp

        expiry = datetime.utcnow() + timedelta(days=2)
        _, router, customer, payload = await self._seed(db, expiry=expiry)
        handoffs, _ = self._patch_pull_io(monkeypatch)
        monkeypatch.setattr(hsp, "derive_router_status", lambda r: "offline")

        async def fake_push(hotspot_payload, verify_only=False):
            return {"success": False, "error": "router unavailable"}

        monkeypatch.setattr(hsp, "_run_mikrotik_operation", fake_push)

        await hsp.provision_hotspot_customer(
            customer_id=customer.id,
            router_id=router.id,
            hotspot_payload=payload,
        )

        assert len(handoffs) == 1
        assert handoffs[0]["identity"] == router.identity
        assert handoffs[0]["key"] == f"cust{customer.id}"
        expected_ts = calendar.timegm(expiry.utctimetuple())
        assert f"# PULL-EXPIRES {expected_ts}" in handoffs[0]["rsc"]

    async def test_false_offline_status_never_suppresses_direct_paid_delivery(
        self, db, monkeypatch
    ):
        import app.services.hotspot_provisioning as hsp

        _, router, customer, payload = await self._seed(
            db, expiry=datetime.utcnow() + timedelta(hours=2)
        )
        router.pull_channel_enabled = False
        await db.commit()
        monkeypatch.setattr(hsp, "derive_router_status", lambda r: "offline")
        pushes = []

        async def fake_push(hotspot_payload, verify_only=False):
            pushes.append(hotspot_payload)
            return {"success": True}

        monkeypatch.setattr(hsp, "_run_mikrotik_operation", fake_push)

        result = await hsp.provision_hotspot_customer(
            customer_id=customer.id,
            router_id=router.id,
            hotspot_payload=payload,
        )

        assert result["success"] is True
        assert pushes == [payload]

    async def test_successful_push_clears_pending_pull_command(self, db, monkeypatch):
        """Delivered over the tunnel -> the queued pull copy must be cleared so
        a later outbound fetch can't re-apply it."""
        import app.services.hotspot_provisioning as hsp

        _, router, customer, payload = await self._seed(
            db, expiry=datetime.utcnow() + timedelta(days=2)
        )
        handoffs, clears = self._patch_pull_io(monkeypatch)
        monkeypatch.setattr(hsp, "derive_router_status", lambda r: "online")

        async def fake_push(hotspot_payload, verify_only=False):
            return {"success": True}

        monkeypatch.setattr(hsp, "_run_mikrotik_operation", fake_push)

        result = await hsp.provision_hotspot_customer(
            customer_id=customer.id,
            router_id=router.id,
            hotspot_payload=payload,
        )

        assert result["success"] is True
        assert handoffs == []  # push worked; nothing queued
        assert clears == [
            {"identity": router.identity, "key": f"cust{customer.id}"}
        ]


class TestPppoeOrphanSecret:
    """docs/agent-memory/incidents/2026-06-01-pppoe-orphan-secret.md

    A router kept an enabled PPPoE secret + live session for a customer the DB
    no longer knew about. Complements tests/test_pppoe_cleanup.py (see module
    docstring) with the force=true removal path and the rule that a partial
    router failure is a cleanup ERROR, not a success.
    """

    async def test_force_cleanup_removes_db_owned_username(self, db, monkeypatch):
        from app.api import pppoe_monitor

        reseller = await make_reseller(db)
        plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
        router = await make_router(db, reseller)
        await make_customer(
            db, reseller, plan, router,
            status=CustomerStatus.ACTIVE,
            mac_address=None,
            pppoe_username="Festo",
            name="Festus",
        )
        calls = []

        async def _cleanup(payload):
            calls.append(payload)
            return {
                "success": True,
                "disconnect_result": {"success": True, "disconnected": 1},
                "remove_result": {"success": True, "action": "removed"},
            }

        monkeypatch.setattr(pppoe_monitor, "call_pppoe_remove", _cleanup)

        response = await pppoe_monitor.cleanup_pppoe_user(
            router.id,
            "Festo",
            True,  # force
            db,
            {"user_id": reseller.id, "role": reseller.role.value},
        )

        assert response["success"] is True
        assert response["forced"] is True
        assert response["customer_present"] is True
        assert calls[0]["pppoe_username"] == "Festo"

    def _fake_api(self, monkeypatch, *, disconnect, remove):
        from app.services import pppoe_provisioning

        class FakeApi:
            def __init__(self, *a, **k):
                pass

            def connect(self):
                return True

            def disconnect(self):
                pass

            def disconnect_pppoe_session(self, username):
                return disconnect

            def remove_pppoe_secret(self, username):
                return remove

        monkeypatch.setattr(pppoe_provisioning, "MikroTikAPI", FakeApi)
        return pppoe_provisioning

    def test_session_disconnect_failure_is_a_cleanup_error(self, monkeypatch):
        """The incident root cause: cleanup 'succeeded' while the router still
        had a live session/secret. Any partial failure must surface as error
        so callers (deletion, orphan endpoint) refuse to proceed."""
        mod = self._fake_api(
            monkeypatch,
            disconnect={"error": "timeout talking to router"},
            remove={"success": True},
        )
        result = mod._remove_pppoe_sync({"pppoe_username": "ghost"})
        assert "Session disconnect failed" in result["error"]

    def test_secret_removal_failure_is_a_cleanup_error(self, monkeypatch):
        mod = self._fake_api(
            monkeypatch,
            disconnect={"success": True, "disconnected": 0},
            remove={"error": "secret is in use"},
        )
        result = mod._remove_pppoe_sync({"pppoe_username": "ghost"})
        assert "Secret removal failed" in result["error"]


class TestResellerShortcodeMerchantDoesNotExist:
    """2026-07-17 reseller-shortcode incident (memory:
    project-reseller-shortcode-incident; no note file exists under
    docs/agent-memory/incidents/ — the closest artifact is the fallback logic
    in app/services/mpesa.py::initiate_stk_push).

    user-40's customer payments died with 'Merchant does not exist' because
    the profile carried a bad mpesa_shortcode (085213) and the STK push used
    it. The pinned behavior: a NULL profile shortcode goes straight to the
    platform shortcode, and a failing reseller shortcode FALLS BACK to the
    platform shortcode instead of killing the payment.
    """

    def _patch_direct(self, monkeypatch, *, fail_for_shortcodes=()):
        from app.services import mpesa

        calls = []

        async def fake_direct(
            phone_number, amount, reference,
            shortcode=None, passkey=None, consumer_key=None,
            consumer_secret=None, callback_url=None, account_reference=None,
        ):
            calls.append(shortcode)
            if shortcode in fail_for_shortcodes:
                raise HTTPException(
                    status_code=500,
                    detail="STK Push initiation failed: Merchant does not exist",
                )
            return mpesa.StkPushResponse(
                checkout_request_id=f"ws_CO_{len(calls)}",
                merchant_request_id=f"mr_{len(calls)}",
            )

        monkeypatch.setattr(mpesa, "initiate_stk_push_direct", fake_direct)
        return mpesa, calls

    async def test_null_profile_shortcode_uses_platform_default(self, monkeypatch):
        mpesa, calls = self._patch_direct(monkeypatch)

        response = await mpesa.initiate_stk_push(
            phone_number="254700000001", amount=100, reference="REF-1",
            shortcode=None,
        )

        assert calls == [None]  # None -> initiate_stk_push_direct uses settings.MPESA_SHORTCODE
        assert response.checkout_request_id == "ws_CO_1"

    async def test_invalid_reseller_shortcode_falls_back_to_platform(self, monkeypatch):
        """The payment must survive a dead reseller shortcode — it retries on
        the platform shortcode instead of propagating 'Merchant does not
        exist' to the customer."""
        mpesa, calls = self._patch_direct(
            monkeypatch, fail_for_shortcodes=("085213",)
        )

        response = await mpesa.initiate_stk_push(
            phone_number="254700000001", amount=100, reference="REF-2",
            shortcode="085213",
        )

        assert calls == ["085213", None]  # reseller attempt, then platform fallback
        assert response.checkout_request_id == "ws_CO_2"

    async def test_platform_shortcode_is_not_treated_as_reseller_override(
        self, monkeypatch
    ):
        from app.config import settings

        mpesa, calls = self._patch_direct(monkeypatch)

        await mpesa.initiate_stk_push(
            phone_number="254700000001", amount=100, reference="REF-3",
            shortcode=settings.MPESA_SHORTCODE,
        )

        assert calls == [None]  # single call on platform credentials


class TestVoucherWalledGardenDomainGap:
    """2026-06-10 voucher walled-garden domain gap (no note file exists under
    docs/agent-memory/incidents/; the durable artifact is the walled-garden
    block emitted by the provisioning script generator).

    Hotspot clients must be able to reach the captive portal and the backend
    API BEFORE authenticating, or the voucher/payment page dead-ends. The
    walled garden on already-provisioned routers is router config (never
    auto-updated), so the unit-testable invariant is: every NEWLY generated
    provisioning script whitelists the portal + API domains and the backend
    IP.
    """

    REQUIRED_WALLED_GARDEN_HOSTS = (
        "isp-frontend-two.vercel.app",   # external captive portal
        "*.vercel.app",                  # Vercel CDN assets
        "isp.bitwavetechnologies.net",   # backend API (.net)
        "isp.bitwavetechnologies.com",   # backend API (.com)
        "ispp.bitwavetechnologies.com",  # backend API, not Cloudflare-proxied
    )

    def _script(self, vpn_type="wireguard"):
        from app.db.models import ProvisioningToken
        from app.services.provisioning import generate_rsc_script

        token = ProvisioningToken(
            token="abc123",
            router_name="Test Router",
            identity="Router-0001",
            vpn_type=vpn_type,
            wireguard_ip="10.0.100.1" if vpn_type == "l2tp" else "10.0.0.2",
            router_admin_password="ApiPassword123",
            server_public_ip="203.0.113.10",
            l2tp_username="l2tp-Router-0001",
            l2tp_password="L2tpPassword123",
            wg_private_key="wg-private",
            server_wg_pubkey="wg-server-public",
            payment_methods=["mpesa", "voucher"],
        )
        return generate_rsc_script(token)

    def test_walled_garden_covers_portal_and_api_domains(self):
        for vpn_type in ("wireguard", "l2tp"):
            script = self._script(vpn_type)
            for host in self.REQUIRED_WALLED_GARDEN_HOSTS:
                assert (
                    f"/ip hotspot walled-garden add dst-host={host} action=allow" in script
                    or f'/ip hotspot walled-garden add dst-host="{host}" action=allow' in script
                ), f"{vpn_type}: walled garden lost {host}"

    def test_walled_garden_allows_backend_ip_directly(self):
        script = self._script()
        assert (
            "/ip hotspot walled-garden ip add dst-address=203.0.113.10/32 "
            "action=accept" in script
        )
