"""Who may sell ads yet, end to end through the real app: the kill switch and
pilot list, the shop link's fixed number, and the staff permission map for the
selling routes. Every STK push here is recorded, none is sent.
"""

from datetime import timedelta

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.api.auth_routes import login_token_claims
from app.db.models import Ad, AdSale, AdSalePayment, AppSetting, PortalSettings, ResellerStaff, SubscriptionStatus
from app.services import ad_sales, mpesa, staff_access
from app.services.ad_serving import invalidate_ad_cache
from app.services.auth import create_access_token, pwd_context
from app.services.mpesa import StkPushResponse
from tests.factories import make_admin, make_reseller

SOLD = {
    "title": "Fresh mandazi", "seller_name": "Mama Njeri Bakery", "phone_number": "0722111222",
    "image_url": "https://media.example/mandazi.webp", "placement": "hero",
    "business_name": "Mama Njeri Bakery", "business_phone": "0722111222",
    "weeks": 2, "price_per_week": 250,
}
HOUSE = {
    "title": "Fast WiFi", "seller_name": "x", "phone_number": "0712345678",
    "image_url": "https://media.example/wifi.webp", "placement": "hero",
}


@pytest.fixture(autouse=True)
def _fresh_staff_cache(monkeypatch):
    staff_access.reset_cache()

    async def no_sms(*args, **kwargs):
        pass
    monkeypatch.setattr(staff_access, "alert_owner", no_sms)
    yield
    staff_access.reset_cache()


@pytest_asyncio.fixture(autouse=True)
async def _fresh_ad_cache():
    await invalidate_ad_cache()
    yield
    await invalidate_ad_cache()


@pytest.fixture
def stk(monkeypatch):
    calls = []

    async def fake_push(**kwargs):
        calls.append(kwargs)
        return StkPushResponse(checkout_request_id=f"ws_CO_{len(calls)}", merchant_request_id=f"mr_{len(calls)}")

    monkeypatch.setattr(mpesa, "initiate_stk_push_direct", fake_push)
    return calls


@pytest_asyncio.fixture
async def client(engine):
    import main
    async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as c:
        yield c


def _bearer(user):
    return {"Authorization": f"Bearer {create_access_token(login_token_claims(user), timedelta(hours=1))}"}


async def _staff_headers(db, owner, permissions):
    staff = ResellerStaff(
        parent_reseller_id=owner.id, name="Staff", email=f"staff{owner.id}-{len(permissions)}@example.com",
        password_hash=pwd_context.hash("staff-password"), permissions=permissions,
    )
    db.add(staff)
    await db.commit()
    await db.refresh(staff)
    token = create_access_token(staff_access.staff_token_claims(staff, owner), timedelta(hours=1))
    return {"Authorization": f"Bearer {token}"}


async def _reseller(db):
    reseller = await make_reseller(
        db, subscription_status=SubscriptionStatus.ACTIVE, support_phone="0712345678", business_name="Acme WiFi",
    )
    db.add(PortalSettings(user_id=reseller.id, show_ads=True))
    await db.commit()
    return reseller


async def _set(db, **values):
    for key, value in values.items():
        db.add(AppSetting(key=key, value=value))
    await db.commit()


async def _pilot(db, *resellers):
    await _set(db, ads_selling_mode="allowlist", ads_selling_allowlist=",".join(str(r.id) for r in resellers))


async def _set_mode(db, mode):
    row = await db.get(AppSetting, "ads_selling_mode")
    row.value = mode
    await db.commit()


def _callback(checkout_id, code=0, receipt="RKX1", amount=500):
    cb = {"CheckoutRequestID": checkout_id, "ResultCode": code, "ResultDesc": "x"}
    if code == 0:
        cb["CallbackMetadata"] = {"Item": [
            {"Name": "Amount", "Value": amount}, {"Name": "MpesaReceiptNumber", "Value": receipt},
        ]}
    return {"Body": {"stkCallback": cb}}


# ---------------------------------------------------------------------------
# The switch itself
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_with_nothing_saved_only_the_test_reseller_can_sell(db):
    assert await ad_sales.selling_settings(db) == ("allowlist", [20])
    assert await ad_sales.selling_allowed(db, 20) is True
    assert await ad_sales.selling_allowed(db, 21) is False


@pytest.mark.parametrize("mode,reseller,allowed", [
    ("off", 7, False), ("off", 8, False),
    ("allowlist", 7, True), ("allowlist", 8, False),
    ("everyone", 7, True), ("everyone", 8, True),
    ("nonsense", 7, False),                     # unknown value fails closed
])
@pytest.mark.asyncio
async def test_each_mode(db, mode, reseller, allowed):
    await _set(db, ads_selling_mode=mode, ads_selling_allowlist="7")
    assert await ad_sales.selling_allowed(db, reseller) is allowed


@pytest.mark.asyncio
async def test_an_emptied_list_lets_nobody_in_rather_than_the_default(db):
    await _set(db, ads_selling_allowlist="")
    assert await ad_sales.selling_allowed(db, 20) is False


# ---------------------------------------------------------------------------
# Refused outside the pilot, working inside it
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_outside_the_pilot_no_sold_ad_is_created_and_no_prompt_goes_out(client, db, stk):
    inside, outside = await _reseller(db), await _reseller(db)
    await _pilot(db, inside)

    r = await client.post("/api/ad-sales", json=SOLD, headers=_bearer(outside))
    assert r.status_code == 403 and "coming soon" in r.json()["detail"]
    assert (await client.get("/api/ad-sales/access", headers=_bearer(outside))).json() == {"allowed": False}
    assert stk == []
    assert (await db.execute(select(Ad))).scalars().first() is None

    # The older free sold ad of someone outside the pilot can't be put up for payment.
    legacy = Ad(title="Old", seller_name="s", phone_number="0722111222", image_url="https://m/x.webp",
                slot="reseller", owner_user_id=outside.id, status="pending")
    db.add(legacy)
    await db.commit()
    r = await client.post(f"/api/ads/{legacy.id}/sale", headers=_bearer(outside), json={
        "business_name": "Shop", "business_phone": "0722111222", "weeks": 1, "price_per_week": 300,
    })
    assert r.status_code == 403
    assert stk == []


@pytest.mark.asyncio
async def test_inside_the_pilot_selling_works(client, db, stk):
    inside = await _reseller(db)
    await _pilot(db, inside)
    assert (await client.get("/api/ad-sales/access", headers=_bearer(inside))).json() == {"allowed": True}
    r = await client.post("/api/ad-sales", json=SOLD, headers=_bearer(inside))
    assert r.status_code == 200, r.text
    assert len(stk) == 1
    assert r.json()["sale"]["prompt"]["status"] == "waiting_for_pin"


@pytest.mark.asyncio
async def test_send_again_and_renew_work_with_a_real_login(client, db, stk):
    # Through the real auth: get_current_user loads the reseller into the
    # request's own session, so a read of it after db.expire_all() would 500.
    reseller, admin = await _reseller(db), await make_admin(db)
    await _pilot(db, reseller)
    h = _bearer(reseller)
    ad_id = (await client.post("/api/ad-sales", json=SOLD, headers=h)).json()["ad"]["id"]
    await client.post("/api/mpesa/ad-sales/callback", json=_callback("ws_CO_1", code=1032))

    r = await client.post(f"/api/ads/{ad_id}/sale/prompt", json={"weeks": 2}, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["prompt"]["status"] == "waiting_for_pin" and r.json()["prompt_result"]["sent"] is True
    await client.post("/api/mpesa/ad-sales/callback", json=_callback("ws_CO_2"))
    await client.post(f"/api/ads/{ad_id}/review", json={"action": "approve"}, headers=_bearer(admin))

    r = await client.post(f"/api/ads/{ad_id}/sale/renew", json={"weeks": 1}, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["due_kind"] == "renewal" and stk[-1]["amount"] == 250


@pytest.mark.asyncio
async def test_own_promos_are_untouched_when_selling_is_off(client, db, stk):
    reseller = await _reseller(db)
    await _set(db, ads_selling_mode="off")
    r = await client.post("/api/ads", json=HOUSE, headers=_bearer(reseller))
    assert r.status_code == 200 and r.json()["status"] == "approved"
    r = await client.put(f"/api/ads/{r.json()['id']}", json={"title": "Faster WiFi"}, headers=_bearer(reseller))
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_a_pending_ad_can_still_be_reviewed_when_selling_is_off(client, db, stk):
    reseller, admin = await _reseller(db), await make_admin(db)
    await _set(db, ads_selling_mode="off")
    ad = Ad(title="Old", seller_name="s", phone_number="0722111222", image_url="https://m/x.webp",
            slot="reseller", owner_user_id=reseller.id, status="pending")
    db.add(ad)
    await db.commit()
    r = await client.post(f"/api/ads/{ad.id}/review", json={"action": "reject", "note": "No"}, headers=_bearer(admin))
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_switching_off_stops_prompts_but_a_prompt_already_sent_still_counts(client, db, stk):
    reseller = await _reseller(db)
    await _pilot(db, reseller)
    out = (await client.post("/api/ad-sales", json=SOLD, headers=_bearer(reseller))).json()
    ad_id = out["ad"]["id"]
    sale = (await db.execute(select(AdSale).where(AdSale.ad_id == ad_id))).scalar_one()
    token = sale.share_token
    await _set_mode(db, "off")

    for path in (f"/api/ads/{ad_id}/sale/prompt", f"/api/ads/{ad_id}/sale/renew"):
        r = await client.post(path, json={}, headers=_bearer(reseller))
        assert r.status_code == 403, path
    assert (await client.post(f"/api/public/promo/{token}/pay")).status_code == 403
    assert (await client.get(f"/api/public/promo/{token}")).json()["payment_due"] is None
    assert len(stk) == 1

    # The shop had already entered its PIN: the money is real and must be recorded.
    await client.post("/api/mpesa/ad-sales/callback", json=_callback("ws_CO_1"))
    payment = (await db.execute(
        select(AdSalePayment).where(AdSalePayment.ad_id == ad_id).execution_options(populate_existing=True)
    )).scalar_one()
    assert payment.status == "paid"


# ---------------------------------------------------------------------------
# Admin controls
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_admin_edits_the_switch_and_the_list(client, db, stk):
    reseller, admin = await _reseller(db), await make_admin(db)
    reseller_id = reseller.id
    h = _bearer(admin)
    rules = (await client.get("/api/ad-review/rules", headers=h)).json()
    assert rules["selling_mode"] == "allowlist"
    assert [row["id"] for row in rules["selling_allowlist"]] == [20]

    r = await client.put("/api/ad-review/rules", json={"selling_allowlist": [reseller.id]}, headers=h)
    assert r.status_code == 200
    assert r.json()["selling_allowlist"] == [{"id": reseller.id, "name": "Acme WiFi"}]
    assert await ad_sales.selling_allowed(db, reseller.id) is True

    r = await client.put("/api/ad-review/rules", json={"selling_mode": "off"}, headers=h)
    assert r.json()["selling_mode"] == "off"
    assert r.json()["blocked_words"]                    # untouched by a partial save
    db.expire_all()
    assert await ad_sales.selling_allowed(db, reseller_id) is False


@pytest.mark.asyncio
async def test_a_bad_save_changes_nothing(client, db, stk):
    admin = await make_admin(db)
    h = _bearer(admin)
    r = await client.put("/api/ad-review/rules", json={"selling_mode": "maybe"}, headers=h)
    assert r.status_code == 400
    r = await client.put("/api/ad-review/rules", json={"selling_mode": "everyone", "selling_allowlist": [999999]}, headers=h)
    assert r.status_code == 400
    r = await client.put("/api/ad-review/rules", json={"selling_mode": "everyone", "selling_allowlist": [admin.id]}, headers=h)
    assert r.status_code == 400                         # an admin is not a reseller
    assert (await client.get("/api/ad-review/rules", headers=h)).json()["selling_mode"] == "allowlist"


@pytest.mark.asyncio
async def test_a_reseller_cannot_open_selling_for_themselves(client, db, stk):
    reseller = await _reseller(db)
    r = await client.put("/api/ad-review/rules", json={"selling_mode": "everyone"}, headers=_bearer(reseller))
    assert r.status_code == 403
    assert await ad_sales.selling_allowed(db, reseller.id) is False


# ---------------------------------------------------------------------------
# The shop link can only prompt the saved number
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_the_shop_link_ignores_any_number_sent_to_it(client, db, stk):
    reseller = await _reseller(db)
    await _pilot(db, reseller)
    out = (await client.post("/api/ad-sales", json=SOLD, headers=_bearer(reseller))).json()
    ad_id = out["ad"]["id"]
    await client.post("/api/mpesa/ad-sales/callback", json=_callback("ws_CO_1", code=1032))
    sale = (await db.execute(select(AdSale).where(AdSale.ad_id == ad_id))).scalar_one()

    r = await client.post(f"/api/public/promo/{sale.share_token}/pay", json={"phone": "0799000111"})
    assert r.status_code == 200 and r.json()["sent"] is True
    assert stk[-1]["phone_number"] == "254722111222"


@pytest.mark.asyncio
async def test_a_renewal_from_the_shop_link_goes_to_the_saved_number(client, db, stk):
    reseller = await _reseller(db)
    await _pilot(db, reseller)
    out = (await client.post("/api/ad-sales", json=SOLD, headers=_bearer(reseller))).json()
    ad_id = out["ad"]["id"]
    await client.post("/api/mpesa/ad-sales/callback", json=_callback("ws_CO_1"))
    await client.post(f"/api/ads/{ad_id}/review", json={"action": "approve"}, headers=_bearer(await make_admin(db)))

    rows = (await db.execute(select(AdSalePayment).where(AdSalePayment.ad_id == ad_id))).scalars().all()
    for row in rows:
        row.created_at = row.created_at - timedelta(minutes=11)
    await db.commit()
    r = await client.post(f"/api/ads/{ad_id}/sale/renew", json={}, headers=_bearer(reseller))
    assert r.status_code == 200, r.text
    await client.post("/api/mpesa/ad-sales/callback", json=_callback(f"ws_CO_{len(stk)}", code=1032))

    sale = (await db.execute(select(AdSale).where(AdSale.ad_id == ad_id))).scalar_one()
    r = await client.post(f"/api/public/promo/{sale.share_token}/pay", json={"phone": "0799000111"})
    assert r.status_code == 200 and r.json()["sent"] is True
    assert stk[-1]["phone_number"] == "254722111222"


# ---------------------------------------------------------------------------
# Staff permissions on the selling routes
# ---------------------------------------------------------------------------

async def _live_sale_ad(client, db, owner):
    out = (await client.post("/api/ad-sales", json=SOLD, headers=_bearer(owner))).json()
    return out["ad"]["id"]


@pytest.mark.asyncio
async def test_portal_staff_can_sell_and_prompt_for_their_owner(client, db, stk):
    owner = await _reseller(db)
    await _pilot(db, owner)
    h = await _staff_headers(db, owner, ["portal.manage"])

    r = await client.post("/api/ad-sales", json=SOLD, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["ad"]["owner_user_id"] == owner.id
    assert len(stk) == 1
    ad_id = r.json()["ad"]["id"]

    assert (await client.get("/api/ad-sales", headers=h)).json()["pagination"]["total"] == 1
    assert (await client.get(f"/api/ads/{ad_id}/sale", headers=h)).status_code == 200
    assert (await client.get("/api/ad-sales/access", headers=h)).json() == {"allowed": True}
    # Reached the handler (the in-flight guard answers), not refused as staff.
    r = await client.post(f"/api/ads/{ad_id}/sale/prompt", json={}, headers=h)
    assert r.status_code == 409 and r.json().get("code") != "staff_permission_denied"


@pytest.mark.asyncio
async def test_portal_staff_are_held_to_their_owners_pilot_status(client, db, stk):
    owner = await _reseller(db)                         # not on the list
    h = await _staff_headers(db, owner, ["portal.manage"])
    r = await client.post("/api/ad-sales", json=SOLD, headers=h)
    assert r.status_code == 403 and r.json().get("code") != "staff_permission_denied"
    assert stk == []


@pytest.mark.asyncio
async def test_portal_staff_cannot_do_bitwaves_part(client, db, stk):
    owner = await _reseller(db)
    await _pilot(db, owner)
    ad_id = await _live_sale_ad(client, db, owner)
    payment = (await db.execute(select(AdSalePayment).where(AdSalePayment.ad_id == ad_id))).scalar_one()
    h = await _staff_headers(db, owner, ["portal.manage"])
    for method, path, body in [
        ("POST", f"/api/ads/{ad_id}/takedown", {"note": "x"}),
        ("POST", f"/api/ads/{ad_id}/review", {"action": "approve"}),
        ("POST", f"/api/ad-sales/payments/{payment.id}/refund", {}),
        ("GET", "/api/ad-review/rules", None),
        ("PUT", "/api/ad-review/rules", {"selling_mode": "everyone"}),
    ]:
        r = await client.request(method, path, json=body, headers=h)
        assert r.status_code == 403, (method, path, r.status_code)
        assert r.json()["code"] == "staff_permission_denied", path


@pytest.mark.asyncio
async def test_view_only_staff_can_read_sales_but_never_prompt(client, db, stk):
    owner = await _reseller(db)
    await _pilot(db, owner)
    ad_id = await _live_sale_ad(client, db, owner)
    sent = len(stk)
    h = await _staff_headers(db, owner, ["dashboard.view"])

    for path in ("/api/ad-sales", "/api/ad-sales/access", "/api/ad-sales/quote?weeks=2&price_per_week=250", f"/api/ads/{ad_id}/sale"):
        assert (await client.get(path, headers=h)).status_code == 200, path

    for path, body in [
        ("/api/ad-sales", SOLD),
        (f"/api/ads/{ad_id}/sale", {"business_name": "S", "business_phone": "0722111222", "weeks": 1, "price_per_week": 300}),
        (f"/api/ads/{ad_id}/sale/prompt", {}),
        (f"/api/ads/{ad_id}/sale/renew", {}),
    ]:
        r = await client.post(path, json=body, headers=h)
        assert r.status_code == 403, path
        assert r.json()["code"] == "staff_permission_denied", path
    assert len(stk) == sent


@pytest.mark.asyncio
async def test_other_staff_get_nothing_from_the_selling_routes(client, db, stk):
    owner = await _reseller(db)
    await _pilot(db, owner)
    ad_id = await _live_sale_ad(client, db, owner)
    sent = len(stk)
    h = await _staff_headers(db, owner, ["customers.view", "routers.view"])
    for method, path, body in [
        ("GET", "/api/ad-sales", None),
        ("GET", "/api/ad-sales/access", None),
        ("GET", "/api/ad-sales/quote?weeks=2&price_per_week=250", None),
        ("GET", f"/api/ads/{ad_id}/sale", None),
        ("POST", "/api/ad-sales", SOLD),
        ("POST", f"/api/ads/{ad_id}/sale/prompt", {}),
        ("POST", f"/api/ads/{ad_id}/sale/renew", {}),
    ]:
        r = await client.request(method, path, json=body, headers=h)
        assert r.status_code == 403, (method, path, r.status_code)
        assert r.json()["code"] == "staff_permission_denied", path
    assert len(stk) == sent


@pytest.mark.asyncio
async def test_admin_takedown_reject_refund_and_lists_work_with_a_real_login(client, db, stk):
    reseller, admin = await _reseller(db), await make_admin(db)
    await _pilot(db, reseller)
    h_owner, h_admin = _bearer(reseller), _bearer(admin)

    paid = (await client.post("/api/ad-sales", json=SOLD, headers=h_owner)).json()["ad"]["id"]
    r = await client.post(f"/api/ads/{paid}/review", json={"action": "reject", "note": "Blurry"}, headers=h_admin)
    assert r.status_code == 200, r.text
    await client.post("/api/mpesa/ad-sales/callback", json=_callback("ws_CO_1"))
    queue = (await client.get("/api/ad-sales?payout_status=refund_due", headers=h_admin)).json()
    assert [row["ad_id"] for row in queue["sales"]] == [paid]
    detail = (await client.get(f"/api/ads/{paid}/sale", headers=h_admin)).json()
    r = await client.post(f"/api/ad-sales/payments/{detail['payments'][0]['id']}/refund", json={}, headers=h_admin)
    assert r.status_code == 200, r.text

    other = (await client.post("/api/ad-sales", json={**SOLD, "title": "Chapati"}, headers=h_owner)).json()["ad"]["id"]
    r = await client.post(f"/api/ads/{other}/takedown", json={"note": "Misleading"}, headers=h_admin)
    assert r.status_code == 200, r.text
    assert (await client.get("/api/ad-sales", headers=h_owner)).status_code == 200
    assert (await client.get("/api/ads/manage", headers=h_owner)).status_code == 200
