# Ads API (hero ads, 2026-10)

Backend: `app/api/ads_routes.py`, serving and counting in `app/services/ad_serving.py`,
uploads in `app/services/ad_media.py`. All signed-in routes take the usual
`Authorization: Bearer <token>`.

## Who can do what

| | Bitwave admin | Reseller |
|---|---|---|
| See ads | every ad | only their own |
| Create | `slot: "platform"`, approved at once, any routers or network-wide | `slot: "house"` (own promo, default) or `"reseller"` (an ad they sold), approved at once after the automatic checks, only their own routers |
| Edit | anything; status unchanged | own ads; a live ad stays live and the automatic checks run again on a change |
| Take down | yes | no |
| Advertisers list | yes | no (403) |

Staff logins act as their reseller (same "own ads only" scope), limited by their
permissions (`app/services/staff_permissions.py`):

| | Captive portal (`portal.manage`) | View dashboard (`dashboard.view`) | Other staff |
|---|---|---|---|
| List / open ads, stats, analytics | yes | yes (read-only) | no |
| Raw click / impression rows (device MACs) | yes | no | no |
| Create, edit, pause, delete, upload media | yes | no | no |
| Take down, approve / reject old rows, advertisers | no (Bitwave admin only) | no | no |

A portal shows an ad only when it is active, approved, inside `starts_at`/`expires_at`,
owned by Bitwave or by the router's reseller, and `router_ids` is null or lists the router.
Hero ads are ordered platform → reseller → house, at most 3.

## Ad object (manage views)

```json
{
  "id": 12, "title": "Red onions", "description": null,
  "seller_name": "Wanjiku Greens", "seller_location": "By the matatu stage",
  "phone_number": "0712000111", "whatsapp_number": "0712000111",
  "price": "KSH 120 / kg", "price_value": 120, "category": "produce",
  "badge_type": null, "badge_text": null,
  "placement": "hero",            // "hero" | "local"
  "media_type": "video",          // "image" | "video"
  "image_url": null, "video_url": "https://…/ads/2026/10/r7-ab12.mp4",
  "poster_url": "https://…/ads/2026/10/r7-cd34.webp",
  "image_fit": "cover",           // "cover" (photo) | "contain" (cut-out product)
  "bg_color": "#14532D",
  "slot": "house",                // "platform" | "reseller" | "house"
  "owner_user_id": 7,             // null = Bitwave
  "owner_name": "Acme WiFi",      // reseller's business name, or "Bitwave"
  "router_ids": [50, 51],         // null = all the owner's routers (network-wide for Bitwave)
  "status": "pending",            // "pending" | "approved" | "rejected"
  "review_note": null, "reviewed_at": null,
  "is_active": true, "priority": 0,
  "starts_at": null, "expires_at": "2026-11-01T00:00:00",
  "created_at": "2026-10-23T09:00:00",
  "views_count": 340,             // unique phones per day, summed, last 30 days
  "clicks_count": 12
}
```

## Endpoints

| Method & path | Body / query | Notes |
|---|---|---|
| `GET /api/ads/manage` | `?status=approved&placement=hero&owner_user_id=7&bitwave_only=true&newly_live=true&page=1&per_page=50` | `{ads: [Ad], pagination}`. `owner_user_id` / `bitwave_only` are admin filters. `newly_live=true` is resellers' ads on portals now, newest go-live first, for an admin to check afterwards. |
| `GET /api/ads/manage/{id}` | | one Ad; 404 for someone else's |
| `POST /api/ads` | Ad fields: required `title`, `seller_name`, `phone_number`; a photo ad needs `image_url`, a video ad `video_url` (+ `poster_url`). Optional `slot`, `router_ids`, `starts_at`, `expires_at` (ISO), `advertiser_id` (admin only), `priority` (admin only) | returns the Ad |
| `PUT /api/ads/{id}` | any subset of the create fields, plus `is_active`; `advertiser_id` (admin, Bitwave ads only) | returns the Ad. A live ad stays live. A customer-visible change (placement included) runs the automatic checks again, and puts an ad still marked pending or rejected live, unless Bitwave took it down. |
| `DELETE /api/ads/{id}` | | |
| `POST /api/ads/{id}/review` | `{action: "approve" \| "reject", note}` | admin only, and nothing waits on it: for rows from before review was removed, and to undo a takedown. `reject` needs a `note` (shown to the reseller). Approving a paid ad starts its weeks and credits the reseller once; repeating it changes nothing. |
| `GET /api/ads/{id}/stats` | `?days=30` | `{impressions, clicks, by_placement: {hero: {impressions, clicks}, wait_screen…}, daily: [{day, impressions, clicks}]}` |
| `GET /api/ads/analytics` | `?days=30` | totals over the caller's ads (admin: all), plus `by_placement` |
| `GET /api/ads/{id}/clicks`, `/impressions` | `?page&per_page` | raw event lists |
| `POST /api/ads/media/upload-url` | `{content_type, size}` | see below |
| `GET/POST /api/advertisers` | | admin only |

## Uploading a photo or video

1. `POST /api/ads/media/upload-url` with `{"content_type": "video/mp4", "size": <bytes>}`.
   Allowed: `image/webp`, `image/jpeg`, `image/png` (≤ 2 MB) and `video/mp4` (≤ 12 MB).
   - `503` = storage not set up yet (R2 env vars empty) — show "Uploads aren't switched on yet".
   - `400` = wrong type or too big (`detail` says which).
2. `PUT` the file to `upload_url` with header `Content-Type: <content_type>` (the browser
   sets Content-Length; it must equal the declared `size`). No auth header.
3. Save `public_url` as the ad's `image_url` / `video_url` / `poster_url`.

Media paths must not contain words ad blockers match. New keys are `c/<yyyy>/<mm>/<owner>-<hex>.<ext>`,
served at `AD_MEDIA_PUBLIC_BASE/c/...`. Keys made before 4 Nov 2026 start with `ads/`, and
EasyList's generic `/media/ads/*$image` rule hid those photos in every browser with an ad blocker.
The media Worker serves `/media/c/<path>` from `c/<path>` and falls back to the old `ads/<path>`
object. The API returns old `/media/ads/` links rewritten to `/media/c/` and stores the new form
when an ad is saved, so no stored data needed migrating.

Media must come from `AD_MEDIA_PUBLIC_BASE` once it is configured (portals load it before the
customer has internet, so it has to be a walled-garden host); until then any `https://` URL is
accepted.

Creative guidance to show in the form: keep any text in the middle of the frame (clear of the
top 20% and bottom 30%), videos ≤ 15 s, start with the offer, assume no sound.

## Public (portal)

- `GET /api/public/portal/{identity}` → `ads`: this router's live ads (empty when the
  reseller's `show_ads` is off), each with `placement`, `media_type`, `video_url`, `poster_url`,
  `image_fit`, `bg_color`, `slot`.
- `POST /api/ads/impression` `{ad_ids, placement, device_id, mac_address, router_identity}` and
  `POST /api/ads/click` `{ad_id, click_type: call|whatsapp|view_details, placement, …}`.
  Placements: `hero`, `wait_screen`, `success_page`, `local`. Counted once per ad, placement,
  phone and UTC day; always answer 200.
- Neutral paths for the same three handlers, which is what the portal calls because ad blockers
  block `/ads` URLs: `GET /api/public/spots`, `POST /api/public/spots/seen` (impression),
  `POST /api/public/spots/tap` (click). The `/api/ads` paths stay for portal pages cached on phones.

## Selling ads through Bitwave (Dennis, 4 Nov 2026)

Code: `app/api/ad_sales_routes.py`, money rules in `app/services/ad_sales.py`, review rules in
`app/services/ad_review.py`. Tests: `tests/test_ad_sales.py`, `tests/test_ad_review_rules.py`.

### Rules

- **Own promo (`house`) is free** and goes live at once after the automatic checks. Its
  `seller_name` is always the reseller's network name (`business_name`, else
  `organization_name`); its phone and WhatsApp must be one of the reseller's support numbers
  (`users.support_phone`, portal support phone/WhatsApp). Anything else is refused with
  "choose An ad I sold".
- **An ad I sold (`reseller`)** is created only through `POST /api/ad-sales` (the old
  `POST /api/ads` refuses `slot: "reseller"` for resellers). Price per week ≥ KES 200
  (≤ 12,500), 1–12 whole weeks. Kenyan (M-Pesa) resellers only for now.
- **Selling is a pilot until an admin opens it.** `ads_selling_mode` is `off`, `allowlist` or
  `everyone`; with nothing saved it is `allowlist` with reseller 20 only. Outside it, creating a sold
  ad and sending any prompt (reseller or shop link) answer 403 "coming soon". Own promos, reviews,
  callbacks for prompts already sent, payouts and the shop's report keep working.
- **The reseller's Show Ads portal switch must be on.** It is off by default and a portal with it
  off shows no ads, so every prompt (create, resend, renew, the shop's link) is refused with a 400
  until it is on. Switching it off later hides a running ad and stops its paid days counting.
- **Nobody reviews an ad first** (Dennis, 5 Nov 2026). A sold ad is approved at creation but has no
  paid period, so no portal shows it until the shop pays. When the payment is confirmed it goes live
  on its own: the paid weeks start and the reseller's 80% is credited at that moment. An edit keeps a
  live ad live, with the automatic checks run again. Admins check afterwards with
  `GET /api/ads/manage?newly_live=true` and take down anything wrong.
- **Rows from before that rule are left as they are.** No migration publishes them. An own promo
  still marked `pending` shows nowhere until its owner changes it or an admin approves it. An unpaid
  sold ad still marked `pending` goes live if its shop pays. A paid ad stuck in `pending` goes live,
  and credits once, when an admin calls `POST /api/ads/{id}/review` with `{"action": "approve"}`.
- **Money**: the business pays the total by STK push to Bitwave's own paybill (the system
  shortcode), also for direct-settlement resellers. `bitwave_fee = floor(amount × 20 / 100)`,
  `reseller_share = amount − bitwave_fee` (rounding favours the reseller: KES 1,005 → 201 / 804).
  The split is on the gross amount. Safaricom's collection fee comes out of Bitwave's 20%, and the
  reseller's normal payout transfer fee still applies when money is sent.
- **Time off doesn't use up paid time**: while a running ad is paused or Show Ads is off, its paid
  days stop counting and `live_until` keeps moving. When it shows again `expires_at` moves out by the
  time it was off. Overlapping reasons count once.
- **Price changes**: the weekly price is capped at KES 12,500. A new price applies from the next
  renewal only: a paid period keeps its price, and `price_per_week` on the sale changes when the
  renewal is paid. A renewal at a new price answers 409 until `confirm_new_price: true` says the
  reseller told the shop. While it is due, the sale shows `due_price_per_week` and
  `price_changed_from`, and the shop's link shows `payment_due.previous_price_per_week`. The M-Pesa
  prompt itself shows the amount.
- **Paid period starts when the payment is confirmed.** A renewal paid while live extends the end
  date; paid after the end, it starts now. `weeks_banked` is only non-zero on old rows that can't go
  live by themselves (paid while pending under the old review, or pending after a takedown).
  A sold ad never runs without a paid period (`ad_serving` refuses a `reseller` ad with no
  `expires_at`) and stops by itself at `expires_at`.
- **Payout**: the reseller's 80% is credited when the paid weeks start running and is a separate
  term of the payout balance (`mpesa_b2b.get_unpaid_balance`), so the normal B2B payout pays it.
  It is never written to `customer_payments` (hotspot revenue, GMV and the 3% hotspot commission
  don't include it). Bitwave's 20% is the `ad_commission` stream in
  `/api/admin/metrics/platform-earnings`; paid-but-not-running money and refunds due are under
  `not_counted`.
- **Automatic checks on every submit**: blocked words (admin-editable, whole words), a valid Kenyan
  mobile number, media present. Own promos are also locked to the network's name and support number.
- **Takedown is the safety net**: an admin takes any ad off every portal at once. An ad taken down
  stays down whatever its owner edits; only an admin can put it back.
- **Refunds are never automatic**: rejected before it ran, ad deleted before it ran, or a second
  payment for the same order → `refund_status: "due"` for the whole amount, listed for an admin,
  who refunds by hand and records it.
- **Taking down an ad that has run** (or rejecting one): the unused whole days are refunded, and the
  paid period ends now. A day already started counts as used. Unused days come off the newest paid
  weeks first, per payment: `refund_amount = floor(amount × unused / paid_days)`. What is kept is split
  80/20 as usual, so `reseller_recovery + bitwave_refund_part = refund_amount` to the shilling. The
  reseller's part is a `reseller_transaction_charges` row (reference `ad-refund:<payment id>`) that the
  payout balance subtracts and the Account Statement lists. It can take the balance below zero;
  nothing is paid out until later earnings cover it. Repeating a takedown, rejection or callback adds
  nothing. Bitwave's part comes off `ad_commission`.

### Prompt guards

- One prompt at a time: a prompt still waiting (< 3 min old) blocks another (409). Before a new
  one, a waiting prompt older than 90 s is checked with Safaricom's STK query; if it turns out
  paid, nothing is sent.
- At most 3 prompts per ad in 10 minutes (429).
- Statuses on the newest prompt (`sale.prompt.status`): `sending`, `waiting_for_pin`, `paid`,
  `cancelled` (ResultCode 1032), `timed_out` (1037/1019, or no answer in 30 min), `failed`, with
  M-Pesa's `reason`. A success callback after a timeout still counts.
- Callbacks, the reconciler (every 60 s) and the business's link can all report one payment; it
  is applied and credited once (sale row lock, paid-state check, unique receipt).

### Endpoints

| Method & path | Who | Body / query | Notes |
|---|---|---|---|
| `GET /api/ad-sales/access` | signed in | | `{allowed}`: may this reseller sell yet |
| `GET /api/ad-sales/quote` | any | `?weeks&price_per_week` | `{amount, bitwave_fee, reseller_share, fee_percent}` |
| `POST /api/ad-sales` | reseller, staff `portal.manage` | Ad fields + `business_name`, `business_phone`, `weeks`, `price_per_week` | `{ad, sale}`; sends the prompt at once |
| `GET /api/ad-sales` | reseller (own), admin (all) | `?state&payout_status&owner_user_id&page&per_page` | `{sales, totals, pagination}`. `payout_status=refund_due` is the refund queue |
| `GET /api/ads/{id}/sale` | owner, admin | | the sale summary with `payments`; poll every few seconds while a prompt is out |
| `POST /api/ads/{id}/sale` | owner | `business_name, business_phone, weeks, price_per_week` | put an older sold ad up for payment |
| `POST /api/ads/{id}/sale/prompt` | owner | `{phone?, weeks?, price_per_week?, confirm_new_price?}` | (re)send the prompt for what is due |
| `POST /api/ads/{id}/sale/renew` | owner | `{phone?, weeks?, price_per_week?, confirm_new_price?}` | renewal prompt (default same price and length) |
| `POST /api/ads/{id}/takedown` | admin | `{note}` | any ad, off every portal now |
| `POST /api/ad-sales/payments/{id}/refund` | admin | `{note?}` | records a hand refund; moves no money |
| `GET/PUT /api/ad-review/rules` | admin | any of `{blocked_words: [...], selling_mode, selling_allowlist: [ids]}` | |
| `POST /api/mpesa/ad-sales/callback` | Safaricom | | always `ResultCode 0` |
| `GET /api/public/promo/{token}` | anyone with the link | | the business's report: title, dates, views, taps, daily, amount due. No fees, phones or device data |
| `POST /api/public/promo/{token}/pay` | anyone with the link | none | prompt for what is due, only ever to the number saved on the sale (same guards) |

Sale summary (`ad.sale` on `/api/ads/manage` rows, and the routes above):

```json
{
  "sale_id": 3, "business_name": "Mama Njeri Bakery", "business_phone": "254722111222",
  "price_per_week": 250, "weeks": 2, "fee_percent": 20,
  "state": "awaiting_payment",   // awaiting_payment | payment_failed | in_review | live | paused | ended | rejected | taken_down | deleted
  "amount_due": 500, "due_kind": "initial", "payment_status": "awaiting_payment",
  "prompt": {"payment_id": 9, "status": "waiting_for_pin", "amount": 500, "phone": "254722111222",
             "kind": "initial", "reason": null, "sent_at": "…", "retry_after": "…"},
  "can_resend": false, "paid_total": 0, "bitwave_fee_total": 0, "reseller_share_total": 0,
  "credited_total": 0, "refund_due_total": 0,
  "payout_status": "none",       // none | waiting_to_run | credited | refund_due | refunded
  "weeks_banked": 0, "live_from": null, "live_until": null,
  "renewal_due": false, "can_renew": false,
  "due_weeks": 2, "due_price_per_week": 250, "price_changed_from": null,
  "refunded_total": 0, "reseller_recovered_total": 0, "bitwave_refund_part_total": 0,
  "shop_net_total": 0, "bitwave_fee_net_total": 0, "reseller_share_net_total": 0,
  "clock_stopped": false, "off_reason": null,   // paused | not_approved | show_ads_off
  "off_seconds_total": 0,
  "share_url": "https://bitwavetechnologies.com/promo/<token>"
}
```

The reseller's Account Statement (`/api/reseller/account-statement`) lists each credited ad
payment as an `ad_revenue` entry and reports `balance.total_ad_revenue` and
`period_summary.ad_revenue`.
