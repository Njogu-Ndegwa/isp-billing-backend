# Ads API (hero ads, 2026-10)

Backend: `app/api/ads_routes.py`, serving and counting in `app/services/ad_serving.py`,
uploads in `app/services/ad_media.py`. All signed-in routes take the usual
`Authorization: Bearer <token>`.

## Who can do what

| | Bitwave admin | Reseller |
|---|---|---|
| See ads | every ad | only their own |
| Create | `slot: "platform"`, approved at once, any routers or network-wide | `slot: "house"` (own promo, default) or `"reseller"` (an ad they sold), **pending** until an admin approves, only their own routers |
| Edit | anything; status unchanged | own ads; changing what customers see (title, photo, video, phone, price…) sends an approved ad back to **pending**; pausing (`is_active`) does not |
| Approve / reject | yes | no |
| Advertisers list | yes | no (403) |

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
| `GET /api/ads/manage` | `?status=pending&placement=hero&owner_user_id=7&bitwave_only=true&page=1&per_page=50` | `{ads: [Ad], pagination}`. `status=pending` is the admin review queue; `owner_user_id` / `bitwave_only` are admin filters. |
| `GET /api/ads/manage/{id}` | | one Ad; 404 for someone else's |
| `POST /api/ads` | Ad fields: required `title`, `seller_name`, `phone_number`; a photo ad needs `image_url`, a video ad `video_url` (+ `poster_url`). Optional `slot`, `router_ids`, `starts_at`, `expires_at` (ISO), `advertiser_id` (admin only), `priority` (admin only) | returns the Ad |
| `PUT /api/ads/{id}` | any subset of the create fields, plus `is_active`; `advertiser_id` (admin, Bitwave ads only) | returns the Ad. A reseller's ad goes back to pending only when a customer-visible value actually changes (placement included). |
| `DELETE /api/ads/{id}` | | |
| `POST /api/ads/{id}/review` | `{action: "approve" \| "reject", note}` | admin only; `reject` needs a `note` (shown to the reseller) |
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
