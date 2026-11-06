"""Presigned uploads of ad photos and videos to Cloudflare R2.

The dashboard asks for an upload URL, then PUTs the file straight to R2, so
the bytes never touch this box (one small worker, read-only container). R2
speaks the S3 API; the URL is signed with AWS Signature V4 in query-string
form, implemented here with the standard library rather than adding boto3.

The signature covers the content type and the exact byte size the client
declared, so R2 rejects an upload that is a different type or larger than
what was approved here.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import uuid
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Optional
from urllib.parse import quote

from app.config import settings

ALLOWED_TYPES = {
    "image/webp": ("webp", 2 * 1024 * 1024),
    "image/jpeg": ("jpg", 2 * 1024 * 1024),
    "image/png": ("png", 2 * 1024 * 1024),
    "video/mp4": ("mp4", 12 * 1024 * 1024),
}
UPLOAD_URL_TTL_SECONDS = 600


class MediaNotConfigured(Exception):
    pass


class MediaRejected(Exception):
    pass


def media_configured() -> bool:
    return all([
        settings.R2_ACCOUNT_ID, settings.R2_ACCESS_KEY_ID, settings.R2_SECRET_ACCESS_KEY,
        settings.R2_BUCKET, settings.AD_MEDIA_PUBLIC_BASE,
    ])


def public_media_base() -> str:
    return (settings.AD_MEDIA_PUBLIC_BASE or "").rstrip("/")


# New uploads are stored and served under c/. Until 4 Nov 2026 the key began
# with ads/, so photos were served from /media/ads/..., and EasyList (Adblock
# Plus, uBlock Origin, AdGuard, Brave Shields) has the generic rule
# "/media/ads/*$image": the upload worked, but the dashboard thumbnail, the
# preview and the portal hero never loaded in a browser with an ad blocker.
# Keep words like ad, ads, advert, banner, sponsor and promo out of media
# paths. The media Worker serves /media/c/<path> from c/<path>, falling back to
# the old ads/<path> object, so old links are rewritten rather than migrated.
KEY_PREFIX = "c/"
LEGACY_KEY_PREFIX = "ads/"


def public_media_url(url: Optional[str]) -> Optional[str]:
    """A stored media link in its ad-blocker-safe form. Links saved before the
    c/ prefix existed are rewritten; anything else is returned unchanged."""
    base = public_media_base()
    if not url or not base:
        return url
    legacy = f"{base}/{LEGACY_KEY_PREFIX}"
    if url.startswith(legacy):
        return f"{base}/{KEY_PREFIX}{url[len(legacy):]}"
    return url


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def presign_url(
    *,
    method: str,
    host: str,
    path: str,
    access_key: str,
    secret_key: str,
    region: str,
    service: str = "s3",
    expires: int = UPLOAD_URL_TTL_SECONDS,
    signed_headers: Optional[dict] = None,
    now: Optional[datetime] = None,
) -> str:
    """AWS SigV4 query-string presigning (the S3 "presigned URL" form).

    signed_headers are header name -> value pairs the client must send
    unchanged; host is always signed. `path` must already be URI-encoded.
    """
    now = now or datetime.utcnow()
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    scope = f"{datestamp}/{region}/{service}/aws4_request"

    headers = {"host": host}
    for name, value in (signed_headers or {}).items():
        headers[name.lower()] = str(value).strip()
    names = sorted(headers)
    signed = ";".join(names)

    query = {
        "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
        "X-Amz-Credential": f"{access_key}/{scope}",
        "X-Amz-Date": amz_date,
        "X-Amz-Expires": str(expires),
        "X-Amz-SignedHeaders": signed,
    }
    canonical_query = "&".join(
        f"{quote(k, safe='-_.~')}={quote(v, safe='-_.~')}" for k, v in sorted(query.items())
    )
    canonical_headers = "".join(f"{n}:{headers[n]}\n" for n in names)
    canonical_request = "\n".join([
        method, path, canonical_query, canonical_headers, signed, "UNSIGNED-PAYLOAD",
    ])
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256", amz_date, scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
    ])
    key = _hmac(("AWS4" + secret_key).encode("utf-8"), datestamp)
    for part in (region, service, "aws4_request"):
        key = _hmac(key, part)
    signature = hmac.new(key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"https://{host}{path}?{canonical_query}&X-Amz-Signature={signature}"


@dataclass
class UploadTicket:
    upload_url: str
    public_url: str
    key: str
    content_type: str
    max_bytes: int
    expires_in: int


def create_upload(content_type: str, size: int, owner_label: str, now: Optional[datetime] = None) -> UploadTicket:
    """A one-file upload slot: where to PUT it, and the URL portals will load."""
    if not media_configured():
        raise MediaNotConfigured("Ad media storage is not set up yet")
    if content_type not in ALLOWED_TYPES:
        raise MediaRejected("Upload a WebP, JPEG or PNG photo, or an MP4 video")
    ext, limit = ALLOWED_TYPES[content_type]
    if not isinstance(size, int) or size <= 0:
        raise MediaRejected("The file is empty")
    if size > limit:
        raise MediaRejected(f"The file is larger than {limit // (1024 * 1024)} MB")

    now = now or datetime.utcnow()
    safe_owner = "".join(c for c in owner_label if c.isalnum() or c in "-_")[:40] or "media"
    key = f"{KEY_PREFIX}{now:%Y/%m}/{safe_owner}-{uuid.uuid4().hex[:16]}.{ext}"
    host = f"{settings.R2_ACCOUNT_ID}.r2.cloudflarestorage.com"
    path = "/" + quote(f"{settings.R2_BUCKET}/{key}", safe="/-_.~")
    url = presign_url(
        method="PUT", host=host, path=path,
        access_key=settings.R2_ACCESS_KEY_ID, secret_key=settings.R2_SECRET_ACCESS_KEY,
        region="auto", signed_headers={"content-type": content_type, "content-length": size},
        now=now,
    )
    return UploadTicket(
        upload_url=url, public_url=f"{public_media_base()}/{key}", key=key,
        content_type=content_type, max_bytes=limit, expires_in=UPLOAD_URL_TTL_SECONDS,
    )


# A reseller's own photo for the portal hero. Stored in the same bucket as ad
# media and served by the same Worker, because that host is already in every
# router's walled garden. Portal users pay for this on metered connections
# before they have even bought a plan: the bundled presets are 25-66 KB, so the
# dashboard re-encodes to about that and this cap, enforced by R2 through the
# signed content-length, is the backstop. No PNG and no video on purpose.
HERO_ALLOWED_TYPES = {"image/jpeg", "image/webp"}
HERO_MAX_BYTES = 300 * 1024


def create_portal_hero_upload(content_type: str, size: int, owner_label: str, now: Optional[datetime] = None) -> UploadTicket:
    """An upload slot for one portal hero photo, far tighter than an ad's."""
    if not media_configured():
        raise MediaNotConfigured("Photo storage is not set up yet")
    if content_type not in HERO_ALLOWED_TYPES:
        raise MediaRejected("Upload a JPEG or WebP photo")
    if not isinstance(size, int) or size <= 0:
        raise MediaRejected("The file is empty")
    if size > HERO_MAX_BYTES:
        raise MediaRejected(f"The photo is larger than {HERO_MAX_BYTES // 1024} KB")
    return replace(create_upload(content_type, size, owner_label, now=now), max_bytes=HERO_MAX_BYTES)


def is_portal_hero_url(url: Optional[str]) -> bool:
    """True for a link create_portal_hero_upload could have produced. The portal
    client (isp-frontend script.js customHeroUrl) checks the same shape."""
    base = public_media_base()
    if not url or not base or not url.startswith(f"{base}/"):
        return False
    rest = url[len(base) + 1:]
    return re.fullmatch(rf"{KEY_PREFIX}\d{{4}}/\d{{2}}/[A-Za-z0-9_-]+\.(?:jpg|webp)", rest) is not None
