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
import uuid
from dataclasses import dataclass
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
    safe_owner = "".join(c for c in owner_label if c.isalnum() or c in "-_")[:40] or "ad"
    key = f"ads/{now:%Y/%m}/{safe_owner}-{uuid.uuid4().hex[:16]}.{ext}"
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
