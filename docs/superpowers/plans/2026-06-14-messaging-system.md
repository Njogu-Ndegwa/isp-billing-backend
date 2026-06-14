# Messaging System Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a messaging system: pluggable SMS provider (Africa's Talking first), reseller→customer bulk SMS with templates, admin→reseller in-app inbox (+ optional SMS), and reseller self-purchase of integer SMS credits via the existing M-Pesa paybill.

**Architecture:** A thin `MessagingProvider` interface with an Africa's Talking implementation, selected by config (mirrors `payment_gateway.py`). An auditable credit ledger + per-reseller balance. Bulk sends reserve credits in a short transaction, then a background dispatcher fans out to the provider **with no DB session held**, recording per-recipient results and refunding failures. Schema ships via the existing idempotent startup-migration pattern (no Alembic).

**Tech Stack:** Python 3.13, FastAPI, SQLAlchemy (async, asyncpg/PostgreSQL; SQLite in tests), httpx, APScheduler, pytest/pytest-asyncio. Frontend: Next.js (App Router) in `../isp-billing-admin`.

**Reference spec:** `docs/superpowers/specs/2026-06-14-messaging-system-design.md`

**Conventions to follow (already in the repo):**
- Migrations: idempotent `run_*_migrations()` in `main.py` `startup_event`, each in its own try/except (non-fatal). Standalone scripts in `migrations/` mirror `migrations/create_mtn_momo_tables.py`.
- Routes: `APIRouter`, `verify_token` + `get_current_user(token, db)` from `app.services.auth`; admin gate via a local `_require_admin`.
- DB discipline (AGENTS.md): never hold a DB session across network I/O; commit, then do I/O, then persist in a fresh short session. Background work load-sheds under DB pool pressure.
- Tests: `tests/conftest.py` (in-memory SQLite, `db` fixture), `tests/factories.py` (`make_reseller`, `make_customer`, `make_plan`, `make_router`).

---

## File Structure

**Backend — create:**
- `app/services/messaging/__init__.py` — `get_provider()`, re-export `count_segments`.
- `app/services/messaging/base.py` — `SendResult`, `MessagingProvider` ABC.
- `app/services/messaging/segments.py` — `count_segments()`.
- `app/services/messaging/africas_talking.py` — `AfricasTalkingProvider`.
- `app/services/sms_credits.py` — balance/ledger ops (account get-or-create, grant, deduct, refund).
- `app/services/sms_dispatch.py` — `dispatch_campaign(campaign_id)`, `resolve_recipients(...)`, `prune_old_messages()`.
- `app/api/messaging_routes.py` — reseller-facing endpoints.
- `app/api/admin_messaging_routes.py` — admin-facing endpoints.
- `migrations/create_messaging_tables.py` — standalone idempotent migration.
- Tests: `tests/test_messaging_segments.py`, `tests/test_messaging_provider.py`, `tests/test_sms_credits.py`, `tests/test_messaging_dispatch.py`, `tests/test_messaging_routes.py`, `tests/test_admin_messaging_routes.py`.

**Backend — modify:**
- `app/config.py` — new settings.
- `app/db/models.py` — 5 enums + 8 models; add `CheckConstraint` to imports.
- `main.py` — `run_messaging_migrations()` + startup call; register two routers; retention scheduler job.
- `tests/factories.py` — `make_sms_credit_account` helper.

**Frontend — create:** `app/messaging/page.tsx`, `app/admin/messaging/page.tsx`, plus a small inbox component.
**Frontend — modify:** `app/lib/api.ts`, `app/lib/types.ts` (or `types.ts`), and the nav/layout to add the Messaging link + inbox bell.

---

## Phase 0 — Provider foundation

### Task 1: Config settings

**Files:**
- Modify: `app/config.py`

- [ ] **Step 1: Add settings** — insert after the `INSURANCE_*` block (before `class Config`):

```python
    # --- Messaging / SMS -------------------------------------------------
    SMS_PROVIDER: str = "africastalking"
    AT_USERNAME: str = ""
    AT_API_KEY: str = ""
    AT_SENDER_ID: str = ""
    AT_BASE_URL: str = "https://api.africastalking.com"
    SMS_DISPATCH_CHUNK_SIZE: int = 100
    SMS_DISPATCH_ENABLED: bool = True
```

- [ ] **Step 2: Verify it imports**

Run: `python -c "from app.config import settings; print(settings.SMS_PROVIDER, settings.SMS_DISPATCH_CHUNK_SIZE)"`
Expected: `africastalking 100`

- [ ] **Step 3: Commit**

```bash
git add app/config.py
git commit -m "feat(messaging): add SMS provider config settings"
```

### Task 2: Segment counter

**Files:**
- Create: `app/services/messaging/__init__.py` (empty for now, makes it a package)
- Create: `app/services/messaging/segments.py`
- Test: `tests/test_messaging_segments.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_messaging_segments.py
from app.services.messaging.segments import count_segments


def test_empty_message_is_one_segment():
    assert count_segments("") == 1


def test_short_gsm7_is_one_segment():
    assert count_segments("Hello there") == 1


def test_gsm7_160_boundary():
    assert count_segments("a" * 160) == 1
    assert count_segments("a" * 161) == 2          # 161 -> 153+8 -> 2 parts
    assert count_segments("a" * 306) == 2          # 2*153
    assert count_segments("a" * 307) == 3


def test_unicode_uses_70_67_boundaries():
    assert count_segments("é" * 70) == 1           # é is GSM7-representable... use emoji below
    assert count_segments("🙂") == 1
    assert count_segments("🙂" * 71) == 2           # emoji forces UCS-2: >70 -> multipart 67


def test_gsm7_extension_char_counts_double():
    # '€' is in the GSM-7 extension table -> weight 2, stays GSM-7
    assert count_segments("€" * 80) == 1            # 80*2=160 -> single
    assert count_segments("€" * 81) == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_messaging_segments.py -q`
Expected: FAIL (module `app.services.messaging.segments` not found)

- [ ] **Step 3: Implement**

```python
# app/services/messaging/segments.py
"""SMS segment counting (GSM-7 vs UCS-2), independent of any provider."""

import math

# GSM 03.38 basic alphabet
_GSM7_BASIC = (
    "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ ÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?"
    "¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà"
)
# Characters that require an escape (count as 2 septets) but keep us in GSM-7
_GSM7_EXTENSION = "^{}\\[~]|€"

_GSM7_SET = set(_GSM7_BASIC) | set(_GSM7_EXTENSION)


def _is_gsm7(body: str) -> bool:
    return all(ch in _GSM7_SET for ch in body)


def _gsm7_weight(body: str) -> int:
    return sum(2 if ch in _GSM7_EXTENSION else 1 for ch in body)


def count_segments(body: str) -> int:
    """Number of SMS segments (>=1) this body consumes per recipient.

    GSM-7: 160 single / 153 per part. UCS-2: 70 single / 67 per part.
    Extension chars (^{}[]~|\\€) weigh 2 septets but stay GSM-7.
    """
    if body is None:
        body = ""
    if _is_gsm7(body):
        length = _gsm7_weight(body)
        single, multi = 160, 153
    else:
        length = len(body)
        single, multi = 70, 67
    if length <= single:
        return 1
    return math.ceil(length / multi)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_messaging_segments.py -q`
Expected: PASS (adjust the `é` assertion if needed: `é` is GSM-7 basic, so `"é"*70` weight 70 → 1 segment; keep the emoji cases as the UCS-2 proof.)

- [ ] **Step 5: Commit**

```bash
git add app/services/messaging/__init__.py app/services/messaging/segments.py tests/test_messaging_segments.py
git commit -m "feat(messaging): SMS segment counter (GSM-7/UCS-2)"
```

### Task 3: Provider base + Africa's Talking + factory

**Files:**
- Create: `app/services/messaging/base.py`
- Create: `app/services/messaging/africas_talking.py`
- Modify: `app/services/messaging/__init__.py`
- Test: `tests/test_messaging_provider.py`

- [ ] **Step 1: Write `base.py`**

```python
# app/services/messaging/base.py
"""Provider-agnostic messaging interface."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class SendResult:
    recipient: str
    success: bool
    provider_message_id: Optional[str] = None
    status: Optional[str] = None       # provider's status string
    error: Optional[str] = None
    cost: Optional[str] = None


class MessagingProvider(ABC):
    name: str = "base"

    @abstractmethod
    async def send_bulk(
        self, recipients: list[str], body: str, sender_id: str
    ) -> list[SendResult]:
        """Send one body to many recipients; return one result per recipient."""
        raise NotImplementedError
```

- [ ] **Step 2: Write the failing test**

```python
# tests/test_messaging_provider.py
import httpx
import pytest

from app.services.messaging import get_provider
from app.services.messaging.africas_talking import AfricasTalkingProvider
from app.services.messaging.base import SendResult


def test_factory_returns_africas_talking(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "SMS_PROVIDER", "africastalking")
    provider = get_provider()
    assert isinstance(provider, AfricasTalkingProvider)


def test_factory_unknown_provider_raises(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "SMS_PROVIDER", "nope")
    with pytest.raises(ValueError):
        get_provider()


@pytest.mark.asyncio
async def test_africas_talking_parses_per_recipient(monkeypatch):
    captured = {}

    class _FakeResponse:
        status_code = 201
        def raise_for_status(self): pass
        def json(self):
            return {"SMSMessageData": {"Recipients": [
                {"number": "+254712345678", "status": "Success",
                 "messageId": "ATXid_1", "cost": "KES 0.8000"},
                {"number": "+254700000000", "status": "Failed",
                 "messageId": "None", "cost": "0"},
            ]}}

    class _FakeClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, data=None, headers=None):
            captured["url"] = url
            captured["data"] = data
            captured["headers"] = headers
            return _FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)
    provider = AfricasTalkingProvider(username="sandbox", api_key="key",
                                      base_url="https://api.example")
    results = await provider.send_bulk(
        ["+254712345678", "+254700000000"], "Hi", "BRAND"
    )
    assert captured["data"]["username"] == "sandbox"
    assert captured["data"]["to"] == "+254712345678,+254700000000"
    assert captured["data"]["from"] == "BRAND"
    assert captured["headers"]["apiKey"] == "key"
    by_num = {r.recipient: r for r in results}
    assert by_num["+254712345678"].success is True
    assert by_num["+254712345678"].provider_message_id == "ATXid_1"
    assert by_num["+254700000000"].success is False
```

- [ ] **Step 3: Run test to verify it fails**

Run: `python -m pytest tests/test_messaging_provider.py -q`
Expected: FAIL (`AfricasTalkingProvider` / `get_provider` not found)

- [ ] **Step 4: Implement `africas_talking.py`**

```python
# app/services/messaging/africas_talking.py
"""Africa's Talking bulk SMS provider."""

import logging
from typing import Optional

import httpx

from app.services.messaging.base import MessagingProvider, SendResult

logger = logging.getLogger(__name__)


class AfricasTalkingProvider(MessagingProvider):
    name = "africastalking"

    def __init__(self, username: str, api_key: str, base_url: str):
        self.username = username
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")

    async def send_bulk(
        self, recipients: list[str], body: str, sender_id: str
    ) -> list[SendResult]:
        if not recipients:
            return []
        data = {
            "username": self.username,
            "to": ",".join(recipients),
            "message": body,
        }
        if sender_id:
            data["from"] = sender_id
        headers = {
            "apiKey": self.api_key,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        url = f"{self.base_url}/version1/messaging"
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(url, data=data, headers=headers)
            resp.raise_for_status()
            payload = resp.json()

        recs = (payload.get("SMSMessageData", {}) or {}).get("Recipients", []) or []
        results: list[SendResult] = []
        for r in recs:
            status = (r.get("status") or "").strip()
            mid = r.get("messageId")
            if mid in (None, "", "None"):
                mid = None
            results.append(SendResult(
                recipient=r.get("number", ""),
                success=status.lower() == "success",
                provider_message_id=mid,
                status=status,
                error=None if status.lower() == "success" else status,
                cost=r.get("cost"),
            ))
        # If AT returned nothing per-recipient, mark all as failed for safety.
        if not results:
            results = [SendResult(recipient=n, success=False,
                                  status="no_response", error="no_response")
                       for n in recipients]
        return results
```

- [ ] **Step 5: Implement the factory in `__init__.py`**

```python
# app/services/messaging/__init__.py
"""Messaging provider factory + segment helper re-export."""

from app.config import settings
from app.services.messaging.base import MessagingProvider, SendResult
from app.services.messaging.segments import count_segments

__all__ = ["get_provider", "count_segments", "MessagingProvider", "SendResult"]


def get_provider() -> MessagingProvider:
    provider = (settings.SMS_PROVIDER or "").lower()
    if provider == "africastalking":
        from app.services.messaging.africas_talking import AfricasTalkingProvider
        return AfricasTalkingProvider(
            username=settings.AT_USERNAME,
            api_key=settings.AT_API_KEY,
            base_url=settings.AT_BASE_URL,
        )
    raise ValueError(f"Unsupported SMS provider: {settings.SMS_PROVIDER!r}")
```

- [ ] **Step 6: Run test to verify it passes**

Run: `python -m pytest tests/test_messaging_provider.py -q`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add app/services/messaging/ tests/test_messaging_provider.py
git commit -m "feat(messaging): provider interface + Africa's Talking + factory"
```

---

## Phase 1 — Data model + migration

### Task 4: Models + enums

**Files:**
- Modify: `app/db/models.py`

- [ ] **Step 1: Extend the top import line** — change line 1 to add `CheckConstraint`:

```python
from sqlalchemy import Column, Integer, String, Enum, DateTime, ForeignKey, Float, Boolean, BigInteger, DECIMAL, Index, UniqueConstraint, CheckConstraint
```

- [ ] **Step 2: Append enums + models at the END of `app/db/models.py`**

```python
# ========================================
# MESSAGING / SMS
# ========================================

class SmsCreditTxnKind(str, enum.Enum):
    PURCHASE = "purchase"
    SEND_DEBIT = "send_debit"
    REFUND = "refund"
    ADMIN_ADJUSTMENT = "admin_adjustment"


class SmsCreditOrderStatus(str, enum.Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"
    EXPIRED = "expired"


class SmsCampaignStatus(str, enum.Enum):
    QUEUED = "queued"
    SENDING = "sending"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELED = "canceled"


class SmsMessageStatus(str, enum.Enum):
    QUEUED = "queued"
    SENT = "sent"
    DELIVERED = "delivered"
    FAILED = "failed"


class SmsMessageKind(str, enum.Enum):
    RESELLER_TO_CUSTOMER = "reseller_to_customer"
    ADMIN_TO_RESELLER = "admin_to_reseller"


class MessagingSettings(Base):
    __tablename__ = "messaging_settings"
    id = Column(Integer, primary_key=True, autoincrement=True)
    price_per_sms_kes = Column(DECIMAL(6, 2), nullable=False, default=1, server_default="1")
    min_purchase_credits = Column(Integer, nullable=False, default=10, server_default="10")
    sender_id = Column(String(20), nullable=True)
    provider = Column(String(50), nullable=False, default="africastalking", server_default="africastalking")
    enabled = Column(Boolean, nullable=False, default=True, server_default="true")
    message_retention_days = Column(Integer, nullable=False, default=60, server_default="60")
    bundles = Column(JSON, nullable=True)  # [{"credits": int, "label": str}]
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SmsCreditAccount(Base):
    __tablename__ = "sms_credit_accounts"
    __table_args__ = (
        CheckConstraint("balance >= 0", name="ck_sms_credit_balance_non_negative"),
    )
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    balance = Column(Integer, nullable=False, default=0, server_default="0")
    total_purchased = Column(Integer, nullable=False, default=0, server_default="0")
    total_spent = Column(Integer, nullable=False, default=0, server_default="0")
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SmsCreditTransaction(Base):
    __tablename__ = "sms_credit_transactions"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    change = Column(Integer, nullable=False)
    balance_after = Column(Integer, nullable=False)
    kind = Column(Enum(SmsCreditTxnKind, name="smscredittxnkind",
                       values_callable=lambda e: [x.value for x in e]), nullable=False)
    reference = Column(String(64), nullable=True)
    note = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class SmsCreditOrder(Base):
    __tablename__ = "sms_credit_orders"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    quantity = Column(Integer, nullable=False)
    unit_price = Column(DECIMAL(6, 2), nullable=False)
    amount = Column(Integer, nullable=False)  # whole KES
    phone_number = Column(String(20), nullable=False)
    status = Column(Enum(SmsCreditOrderStatus, name="smscreditorderstatus",
                         values_callable=lambda e: [x.value for x in e]),
                    nullable=False, default=SmsCreditOrderStatus.PENDING)
    mpesa_checkout_request_id = Column(String(128), nullable=True, index=True)
    mpesa_merchant_request_id = Column(String(128), nullable=True)
    payment_reference = Column(String(128), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class MessageTemplate(Base):
    __tablename__ = "message_templates"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String(120), nullable=False)
    body = Column(String(1000), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SmsCampaign(Base):
    __tablename__ = "sms_campaigns"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    body = Column(String(1000), nullable=False)
    recipient_count = Column(Integer, nullable=False)
    segments_per_message = Column(Integer, nullable=False)
    total_credits = Column(Integer, nullable=False)
    sent_count = Column(Integer, nullable=False, default=0, server_default="0")
    failed_count = Column(Integer, nullable=False, default=0, server_default="0")
    refunded_credits = Column(Integer, nullable=False, default=0, server_default="0")
    sender_id = Column(String(20), nullable=True)
    status = Column(Enum(SmsCampaignStatus, name="smscampaignstatus",
                         values_callable=lambda e: [x.value for x in e]),
                    nullable=False, default=SmsCampaignStatus.QUEUED)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SmsMessage(Base):
    __tablename__ = "sms_messages"
    id = Column(Integer, primary_key=True, autoincrement=True)
    campaign_id = Column(Integer, ForeignKey("sms_campaigns.id"), nullable=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=True)
    recipient_phone = Column(String(20), nullable=False)
    body = Column(String(1000), nullable=False)
    segments = Column(Integer, nullable=False)
    credits_charged = Column(Integer, nullable=False)
    kind = Column(Enum(SmsMessageKind, name="smsmessagekind",
                       values_callable=lambda e: [x.value for x in e]), nullable=False)
    provider = Column(String(50), nullable=True)
    provider_message_id = Column(String(128), nullable=True)
    status = Column(Enum(SmsMessageStatus, name="smsmessagestatus",
                         values_callable=lambda e: [x.value for x in e]),
                    nullable=False, default=SmsMessageStatus.QUEUED)
    error = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ResellerInboxMessage(Base):
    __tablename__ = "reseller_inbox_messages"
    id = Column(Integer, primary_key=True, autoincrement=True)
    recipient_user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    sender_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    subject = Column(String(200), nullable=True)
    body = Column(String(2000), nullable=False)
    is_read = Column(Boolean, nullable=False, default=False, server_default="false")
    read_at = Column(DateTime, nullable=True)
    sent_sms = Column(Boolean, nullable=False, default=False, server_default="false")
    broadcast_id = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
```

- [ ] **Step 3: Verify models import & create_all works on SQLite**

Run:
```bash
python -c "import asyncio; from sqlalchemy.ext.asyncio import create_async_engine; from app.db.database import Base; import app.db.models; \
e=create_async_engine('sqlite+aiosqlite:///:memory:'); \
asyncio.run(__import__('app.db.models'))" 2>&1 | head -5
python -m pytest tests/test_account_numbers.py -q
```
Expected: existing tests still PASS (new tables registered, no import errors).

- [ ] **Step 4: Commit**

```bash
git add app/db/models.py
git commit -m "feat(messaging): add 8 SMS/messaging models + enums"
```

### Task 5: Migration script + startup auto-migration

**Files:**
- Create: `migrations/create_messaging_tables.py`
- Modify: `main.py`

- [ ] **Step 1: Write the standalone migration** (mirrors `migrations/create_mtn_momo_tables.py`)

```python
# migrations/create_messaging_tables.py
"""
Migration: Messaging / SMS system.

Creates enums, 8 tables, lean indexes (incl. a partial index on failed
sms_messages), and seeds the messaging_settings singleton (id=1).
Idempotent — safe to run repeatedly.

Usage:
    python migrations/create_messaging_tables.py
    python migrations/create_messaging_tables.py --rollback
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import async_engine as engine


ENUMS = {
    "smscredittxnkind": ["purchase", "send_debit", "refund", "admin_adjustment"],
    "smscreditorderstatus": ["pending", "completed", "failed", "expired"],
    "smscampaignstatus": ["queued", "sending", "completed", "partial", "failed", "canceled"],
    "smsmessagestatus": ["queued", "sent", "delivered", "failed"],
    "smsmessagekind": ["reseller_to_customer", "admin_to_reseller"],
}

TABLES = [
    """
    CREATE TABLE IF NOT EXISTS messaging_settings (
        id SERIAL PRIMARY KEY,
        price_per_sms_kes NUMERIC(6,2) NOT NULL DEFAULT 1,
        min_purchase_credits INTEGER NOT NULL DEFAULT 10,
        sender_id VARCHAR(20),
        provider VARCHAR(50) NOT NULL DEFAULT 'africastalking',
        enabled BOOLEAN NOT NULL DEFAULT TRUE,
        message_retention_days INTEGER NOT NULL DEFAULT 60,
        bundles JSON,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sms_credit_accounts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL UNIQUE REFERENCES users(id),
        balance INTEGER NOT NULL DEFAULT 0,
        total_purchased INTEGER NOT NULL DEFAULT 0,
        total_spent INTEGER NOT NULL DEFAULT 0,
        updated_at TIMESTAMP DEFAULT NOW(),
        CONSTRAINT ck_sms_credit_balance_non_negative CHECK (balance >= 0)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sms_credit_transactions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        change INTEGER NOT NULL,
        balance_after INTEGER NOT NULL,
        kind smscredittxnkind NOT NULL,
        reference VARCHAR(64),
        note VARCHAR(255),
        created_at TIMESTAMP DEFAULT NOW()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sms_credit_orders (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        quantity INTEGER NOT NULL,
        unit_price NUMERIC(6,2) NOT NULL,
        amount INTEGER NOT NULL,
        phone_number VARCHAR(20) NOT NULL,
        status smscreditorderstatus NOT NULL DEFAULT 'pending',
        mpesa_checkout_request_id VARCHAR(128),
        mpesa_merchant_request_id VARCHAR(128),
        payment_reference VARCHAR(128),
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS message_templates (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        name VARCHAR(120) NOT NULL,
        body VARCHAR(1000) NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sms_campaigns (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        body VARCHAR(1000) NOT NULL,
        recipient_count INTEGER NOT NULL,
        segments_per_message INTEGER NOT NULL,
        total_credits INTEGER NOT NULL,
        sent_count INTEGER NOT NULL DEFAULT 0,
        failed_count INTEGER NOT NULL DEFAULT 0,
        refunded_credits INTEGER NOT NULL DEFAULT 0,
        sender_id VARCHAR(20),
        status smscampaignstatus NOT NULL DEFAULT 'queued',
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sms_messages (
        id SERIAL PRIMARY KEY,
        campaign_id INTEGER REFERENCES sms_campaigns(id),
        user_id INTEGER NOT NULL REFERENCES users(id),
        customer_id INTEGER REFERENCES customers(id),
        recipient_phone VARCHAR(20) NOT NULL,
        body VARCHAR(1000) NOT NULL,
        segments INTEGER NOT NULL,
        credits_charged INTEGER NOT NULL,
        kind smsmessagekind NOT NULL,
        provider VARCHAR(50),
        provider_message_id VARCHAR(128),
        status smsmessagestatus NOT NULL DEFAULT 'queued',
        error VARCHAR(255),
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS reseller_inbox_messages (
        id SERIAL PRIMARY KEY,
        recipient_user_id INTEGER NOT NULL REFERENCES users(id),
        sender_user_id INTEGER NOT NULL REFERENCES users(id),
        subject VARCHAR(200),
        body VARCHAR(2000) NOT NULL,
        is_read BOOLEAN NOT NULL DEFAULT FALSE,
        read_at TIMESTAMP,
        sent_sms BOOLEAN NOT NULL DEFAULT FALSE,
        broadcast_id VARCHAR(64),
        created_at TIMESTAMP DEFAULT NOW()
    )
    """,
]

INDEXES = [
    "CREATE INDEX IF NOT EXISTS ix_sms_credit_tx_user_created ON sms_credit_transactions(user_id, created_at)",
    "CREATE INDEX IF NOT EXISTS ix_sms_credit_orders_checkout ON sms_credit_orders(mpesa_checkout_request_id)",
    "CREATE INDEX IF NOT EXISTS ix_sms_credit_orders_user_created ON sms_credit_orders(user_id, created_at)",
    "CREATE INDEX IF NOT EXISTS ix_message_templates_user ON message_templates(user_id)",
    "CREATE INDEX IF NOT EXISTS ix_sms_campaigns_user_created ON sms_campaigns(user_id, created_at)",
    "CREATE INDEX IF NOT EXISTS ix_sms_messages_campaign ON sms_messages(campaign_id)",
    "CREATE INDEX IF NOT EXISTS ix_sms_messages_created ON sms_messages(created_at)",
    # Partial index: only failed rows (small, kept longer, queried for troubleshooting)
    "CREATE INDEX IF NOT EXISTS ix_sms_messages_failed ON sms_messages(created_at) WHERE status = 'failed'",
    "CREATE INDEX IF NOT EXISTS ix_inbox_recipient_read ON reseller_inbox_messages(recipient_user_id, is_read)",
]


async def migrate():
    # enums first, each tolerant of pre-existence
    async with engine.begin() as conn:
        for name, values in ENUMS.items():
            vals = ", ".join(f"'{v}'" for v in values)
            await conn.execute(text(
                f"DO $$ BEGIN CREATE TYPE {name} AS ENUM ({vals}); "
                f"EXCEPTION WHEN duplicate_object THEN NULL; END $$;"
            ))
        for ddl in TABLES:
            await conn.execute(text(ddl))
        for ddl in INDEXES:
            await conn.execute(text(ddl))
        # seed singleton settings row
        await conn.execute(text(
            "INSERT INTO messaging_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING"
        ))
    print("Messaging migration completed successfully!")


async def rollback():
    async with engine.begin() as conn:
        for t in ["sms_messages", "reseller_inbox_messages", "sms_campaigns",
                  "message_templates", "sms_credit_orders",
                  "sms_credit_transactions", "sms_credit_accounts",
                  "messaging_settings"]:
            await conn.execute(text(f"DROP TABLE IF EXISTS {t} CASCADE"))
        for name in ENUMS:
            await conn.execute(text(f"DROP TYPE IF EXISTS {name}"))
    print("Rollback completed.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Messaging tables migration")
    parser.add_argument("--rollback", action="store_true")
    args = parser.parse_args()
    asyncio.run(rollback() if args.rollback else migrate())
```

- [ ] **Step 2: Add `run_messaging_migrations()` to `main.py`** — place it next to the other `run_*_migrations` defs (e.g. right before `@app.on_event("startup")`). It must be idempotent and use existence checks like the other functions:

```python
async def run_messaging_migrations():
    """Create messaging/SMS enums, tables, indexes; seed settings. Idempotent."""
    from sqlalchemy import text, inspect

    enums = {
        "smscredittxnkind": ["purchase", "send_debit", "refund", "admin_adjustment"],
        "smscreditorderstatus": ["pending", "completed", "failed", "expired"],
        "smscampaignstatus": ["queued", "sending", "completed", "partial", "failed", "canceled"],
        "smsmessagestatus": ["queued", "sent", "delivered", "failed"],
        "smsmessagekind": ["reseller_to_customer", "admin_to_reseller"],
    }
    async with async_engine.begin() as conn:
        for name, values in enums.items():
            vals = ", ".join(f"'{v}'" for v in values)
            await conn.execute(text(
                f"DO $$ BEGIN CREATE TYPE {name} AS ENUM ({vals}); "
                f"EXCEPTION WHEN duplicate_object THEN NULL; END $$;"
            ))

        def existing_tables(connection):
            return set(inspect(connection).get_table_names())

        tables = await conn.run_sync(existing_tables)

        # Reuse Base.metadata to create only the messaging tables we added.
        from app.db.models import (
            MessagingSettings, SmsCreditAccount, SmsCreditTransaction,
            SmsCreditOrder, MessageTemplate, SmsCampaign, SmsMessage,
            ResellerInboxMessage,
        )
        targets = [
            MessagingSettings, SmsCreditAccount, SmsCreditTransaction,
            SmsCreditOrder, MessageTemplate, SmsCampaign, SmsMessage,
            ResellerInboxMessage,
        ]
        to_create = [m.__table__ for m in targets if m.__tablename__ not in tables]
        if to_create:
            await conn.run_sync(lambda c: Base.metadata.create_all(c, tables=to_create))

        # Partial index for failed rows (Postgres only; harmless if it exists).
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_sms_messages_failed "
            "ON sms_messages(created_at) WHERE status = 'failed'"
        ))
        # Seed singleton settings row.
        await conn.execute(text(
            "INSERT INTO messaging_settings (id) VALUES (1) "
            "ON CONFLICT (id) DO NOTHING"
        ))
    logger.info("Migration: Messaging/SMS tables, enums, indexes ready")
```

> Note: using `Base.metadata.create_all(..., tables=[...])` keeps the enum type
> names consistent with the models and avoids hand-maintaining DDL twice. The
> explicit `CREATE TYPE` block first ensures the enums exist for the columns.

- [ ] **Step 3: Call it in `startup_event`** — after the anti-tethering block (around line 1670), before the `scheduler.add_job(...)` calls:

```python
    try:
        await run_messaging_migrations()
        logger.info("Messaging migrations completed successfully")
    except Exception as e:
        logger.error(f"Messaging migration failed (non-fatal): {e}")
```

- [ ] **Step 4: Verify the migration script parses and existing tests pass**

Run:
```bash
python -c "import ast; ast.parse(open('migrations/create_messaging_tables.py').read()); print('parse OK')"
python -m pytest tests/test_account_numbers.py -q
```
Expected: `parse OK` and existing tests PASS.

- [ ] **Step 5: Commit**

```bash
git add migrations/create_messaging_tables.py main.py
git commit -m "feat(messaging): idempotent auto-migration (script + startup)"
```

---

## Phase 2 — Credit ledger service

### Task 6: `sms_credits` service

**Files:**
- Create: `app/services/sms_credits.py`
- Modify: `tests/factories.py`
- Test: `tests/test_sms_credits.py`

- [ ] **Step 1: Add a factory helper** to `tests/factories.py` (append; extend the `from app.db.models import (...)` block to include `SmsCreditAccount`):

```python
async def make_sms_account(db: AsyncSession, reseller: "User", *, balance: int = 0):
    from app.db.models import SmsCreditAccount
    acct = SmsCreditAccount(user_id=reseller.id, balance=balance,
                            total_purchased=balance)
    db.add(acct)
    await db.commit()
    await db.refresh(acct)
    return acct
```

- [ ] **Step 2: Write the failing test**

```python
# tests/test_sms_credits.py
import pytest

from app.db.models import SmsCreditTransaction, SmsCreditTxnKind
from app.services import sms_credits
from tests.factories import make_reseller, make_sms_account


@pytest.mark.asyncio
async def test_get_or_create_account_starts_at_zero(db):
    r = await make_reseller(db)
    acct = await sms_credits.get_or_create_account(db, r.id)
    await db.commit()
    assert acct.balance == 0


@pytest.mark.asyncio
async def test_grant_increases_balance_and_writes_ledger(db):
    r = await make_reseller(db)
    await sms_credits.grant(db, r.id, 100, SmsCreditTxnKind.PURCHASE, reference="SMS-1")
    await db.commit()
    acct = await sms_credits.get_or_create_account(db, r.id)
    assert acct.balance == 100
    assert acct.total_purchased == 100
    rows = (await db.execute(
        SmsCreditTransaction.__table__.select()
    )).fetchall()
    assert len(rows) == 1
    assert rows[0].change == 100
    assert rows[0].balance_after == 100


@pytest.mark.asyncio
async def test_deduct_requires_sufficient_balance(db):
    r = await make_reseller(db)
    await make_sms_account(db, r, balance=5)
    ok = await sms_credits.try_deduct(db, r.id, 10, reference="C-1")
    await db.commit()
    assert ok is False
    acct = await sms_credits.get_or_create_account(db, r.id)
    assert acct.balance == 5


@pytest.mark.asyncio
async def test_deduct_then_refund(db):
    r = await make_reseller(db)
    await make_sms_account(db, r, balance=10)
    ok = await sms_credits.try_deduct(db, r.id, 8, reference="C-2")
    await db.commit()
    assert ok is True
    await sms_credits.refund(db, r.id, 3, reference="C-2")
    await db.commit()
    acct = await sms_credits.get_or_create_account(db, r.id)
    assert acct.balance == 5          # 10 - 8 + 3
    assert acct.total_spent == 8
```

- [ ] **Step 3: Run test to verify it fails**

Run: `python -m pytest tests/test_sms_credits.py -q`
Expected: FAIL (module not found)

- [ ] **Step 4: Implement `app/services/sms_credits.py`**

```python
# app/services/sms_credits.py
"""SMS credit balance + ledger operations.

All functions take a session and mutate within the caller's transaction
(caller commits). They never perform network I/O.
"""

from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    SmsCreditAccount,
    SmsCreditTransaction,
    SmsCreditTxnKind,
)


async def get_or_create_account(db: AsyncSession, user_id: int) -> SmsCreditAccount:
    acct = (await db.execute(
        select(SmsCreditAccount).where(SmsCreditAccount.user_id == user_id)
    )).scalar_one_or_none()
    if acct is None:
        acct = SmsCreditAccount(user_id=user_id, balance=0)
        db.add(acct)
        await db.flush()
    return acct


async def _ledger(db, user_id, change, balance_after, kind, reference, note):
    db.add(SmsCreditTransaction(
        user_id=user_id, change=change, balance_after=balance_after,
        kind=kind, reference=reference, note=note,
    ))


async def grant(db: AsyncSession, user_id: int, amount: int,
                kind: SmsCreditTxnKind = SmsCreditTxnKind.PURCHASE,
                reference: Optional[str] = None, note: Optional[str] = None) -> int:
    """Add credits (purchase / admin grant). Returns new balance."""
    if amount <= 0:
        raise ValueError("grant amount must be positive")
    acct = await get_or_create_account(db, user_id)
    acct.balance += amount
    if kind == SmsCreditTxnKind.PURCHASE:
        acct.total_purchased += amount
    await db.flush()
    await _ledger(db, user_id, amount, acct.balance, kind, reference, note)
    return acct.balance


async def try_deduct(db: AsyncSession, user_id: int, amount: int,
                     reference: Optional[str] = None,
                     note: Optional[str] = None) -> bool:
    """Deduct credits for a send. Returns False (no change) if insufficient."""
    if amount <= 0:
        return True
    acct = await get_or_create_account(db, user_id)
    if acct.balance < amount:
        return False
    acct.balance -= amount
    acct.total_spent += amount
    await db.flush()
    await _ledger(db, user_id, -amount, acct.balance,
                  SmsCreditTxnKind.SEND_DEBIT, reference, note)
    return True


async def refund(db: AsyncSession, user_id: int, amount: int,
                 reference: Optional[str] = None,
                 note: Optional[str] = None) -> int:
    """Return credits for failed recipients. Returns new balance."""
    if amount <= 0:
        return (await get_or_create_account(db, user_id)).balance
    acct = await get_or_create_account(db, user_id)
    acct.balance += amount
    acct.total_spent = max(0, acct.total_spent - amount)
    await db.flush()
    await _ledger(db, user_id, amount, acct.balance,
                  SmsCreditTxnKind.REFUND, reference, note)
    return acct.balance


async def adjust(db: AsyncSession, user_id: int, delta: int,
                 note: Optional[str] = None) -> int:
    """Admin manual adjustment (can be +/-). Clamps at zero. Returns new balance."""
    acct = await get_or_create_account(db, user_id)
    acct.balance = max(0, acct.balance + delta)
    if delta > 0:
        acct.total_purchased += delta
    await db.flush()
    await _ledger(db, user_id, delta, acct.balance,
                  SmsCreditTxnKind.ADMIN_ADJUSTMENT, None, note)
    return acct.balance
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python -m pytest tests/test_sms_credits.py -q`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add app/services/sms_credits.py tests/factories.py tests/test_sms_credits.py
git commit -m "feat(messaging): SMS credit ledger service"
```

---

## Phase 3 — Send flow (recipients + dispatch)

### Task 7: Recipient resolution + dispatch service

**Files:**
- Create: `app/services/sms_dispatch.py`
- Test: `tests/test_messaging_dispatch.py`

Design note (DB discipline): `dispatch_campaign(campaign_id: int)` takes an **id, not a session** — it opens its own short sessions and calls the provider between them, structurally guaranteeing no session is held across provider I/O. `resolve_recipients` is a pure read that takes a session.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_messaging_dispatch.py
from datetime import datetime, timedelta

import pytest

from app.db.models import (
    Customer, CustomerStatus, SmsCampaign, SmsCampaignStatus,
    SmsMessage, SmsMessageStatus, SmsMessageKind,
)
from app.services import sms_dispatch, sms_credits
from app.services.messaging.base import SendResult
from tests.factories import make_reseller, make_plan, make_customer, make_sms_account


@pytest.mark.asyncio
async def test_resolve_recipients_all_scoped_to_reseller(db):
    r1 = await make_reseller(db)
    r2 = await make_reseller(db)
    p1 = await make_plan(db, r1)
    await make_customer(db, r1, p1, phone="254700000001", status=CustomerStatus.ACTIVE)
    await make_customer(db, r1, p1, phone="254700000002", status=CustomerStatus.ACTIVE)
    p2 = await make_plan(db, r2)
    await make_customer(db, r2, p2, phone="254700000003", status=CustomerStatus.ACTIVE)

    recips = await sms_dispatch.resolve_recipients(db, r1.id, filter="all")
    phones = {c["phone"] for c in recips}
    assert phones == {"254700000001", "254700000002"}


@pytest.mark.asyncio
async def test_dispatch_marks_sent_and_refunds_failures(db, session_factory, monkeypatch):
    r = await make_reseller(db)
    p = await make_plan(db, r)
    c1 = await make_customer(db, r, p, phone="254700000001")
    c2 = await make_customer(db, r, p, phone="254700000002")
    await make_sms_account(db, r, balance=10)

    # reserve 2 credits (1 segment x 2 recipients) and build campaign + rows
    await sms_credits.try_deduct(db, r.id, 2, reference="pending")
    camp = SmsCampaign(user_id=r.id, body="Hi", recipient_count=2,
                       segments_per_message=1, total_credits=2,
                       status=SmsCampaignStatus.QUEUED, sender_id="BRAND")
    db.add(camp)
    await db.flush()
    for cust in (c1, c2):
        db.add(SmsMessage(campaign_id=camp.id, user_id=r.id, customer_id=cust.id,
                          recipient_phone=cust.phone, body="Hi", segments=1,
                          credits_charged=1, kind=SmsMessageKind.RESELLER_TO_CUSTOMER,
                          status=SmsMessageStatus.QUEUED))
    await db.commit()
    camp_id = camp.id

    class _FakeProvider:
        name = "fake"
        async def send_bulk(self, recipients, body, sender_id):
            return [
                SendResult(recipient="254700000001", success=True,
                           provider_message_id="X1", status="Success"),
                SendResult(recipient="254700000002", success=False,
                           status="Failed", error="Failed"),
            ]

    monkeypatch.setattr(sms_dispatch, "get_provider", lambda: _FakeProvider())

    await sms_dispatch.dispatch_campaign(camp_id)

    async with session_factory() as s:
        camp = await s.get(SmsCampaign, camp_id)
        assert camp.status == SmsCampaignStatus.PARTIAL
        assert camp.sent_count == 1
        assert camp.failed_count == 1
        assert camp.refunded_credits == 1
        acct = await sms_credits.get_or_create_account(s, r.id)
        # started 10, reserved -2, refunded +1 for the one failure => 9
        assert acct.balance == 9
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_messaging_dispatch.py -q`
Expected: FAIL (module not found)

- [ ] **Step 3: Implement `app/services/sms_dispatch.py`**

```python
# app/services/sms_dispatch.py
"""Recipient resolution + background SMS campaign dispatch.

DB discipline: dispatch_campaign() takes a campaign id (not a session). It
opens short sessions, calls the provider with NO session held, and persists
per-recipient results in fresh sessions. Credits for failed recipients are
refunded in their own short transaction.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import select, delete

from app.config import settings
from app.db.database import async_session
from app.db.models import (
    Customer, CustomerStatus,
    SmsCampaign, SmsCampaignStatus,
    SmsMessage, SmsMessageStatus,
    MessagingSettings,
)
from app.services import sms_credits
from app.services.messaging import get_provider

logger = logging.getLogger(__name__)


async def resolve_recipients(db, reseller_id: int, *, filter: str = "all",
                             plan_id: Optional[int] = None,
                             customer_ids: Optional[list[int]] = None,
                             expiring_days: int = 7) -> list[dict]:
    """Return [{customer_id, phone}] for a reseller, de-duplicated by phone."""
    stmt = select(Customer.id, Customer.phone).where(Customer.user_id == reseller_id)
    stmt = stmt.where(Customer.phone.isnot(None))
    if customer_ids:
        stmt = stmt.where(Customer.id.in_(customer_ids))
    elif filter == "by_plan" and plan_id:
        stmt = stmt.where(Customer.plan_id == plan_id)
    elif filter == "active":
        stmt = stmt.where(Customer.status == CustomerStatus.ACTIVE)
    elif filter == "expiring":
        cutoff = datetime.utcnow() + timedelta(days=expiring_days)
        stmt = stmt.where(Customer.expiry.isnot(None), Customer.expiry <= cutoff)
    rows = (await db.execute(stmt)).all()
    seen, out = set(), []
    for cid, phone in rows:
        phone = (phone or "").strip()
        if not phone or phone in seen:
            continue
        seen.add(phone)
        out.append({"customer_id": cid, "phone": phone})
    return out


def _chunks(seq, size):
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


async def dispatch_campaign(campaign_id: int) -> None:
    """Send all queued messages for a campaign. Self-managed sessions only."""
    if not settings.SMS_DISPATCH_ENABLED:
        logger.warning("SMS dispatch disabled; campaign %s left queued", campaign_id)
        return

    # 1) load campaign + queued rows (short session), mark sending
    async with async_session() as db:
        camp = await db.get(SmsCampaign, campaign_id)
        if camp is None or camp.status not in (SmsCampaignStatus.QUEUED,
                                               SmsCampaignStatus.SENDING):
            return
        camp.status = SmsCampaignStatus.SENDING
        msgs = (await db.execute(
            select(SmsMessage.id, SmsMessage.recipient_phone)
            .where(SmsMessage.campaign_id == campaign_id,
                   SmsMessage.status == SmsMessageStatus.QUEUED)
        )).all()
        body = camp.body
        sender_id = camp.sender_id or settings.AT_SENDER_ID
        user_id = camp.user_id
        await db.commit()

    if not msgs:
        await _finalize(campaign_id)
        return

    provider = get_provider()
    chunk_size = settings.SMS_DISPATCH_CHUNK_SIZE

    for chunk in _chunks(msgs, chunk_size):
        phones = [m.recipient_phone for m in chunk]
        # 2) provider call — NO DB session open here
        try:
            results = await provider.send_bulk(phones, body, sender_id)
        except Exception as e:
            logger.error("Provider send failed for campaign %s: %s", campaign_id, e)
            results = []
        by_phone = {r.recipient: r for r in results}

        # 3) persist results + count failures (short session)
        failed_credits = 0
        async with async_session() as db:
            for m in chunk:
                row = await db.get(SmsMessage, m.id)
                res = by_phone.get(m.recipient_phone)
                if res is not None and res.success:
                    row.status = SmsMessageStatus.SENT
                    row.provider_message_id = res.provider_message_id
                    row.provider = provider.name
                else:
                    row.status = SmsMessageStatus.FAILED
                    row.error = (res.error if res else "no_response")[:255]
                    failed_credits += row.credits_charged
            await db.commit()

        # 4) refund failures in their own short transaction
        if failed_credits:
            async with async_session() as db:
                await sms_credits.refund(db, user_id, failed_credits,
                                         reference=f"campaign:{campaign_id}",
                                         note="failed recipients")
                camp = await db.get(SmsCampaign, campaign_id)
                camp.refunded_credits += failed_credits
                await db.commit()

    await _finalize(campaign_id)


async def _finalize(campaign_id: int) -> None:
    async with async_session() as db:
        camp = await db.get(SmsCampaign, campaign_id)
        if camp is None:
            return
        counts = (await db.execute(
            select(SmsMessage.status).where(SmsMessage.campaign_id == campaign_id)
        )).scalars().all()
        sent = sum(1 for s in counts if s == SmsMessageStatus.SENT)
        failed = sum(1 for s in counts if s == SmsMessageStatus.FAILED)
        camp.sent_count = sent
        camp.failed_count = failed
        if failed == 0:
            camp.status = SmsCampaignStatus.COMPLETED
        elif sent == 0:
            camp.status = SmsCampaignStatus.FAILED
        else:
            camp.status = SmsCampaignStatus.PARTIAL
        await db.commit()


async def prune_old_messages() -> int:
    """Retention: delete sent/delivered rows past the window. Returns count.

    Load-sheds under DB pool pressure; deletes in bounded batches.
    """
    from app.db.database import db_pool_snapshot
    level = db_pool_snapshot().get("pressure", {}).get("level", "healthy")
    if level in ("warning", "critical"):
        logger.info("Skip SMS retention prune (pool pressure: %s)", level)
        return 0

    async with async_session() as db:
        settings_row = await db.get(MessagingSettings, 1)
        days = settings_row.message_retention_days if settings_row else 60
    cutoff = datetime.utcnow() - timedelta(days=days)

    total = 0
    while True:
        async with async_session() as db:
            ids = (await db.execute(
                select(SmsMessage.id).where(
                    SmsMessage.status.in_([SmsMessageStatus.SENT,
                                           SmsMessageStatus.DELIVERED]),
                    SmsMessage.created_at < cutoff,
                ).limit(500)
            )).scalars().all()
            if not ids:
                break
            await db.execute(delete(SmsMessage).where(SmsMessage.id.in_(ids)))
            await db.commit()
            total += len(ids)
    if total:
        logger.info("SMS retention: pruned %s old message rows", total)
    return total
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_messaging_dispatch.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add app/services/sms_dispatch.py tests/test_messaging_dispatch.py
git commit -m "feat(messaging): recipient resolution + background dispatch + retention"
```

---

## Phase 4 — Reseller API

### Task 8: Reseller messaging routes (credits, send, recipients, templates, campaigns, inbox)

**Files:**
- Create: `app/api/messaging_routes.py`
- Modify: `main.py` (import + `include_router`)
- Test: `tests/test_messaging_routes.py`

- [ ] **Step 1: Implement `app/api/messaging_routes.py`** (reseller-scoped; mirrors `subscription_routes` auth + M-Pesa pattern)

```python
# app/api/messaging_routes.py
import logging
import math
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db.database import get_db
from app.db.models import (
    User, UserRole,
    MessagingSettings, MessageTemplate,
    SmsCreditOrder, SmsCreditOrderStatus, SmsCreditTxnKind,
    SmsCampaign, SmsCampaignStatus, SmsMessage, SmsMessageStatus, SmsMessageKind,
    ResellerInboxMessage,
)
from app.services.auth import verify_token, get_current_user
from app.services import sms_credits, sms_dispatch
from app.services.messaging import count_segments
from app.services.mpesa import initiate_stk_push_direct

logger = logging.getLogger(__name__)
router = APIRouter(tags=["messaging"])


async def _require_reseller(token: str, db: AsyncSession) -> User:
    user = await get_current_user(token, db)
    if user.role != UserRole.RESELLER:
        raise HTTPException(status_code=403, detail="Resellers only")
    return user


async def _get_settings(db: AsyncSession) -> MessagingSettings:
    s = await db.get(MessagingSettings, 1)
    if s is None:                       # safety if migration seed missed
        s = MessagingSettings(id=1)
        db.add(s)
        await db.flush()
    return s


# ---- Credits --------------------------------------------------------------

@router.get("/api/messaging/credits")
async def get_credits(db: AsyncSession = Depends(get_db),
                      token: str = Depends(verify_token)):
    user = await _require_reseller(token, db)
    acct = await sms_credits.get_or_create_account(db, user.id)
    s = await _get_settings(db)
    return {
        "balance": acct.balance,
        "total_purchased": acct.total_purchased,
        "total_spent": acct.total_spent,
        "price_per_sms_kes": float(s.price_per_sms_kes),
        "min_purchase_credits": s.min_purchase_credits,
        "bundles": s.bundles or [],
        "enabled": s.enabled,
    }


class PurchaseRequest(BaseModel):
    quantity: int = Field(..., ge=1)
    phone_number: str


@router.post("/api/messaging/credits/purchase")
async def purchase_credits(req: PurchaseRequest,
                           db: AsyncSession = Depends(get_db),
                           token: str = Depends(verify_token)):
    user = await _require_reseller(token, db)
    s = await _get_settings(db)
    if not s.enabled:
        raise HTTPException(status_code=400, detail="Messaging is disabled")
    if req.quantity < s.min_purchase_credits:
        raise HTTPException(status_code=400,
                            detail=f"Minimum purchase is {s.min_purchase_credits} credits")
    unit_price = float(s.price_per_sms_kes)
    amount = math.ceil(req.quantity * unit_price)
    if amount < 1:
        raise HTTPException(status_code=400, detail="Computed amount too small")

    phone = req.phone_number.strip()
    if phone.startswith("0"):
        phone = "254" + phone[1:]
    elif phone.startswith("+"):
        phone = phone[1:]

    order = SmsCreditOrder(user_id=user.id, quantity=req.quantity,
                           unit_price=s.price_per_sms_kes, amount=amount,
                           phone_number=phone, status=SmsCreditOrderStatus.PENDING)
    db.add(order)
    await db.flush()

    callback_url = settings.MPESA_CALLBACK_URL.rstrip("/")
    if "/api/mpesa/callback" in callback_url:
        callback_url = callback_url.replace("/api/mpesa/callback",
                                            "/api/messaging/credits/mpesa/callback")
    else:
        callback_url = callback_url + "/api/messaging/credits/mpesa/callback"

    try:
        stk = await initiate_stk_push_direct(
            phone_number=phone, amount=amount, reference=f"SMS-{order.id}",
            callback_url=callback_url, account_reference="SMS Credits",
        )
    except Exception as e:
        order.status = SmsCreditOrderStatus.FAILED
        await db.commit()
        raise HTTPException(status_code=502, detail=f"STK push failed: {e}")

    if stk:
        order.mpesa_checkout_request_id = stk.checkout_request_id
        order.mpesa_merchant_request_id = stk.merchant_request_id
    await db.commit()
    return {
        "message": "STK push sent. Confirm on your phone.",
        "order_id": order.id,
        "quantity": order.quantity,
        "amount": amount,
        "checkout_request_id": stk.checkout_request_id if stk else None,
    }


@router.post("/api/messaging/credits/mpesa/callback")
async def credits_callback(request: "Request", db: AsyncSession = Depends(get_db)):  # noqa: F821
    from fastapi import Request  # local import to keep signature simple
    body = await request.json()
    cb = body.get("Body", {}).get("stkCallback", {})
    checkout_id = cb.get("CheckoutRequestID")
    result_code = cb.get("ResultCode")
    if not checkout_id:
        return {"ResultCode": 0, "ResultDesc": "Accepted"}

    order = (await db.execute(
        select(SmsCreditOrder).where(
            SmsCreditOrder.mpesa_checkout_request_id == checkout_id)
    )).scalar_one_or_none()
    if not order or order.status != SmsCreditOrderStatus.PENDING:
        return {"ResultCode": 0, "ResultDesc": "Accepted"}

    if result_code == 0:
        receipt = None
        for item in cb.get("CallbackMetadata", {}).get("Item", []):
            if item.get("Name") == "MpesaReceiptNumber":
                receipt = item.get("Value")
        order.status = SmsCreditOrderStatus.COMPLETED
        order.payment_reference = receipt
        await sms_credits.grant(db, order.user_id, order.quantity,
                                SmsCreditTxnKind.PURCHASE,
                                reference=f"SMS-{order.id}")
        logger.info("SMS credits granted: order %s, qty %s", order.id, order.quantity)
    else:
        order.status = SmsCreditOrderStatus.FAILED
    await db.commit()
    return {"ResultCode": 0, "ResultDesc": "Accepted"}


# ---- Recipients + send ----------------------------------------------------

@router.get("/api/messaging/recipients")
async def list_recipients(filter: str = Query("all"),
                          plan_id: Optional[int] = None,
                          db: AsyncSession = Depends(get_db),
                          token: str = Depends(verify_token)):
    user = await _require_reseller(token, db)
    recips = await sms_dispatch.resolve_recipients(db, user.id, filter=filter,
                                                   plan_id=plan_id)
    return {"count": len(recips), "recipients": recips}


class SendRequest(BaseModel):
    body: str = Field(..., min_length=1, max_length=1000)
    filter: str = "all"
    plan_id: Optional[int] = None
    customer_ids: Optional[list[int]] = None
    template_id: Optional[int] = None


@router.post("/api/messaging/send")
async def send_messages(req: SendRequest, background: BackgroundTasks,
                        db: AsyncSession = Depends(get_db),
                        token: str = Depends(verify_token)):
    user = await _require_reseller(token, db)
    s = await _get_settings(db)
    if not s.enabled:
        raise HTTPException(status_code=400, detail="Messaging is disabled")

    recips = await sms_dispatch.resolve_recipients(
        db, user.id, filter=req.filter, plan_id=req.plan_id,
        customer_ids=req.customer_ids)
    if not recips:
        raise HTTPException(status_code=400, detail="No recipients matched")

    segments = count_segments(req.body)
    total = segments * len(recips)
    acct = await sms_credits.get_or_create_account(db, user.id)
    if acct.balance < total:
        raise HTTPException(status_code=400, detail={
            "message": "Insufficient SMS credits",
            "required": total, "balance": acct.balance,
            "shortfall": total - acct.balance,
        })

    await sms_credits.try_deduct(db, user.id, total, reference="campaign:pending")
    sender_id = s.sender_id or settings.AT_SENDER_ID
    camp = SmsCampaign(user_id=user.id, body=req.body, recipient_count=len(recips),
                       segments_per_message=segments, total_credits=total,
                       sender_id=sender_id, status=SmsCampaignStatus.QUEUED)
    db.add(camp)
    await db.flush()
    for r in recips:
        db.add(SmsMessage(campaign_id=camp.id, user_id=user.id,
                          customer_id=r["customer_id"], recipient_phone=r["phone"],
                          body=req.body, segments=segments, credits_charged=segments,
                          kind=SmsMessageKind.RESELLER_TO_CUSTOMER,
                          status=SmsMessageStatus.QUEUED))
    await db.commit()
    campaign_id = camp.id

    # Dispatch AFTER the request transaction commits (no session held across I/O).
    background.add_task(sms_dispatch.dispatch_campaign, campaign_id)
    return {"message": "Send queued", "campaign_id": campaign_id,
            "recipient_count": len(recips), "segments": segments,
            "credits_reserved": total}


# ---- Templates ------------------------------------------------------------

class TemplateIn(BaseModel):
    name: str = Field(..., max_length=120)
    body: str = Field(..., max_length=1000)


@router.get("/api/messaging/templates")
async def list_templates(db: AsyncSession = Depends(get_db),
                         token: str = Depends(verify_token)):
    user = await _require_reseller(token, db)
    rows = (await db.execute(
        select(MessageTemplate).where(MessageTemplate.user_id == user.id)
        .order_by(MessageTemplate.created_at.desc())
    )).scalars().all()
    return {"templates": [{"id": t.id, "name": t.name, "body": t.body} for t in rows]}


@router.post("/api/messaging/templates")
async def create_template(t: TemplateIn, db: AsyncSession = Depends(get_db),
                          token: str = Depends(verify_token)):
    user = await _require_reseller(token, db)
    tpl = MessageTemplate(user_id=user.id, name=t.name, body=t.body)
    db.add(tpl)
    await db.commit()
    await db.refresh(tpl)
    return {"id": tpl.id, "name": tpl.name, "body": tpl.body}


@router.delete("/api/messaging/templates/{template_id}")
async def delete_template(template_id: int, db: AsyncSession = Depends(get_db),
                          token: str = Depends(verify_token)):
    user = await _require_reseller(token, db)
    tpl = (await db.execute(
        select(MessageTemplate).where(MessageTemplate.id == template_id,
                                      MessageTemplate.user_id == user.id)
    )).scalar_one_or_none()
    if not tpl:
        raise HTTPException(status_code=404, detail="Template not found")
    await db.delete(tpl)
    await db.commit()
    return {"deleted": template_id}


# ---- Campaign history -----------------------------------------------------

@router.get("/api/messaging/campaigns")
async def list_campaigns(db: AsyncSession = Depends(get_db),
                         token: str = Depends(verify_token)):
    user = await _require_reseller(token, db)
    rows = (await db.execute(
        select(SmsCampaign).where(SmsCampaign.user_id == user.id)
        .order_by(SmsCampaign.created_at.desc()).limit(100)
    )).scalars().all()
    return {"campaigns": [{
        "id": c.id, "body": c.body, "recipient_count": c.recipient_count,
        "segments_per_message": c.segments_per_message, "total_credits": c.total_credits,
        "sent_count": c.sent_count, "failed_count": c.failed_count,
        "refunded_credits": c.refunded_credits,
        "status": c.status.value if hasattr(c.status, "value") else c.status,
        "created_at": c.created_at.isoformat() if c.created_at else None,
    } for c in rows]}


@router.get("/api/messaging/campaigns/{campaign_id}")
async def campaign_detail(campaign_id: int, db: AsyncSession = Depends(get_db),
                          token: str = Depends(verify_token)):
    user = await _require_reseller(token, db)
    camp = (await db.execute(
        select(SmsCampaign).where(SmsCampaign.id == campaign_id,
                                  SmsCampaign.user_id == user.id)
    )).scalar_one_or_none()
    if not camp:
        raise HTTPException(status_code=404, detail="Campaign not found")
    msgs = (await db.execute(
        select(SmsMessage).where(SmsMessage.campaign_id == campaign_id).limit(2000)
    )).scalars().all()
    return {
        "id": camp.id, "status": camp.status.value if hasattr(camp.status, "value") else camp.status,
        "messages": [{
            "phone": m.recipient_phone,
            "status": m.status.value if hasattr(m.status, "value") else m.status,
            "error": m.error,
        } for m in msgs],
    }


# ---- Inbox (admin -> reseller) --------------------------------------------

@router.get("/api/messaging/inbox")
async def get_inbox(db: AsyncSession = Depends(get_db),
                    token: str = Depends(verify_token)):
    user = await _require_reseller(token, db)
    rows = (await db.execute(
        select(ResellerInboxMessage)
        .where(ResellerInboxMessage.recipient_user_id == user.id)
        .order_by(ResellerInboxMessage.created_at.desc()).limit(100)
    )).scalars().all()
    unread = (await db.execute(
        select(func.count(ResellerInboxMessage.id)).where(
            ResellerInboxMessage.recipient_user_id == user.id,
            ResellerInboxMessage.is_read == False)  # noqa: E712
    )).scalar() or 0
    return {"unread": unread, "messages": [{
        "id": m.id, "subject": m.subject, "body": m.body, "is_read": m.is_read,
        "created_at": m.created_at.isoformat() if m.created_at else None,
    } for m in rows]}


@router.post("/api/messaging/inbox/{message_id}/read")
async def mark_read(message_id: int, db: AsyncSession = Depends(get_db),
                    token: str = Depends(verify_token)):
    from datetime import datetime
    user = await _require_reseller(token, db)
    msg = (await db.execute(
        select(ResellerInboxMessage).where(
            ResellerInboxMessage.id == message_id,
            ResellerInboxMessage.recipient_user_id == user.id)
    )).scalar_one_or_none()
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")
    msg.is_read = True
    msg.read_at = datetime.utcnow()
    await db.commit()
    return {"id": message_id, "is_read": True}
```

> **Fix the callback signature before running:** move `from fastapi import Request`
> to the top imports and change the handler to
> `async def credits_callback(request: Request, db: AsyncSession = Depends(get_db)):`.
> (Shown inline above only to keep the import list compact.)

- [ ] **Step 2: Register the router in `main.py`** — add an import near the other `from app.api...` lines and an `include_router` near the others:

```python
from app.api.messaging_routes import router as messaging_router
# ...
app.include_router(messaging_router)
```

- [ ] **Step 3: Write the route tests**

```python
# tests/test_messaging_routes.py
import pytest
from httpx import AsyncClient, ASGITransport

import app.api.messaging_routes as mr
from app.db.models import SmsCreditOrder, SmsCreditOrderStatus
from app.services import sms_credits
from tests.factories import make_reseller, make_plan, make_customer, make_sms_account


def _client(monkeypatch, db, user):
    """Build an AsyncClient bound to the FastAPI app with auth + db overridden."""
    from main import app
    from app.db.database import get_db
    from app.services.auth import verify_token, get_current_user

    async def _fake_get_db():
        yield db
    app.dependency_overrides[get_db] = _fake_get_db
    app.dependency_overrides[verify_token] = lambda: "tok"
    monkeypatch.setattr(mr, "get_current_user", lambda token, d: _return(user))
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://t")


async def _return(v):
    return v


@pytest.mark.asyncio
async def test_purchase_creates_order_and_calls_stk(db, monkeypatch):
    r = await make_reseller(db)

    class _Stk:
        checkout_request_id = "ws_CO_1"
        merchant_request_id = "mr_1"
    async def _fake_stk(**kwargs):
        assert kwargs["amount"] == 50      # 50 credits * 1.0 default price
        return _Stk()
    monkeypatch.setattr(mr, "initiate_stk_push_direct", _fake_stk)

    async with _client(monkeypatch, db, r) as c:
        resp = await c.post("/api/messaging/credits/purchase",
                            json={"quantity": 50, "phone_number": "0712345678"})
    assert resp.status_code == 200
    assert resp.json()["checkout_request_id"] == "ws_CO_1"


@pytest.mark.asyncio
async def test_callback_grants_credits(db, monkeypatch):
    r = await make_reseller(db)
    order = SmsCreditOrder(user_id=r.id, quantity=50, unit_price=1, amount=50,
                           phone_number="254712345678",
                           status=SmsCreditOrderStatus.PENDING,
                           mpesa_checkout_request_id="ws_CO_2")
    db.add(order)
    await db.commit()

    async with _client(monkeypatch, db, r) as c:
        resp = await c.post("/api/messaging/credits/mpesa/callback", json={
            "Body": {"stkCallback": {"CheckoutRequestID": "ws_CO_2", "ResultCode": 0,
                     "CallbackMetadata": {"Item": [
                         {"Name": "MpesaReceiptNumber", "Value": "QABC123"}]}}}})
    assert resp.status_code == 200
    acct = await sms_credits.get_or_create_account(db, r.id)
    assert acct.balance == 50


@pytest.mark.asyncio
async def test_send_rejects_when_insufficient_credits(db, monkeypatch):
    r = await make_reseller(db)
    p = await make_plan(db, r)
    await make_customer(db, r, p, phone="254700000001")
    await make_sms_account(db, r, balance=0)
    async with _client(monkeypatch, db, r) as c:
        resp = await c.post("/api/messaging/send",
                            json={"body": "Hi", "filter": "all"})
    assert resp.status_code == 400
```

> Note: if the `dependency_overrides` + `get_current_user` monkeypatch proves
> awkward with the existing auth, follow the pattern used in
> `tests/test_c2b_routes.py` / `tests/test_register_and_pay_dup_guard.py`
> (whichever the repo already uses for authed-route tests) and mirror it.

- [ ] **Step 4: Run the tests**

Run: `python -m pytest tests/test_messaging_routes.py -q`
Expected: PASS (fix the `Request` import per the note in Step 1 first).

- [ ] **Step 5: Commit**

```bash
git add app/api/messaging_routes.py main.py tests/test_messaging_routes.py
git commit -m "feat(messaging): reseller routes (credits, send, templates, campaigns, inbox)"
```

---

## Phase 5 — Admin API

### Task 9: Admin messaging routes (settings, orders, credit adjust, inbox send)

**Files:**
- Create: `app/api/admin_messaging_routes.py`
- Modify: `main.py` (import + include_router)
- Test: `tests/test_admin_messaging_routes.py`

- [ ] **Step 1: Implement `app/api/admin_messaging_routes.py`**

```python
# app/api/admin_messaging_routes.py
import logging
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db.database import get_db, async_session
from app.db.models import (
    User, UserRole, MessagingSettings, SmsCreditOrder, ResellerInboxMessage,
)
from app.services.auth import verify_token, get_current_user
from app.services import sms_credits
from app.services.messaging import get_provider

logger = logging.getLogger(__name__)
router = APIRouter(tags=["admin-messaging"])


async def _require_admin(token: str, db: AsyncSession) -> User:
    user = await get_current_user(token, db)
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


class SettingsIn(BaseModel):
    price_per_sms_kes: Optional[float] = None
    min_purchase_credits: Optional[int] = None
    sender_id: Optional[str] = None
    enabled: Optional[bool] = None
    message_retention_days: Optional[int] = None
    bundles: Optional[list] = None


@router.get("/api/admin/messaging/settings")
async def get_settings(db: AsyncSession = Depends(get_db),
                       token: str = Depends(verify_token)):
    await _require_admin(token, db)
    s = await db.get(MessagingSettings, 1) or MessagingSettings(id=1)
    return {
        "price_per_sms_kes": float(s.price_per_sms_kes),
        "min_purchase_credits": s.min_purchase_credits,
        "sender_id": s.sender_id,
        "enabled": s.enabled,
        "message_retention_days": s.message_retention_days,
        "bundles": s.bundles or [],
    }


@router.put("/api/admin/messaging/settings")
async def update_settings(body: SettingsIn, db: AsyncSession = Depends(get_db),
                          token: str = Depends(verify_token)):
    await _require_admin(token, db)
    s = await db.get(MessagingSettings, 1)
    if s is None:
        s = MessagingSettings(id=1)
        db.add(s)
    if body.price_per_sms_kes is not None:
        s.price_per_sms_kes = body.price_per_sms_kes
    if body.min_purchase_credits is not None:
        s.min_purchase_credits = body.min_purchase_credits
    if body.sender_id is not None:
        s.sender_id = body.sender_id or None
    if body.enabled is not None:
        s.enabled = body.enabled
    if body.message_retention_days is not None:
        s.message_retention_days = body.message_retention_days
    if body.bundles is not None:
        s.bundles = body.bundles
    await db.commit()
    return {"message": "Settings updated"}


@router.get("/api/admin/messaging/credits/orders")
async def list_orders(db: AsyncSession = Depends(get_db),
                      token: str = Depends(verify_token)):
    await _require_admin(token, db)
    rows = (await db.execute(
        select(SmsCreditOrder).order_by(SmsCreditOrder.created_at.desc()).limit(200)
    )).scalars().all()
    return {"orders": [{
        "id": o.id, "user_id": o.user_id, "quantity": o.quantity,
        "amount": o.amount, "status": o.status.value if hasattr(o.status, "value") else o.status,
        "payment_reference": o.payment_reference,
        "created_at": o.created_at.isoformat() if o.created_at else None,
    } for o in rows]}


class AdjustIn(BaseModel):
    delta: int
    note: Optional[str] = None


@router.post("/api/admin/messaging/resellers/{reseller_id}/credits/adjust")
async def adjust_credits(reseller_id: int, body: AdjustIn,
                         db: AsyncSession = Depends(get_db),
                         token: str = Depends(verify_token)):
    await _require_admin(token, db)
    reseller = (await db.execute(
        select(User).where(User.id == reseller_id, User.role == UserRole.RESELLER)
    )).scalar_one_or_none()
    if not reseller:
        raise HTTPException(status_code=404, detail="Reseller not found")
    new_balance = await sms_credits.adjust(db, reseller_id, body.delta, note=body.note)
    await db.commit()
    return {"reseller_id": reseller_id, "balance": new_balance}


class InboxSendIn(BaseModel):
    recipient: str = Field(..., description='reseller id (as string) or "all"')
    subject: Optional[str] = None
    body: str = Field(..., min_length=1, max_length=2000)
    also_sms: bool = False


@router.post("/api/admin/messaging/inbox")
async def send_inbox(req: InboxSendIn, background: BackgroundTasks,
                     db: AsyncSession = Depends(get_db),
                     token: str = Depends(verify_token)):
    admin = await _require_admin(token, db)
    if req.recipient == "all":
        resellers = (await db.execute(
            select(User).where(User.role == UserRole.RESELLER)
        )).scalars().all()
    else:
        try:
            rid = int(req.recipient)
        except ValueError:
            raise HTTPException(status_code=400, detail="recipient must be id or 'all'")
        resellers = (await db.execute(
            select(User).where(User.id == rid, User.role == UserRole.RESELLER)
        )).scalars().all()
        if not resellers:
            raise HTTPException(status_code=404, detail="Reseller not found")

    broadcast_id = str(uuid.uuid4()) if req.recipient == "all" else None
    targets = []
    for r in resellers:
        db.add(ResellerInboxMessage(
            recipient_user_id=r.id, sender_user_id=admin.id, subject=req.subject,
            body=req.body, sent_sms=req.also_sms, broadcast_id=broadcast_id))
        if req.also_sms and r.support_phone:
            targets.append(r.support_phone)
    await db.commit()

    if req.also_sms and targets:
        body = req.body
        sender_id = settings.AT_SENDER_ID
        background.add_task(_send_admin_sms, targets, body, sender_id)

    return {"message": "Inbox message sent", "recipients": len(resellers)}


async def _send_admin_sms(phones: list[str], body: str, sender_id: str):
    """Admin->reseller SMS. Platform cost, no reseller credit deduction.
    No DB session held across the provider call (none needed here)."""
    try:
        provider = get_provider()
        await provider.send_bulk(phones, body, sender_id)
    except Exception as e:
        logger.error("Admin SMS send failed: %s", e)
```

- [ ] **Step 2: Register the router in `main.py`**

```python
from app.api.admin_messaging_routes import router as admin_messaging_router
# ...
app.include_router(admin_messaging_router)
```

- [ ] **Step 3: Write tests**

```python
# tests/test_admin_messaging_routes.py
import pytest
from httpx import AsyncClient, ASGITransport

import app.api.admin_messaging_routes as amr
from app.db.models import MessagingSettings
from app.services import sms_credits
from tests.factories import make_reseller


def _client(monkeypatch, db, user):
    from main import app
    from app.db.database import get_db
    from app.services.auth import verify_token

    async def _fake_get_db():
        yield db
    app.dependency_overrides[get_db] = _fake_get_db
    app.dependency_overrides[verify_token] = lambda: "tok"

    async def _ret(token, d):
        return user
    monkeypatch.setattr(amr, "get_current_user", _ret)
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://t")


@pytest.mark.asyncio
async def test_admin_updates_price(db, monkeypatch):
    admin = await make_reseller(db, role=__import__("app.db.models", fromlist=["UserRole"]).UserRole.ADMIN)
    db.add(MessagingSettings(id=1))
    await db.commit()
    async with _client(monkeypatch, db, admin) as c:
        resp = await c.put("/api/admin/messaging/settings",
                           json={"price_per_sms_kes": 0.8})
    assert resp.status_code == 200
    s = await db.get(MessagingSettings, 1)
    assert float(s.price_per_sms_kes) == 0.8


@pytest.mark.asyncio
async def test_admin_adjust_grants_credits(db, monkeypatch):
    from app.db.models import UserRole
    admin = await make_reseller(db, role=UserRole.ADMIN)
    reseller = await make_reseller(db)
    async with _client(monkeypatch, db, admin) as c:
        resp = await c.post(
            f"/api/admin/messaging/resellers/{reseller.id}/credits/adjust",
            json={"delta": 25, "note": "promo"})
    assert resp.status_code == 200
    acct = await sms_credits.get_or_create_account(db, reseller.id)
    assert acct.balance == 25
```

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/test_admin_messaging_routes.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add app/api/admin_messaging_routes.py main.py tests/test_admin_messaging_routes.py
git commit -m "feat(messaging): admin routes (settings, orders, credit adjust, inbox)"
```

---

## Phase 6 — Retention scheduler job

### Task 10: Wire the retention prune into the scheduler

**Files:**
- Modify: `main.py`

- [ ] **Step 1: Add a scheduler job** next to the other `scheduler.add_job(...)` calls in `startup_event`:

```python
    async def _prune_sms_messages_background():
        from app.services.sms_dispatch import prune_old_messages
        try:
            pruned = await prune_old_messages()
            if pruned:
                logger.info(f"[MESSAGING] Retention pruned {pruned} rows")
        except Exception as e:
            logger.error(f"[MESSAGING] Retention prune failed: {e}")

    scheduler.add_job(
        _prune_sms_messages_background,
        trigger=CronTrigger(hour=3, minute=30),
        id='prune_sms_messages',
        name='Prune old SMS message rows past retention window',
        replace_existing=True,
        max_instances=1,
        misfire_grace_time=900,
    )
```

- [ ] **Step 2: Verify the app imports cleanly**

Run: `python -c "import main; print('app import OK')" 2>&1 | tail -5`
Expected: `app import OK` (no exceptions at import time).

- [ ] **Step 3: Run the full backend test suite for regressions**

Run: `python -m pytest tests/ -q 2>&1 | tail -25`
Expected: all messaging tests PASS; no previously-passing test breaks. Report any pre-existing failures unrelated to this work.

- [ ] **Step 4: Commit**

```bash
git add main.py
git commit -m "feat(messaging): daily SMS retention prune job"
```

---

## Phase 7 — Frontend (`../isp-billing-admin`)

> Work in the sibling repo `../isp-billing-admin`. Follow existing page/component
> conventions (look at `app/settings/subscription/page.tsx` for the M-Pesa STK
> "pay then poll" pattern and `app/admin/subscriptions/page.tsx` for an admin
> table page). Reuse the existing API client wrapper and auth/role context in
> `app/context`. Do NOT invent new design systems — mirror existing pages.

### Task 11: API client + types

**Files:**
- Modify: `app/lib/api.ts`, `app/lib/types.ts` (or `app/lib/api.ts`’s colocated types — match the repo)

- [ ] **Step 1:** Add typed client methods mirroring existing ones for every endpoint:
  - `getSmsCredits()`, `purchaseSmsCredits({quantity, phone_number})`,
    `listRecipients(filter, planId?)`, `sendSms(payload)`,
    `listTemplates()`, `createTemplate(t)`, `deleteTemplate(id)`,
    `listCampaigns()`, `getCampaign(id)`,
    `getInbox()`, `markInboxRead(id)`.
  - Admin: `getMessagingSettings()`, `updateMessagingSettings(body)`,
    `listCreditOrders()`, `adjustResellerCredits(id, {delta, note})`,
    `sendInboxMessage({recipient, subject, body, also_sms})`.
- [ ] **Step 2:** Add TS interfaces: `SmsCreditInfo`, `SmsCampaign`, `SmsTemplate`,
  `InboxMessage`, `MessagingSettings`, `CreditOrder`.
- [ ] **Step 3:** `npx tsc --noEmit` (or the repo's typecheck script) passes.
- [ ] **Step 4: Commit** in the admin repo.

```bash
git add app/lib/api.ts app/lib/types.ts
git commit -m "feat(messaging): admin API client methods + types"
```

### Task 12: Reseller Messaging page

**Files:**
- Create: `app/messaging/page.tsx`
- Modify: nav/sidebar component to add a "Messaging" link (reseller role).

- [ ] **Step 1:** Build a tabbed page (mirror an existing tabbed settings page):
  - **Send tab:** textarea bound to `body`; live counter showing
    `segments = ceil(...)` (reuse the same GSM-7/UCS-2 rule from the backend; a
    small client helper is fine) and `credits = segments × recipientCount`;
    recipient selector (radio: All / By plan (plan dropdown) / Expiring /
    Individual (multi-select of customers)); template picker + "Save as
    template"; a balance chip; Send button → `sendSms(...)` → toast with
    `campaign_id`; disable Send when `credits > balance`.
  - **Credits tab:** balance, price per SMS, bundle buttons + custom quantity →
    `purchaseSmsCredits(...)` → show "Check your phone", then poll
    `getSmsCredits()` every ~4s until balance increases or timeout (mirror the
    subscription pay-then-poll). Purchase history list.
  - **History tab:** `listCampaigns()` table (status, sent/failed, credits,
    refunded, date); row → `getCampaign(id)` modal with per-recipient statuses.
  - **Templates tab:** list + create + delete.
- [ ] **Step 2:** Typecheck + `npm run build` passes.
- [ ] **Step 3: Commit.**

```bash
git add app/messaging/page.tsx <nav file>
git commit -m "feat(messaging): reseller messaging page (send/credits/history/templates)"
```

### Task 13: Reseller inbox bell

**Files:**
- Create: a small `app/components/InboxBell.tsx` (or colocated) used in the reseller layout/nav.

- [ ] **Step 1:** On mount, `getInbox()`; show a bell with the `unread` badge; a
  dropdown/list of messages; clicking one calls `markInboxRead(id)` and updates
  the badge. Poll every ~60s (lightweight).
- [ ] **Step 2:** Typecheck + build passes.
- [ ] **Step 3: Commit.**

```bash
git add app/components/InboxBell.tsx <layout file>
git commit -m "feat(messaging): reseller inbox bell + unread badge"
```

### Task 14: Admin Messaging page

**Files:**
- Create: `app/admin/messaging/page.tsx`
- Modify: admin nav to add the link.

- [ ] **Step 1:** Tabbed admin page:
  - **Settings tab:** form for price per SMS, min purchase, sender ID, enabled
    toggle, retention days, bundle editor (list of `{credits, label}`) →
    `updateMessagingSettings(...)`.
  - **Credit sales tab:** `listCreditOrders()` table (reseller, qty, amount,
    status, receipt, date) + a per-reseller manual adjust control
    (`adjustResellerCredits`).
  - **Message resellers tab:** recipient (one reseller dropdown or "All"),
    subject, body, `also_sms` checkbox → `sendInboxMessage(...)`.
- [ ] **Step 2:** Typecheck + `npm run build` passes.
- [ ] **Step 3: Commit.**

```bash
git add app/admin/messaging/page.tsx <admin nav file>
git commit -m "feat(messaging): admin messaging page (settings/sales/broadcast)"
```

### Task 15: Frontend build verification

- [ ] **Step 1:** From `../isp-billing-admin`: `npm run build`.
  Expected: build succeeds with no type errors.
- [ ] **Step 2:** If a vitest setup exists, add a smoke test for the messaging
  page (renders, segment counter computes). Run the test command. If the test
  framework isn't configured, note that explicitly and skip.

---

## Final verification

- [ ] Backend: `python -m pytest tests/ -q` — all messaging tests pass; no
  regressions. Report any unrelated pre-existing failures.
- [ ] Migration dry-run (if a Postgres instance is reachable):
  `python migrations/create_messaging_tables.py` then re-run it to prove
  idempotency (second run prints success, no errors).
- [ ] App import: `python -c "import main"` succeeds (startup migration function
  is wired but only runs against a live DB).
- [ ] Frontend: `npm run build` in `../isp-billing-admin` succeeds.
- [ ] Manual smoke (optional, needs live AT sandbox + M-Pesa sandbox): admin sets
  price → reseller buys credits (STK) → callback grants → reseller sends to a
  test customer → campaign completes → balance reflects sends/refunds.

---

## Self-Review (completed during planning)

**Spec coverage:** provider abstraction (T2–3), 8 tables + enums (T4), auto-migration script + startup (T5), credit ledger (T6), recipient resolution + background dispatch + refund + retention (T7, T10), reseller credits/send/templates/campaigns/inbox routes (T8), admin settings/orders/adjust/inbox routes (T9), frontend reseller + admin + inbox (T11–15). Sender ID = shared (`settings.AT_SENDER_ID` / settings row). DB discipline: dispatch takes an id and opens its own sessions; provider called with no session held; refunds in own txn; retention load-sheds. ✓

**Placeholders:** none — every backend step has full code. Frontend tasks are
contract-level by design (mirror existing pages); flagged as such.

**Type consistency:** `count_segments`, `get_provider`, `SendResult` fields
(`recipient/success/provider_message_id/status/error/cost`),
`sms_credits.{get_or_create_account,grant,try_deduct,refund,adjust}`,
`sms_dispatch.{resolve_recipients,dispatch_campaign,prune_old_messages}`, and
model/enum names are used consistently across tasks. ✓

**Known follow-ups to confirm during execution:** (1) the authed-route test
helper may need to match the repo's existing pattern (noted in T8/T9);
(2) move `from fastapi import Request` to top-of-file in `messaging_routes.py`
(noted in T8).
