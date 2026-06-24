# Reseller Welcome Message Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Automatically send a reseller a welcome message (in-app inbox + optional SMS) on signup, offering free router-onboarding help with a support phone, editable from admin settings and visible in the admin SMS history.

**Architecture:** Reuse the existing admin→reseller messaging plumbing. On reseller registration, a DB-only service creates a `ResellerInboxMessage` (always) and an optional `SmsMessage(kind=ADMIN_TO_RESELLER, category='reseller_welcome')`; the existing background dispatcher sends the SMS with no DB session held. Welcome text/phone/toggle live in `messaging_settings`, pre-filled with code defaults.

**Tech Stack:** FastAPI, SQLAlchemy (async), Postgres (prod) / in-memory SQLite (tests), pytest-asyncio; Next.js + TypeScript admin frontend (separate repo `isp-billing-admin`).

## Global Constraints

- Backend repo: `isp-billing` worktree `worktree-reseller-welcome-message`. Frontend repo: `isp-billing-admin` in a **separate** worktree — never share one worktree between repos.
- Any backend schema change MUST be wired into the idempotent startup migration in `main.py` (AGENTS.md First Rule), in addition to `app/db/models.py`.
- Database Session Discipline: welcome service does DB-only work and does not commit; provider/network I/O happens only in `sms_dispatch.dispatch_admin_sms_messages` with no DB session held. Registration must never fail because of a messaging error.
- Welcome SMS is free to the reseller (no credit deduction), matching the existing admin→reseller send path.
- SMS category tag value is exactly `reseller_welcome`. Welcome SMS keeps `kind=ADMIN_TO_RESELLER` (no new enum value).
- Tests use the in-memory SQLite harness in `tests/conftest.py` (tables via `Base.metadata.create_all`) and `tests/factories.make_reseller`.
- Run backend tests with `python -m pytest` from the worktree root.

---

### Task 1: DB columns + startup migration

**Files:**
- Modify: `app/db/models.py` (class `MessagingSettings` ~line 1609; class `SmsMessage` ~line 1696)
- Modify: `main.py` (messaging migration block ~lines 1795-1818)
- Test: `tests/test_reseller_welcome.py` (new)

**Interfaces:**
- Produces: `MessagingSettings.welcome_enabled: bool`, `.welcome_subject: str|None`, `.welcome_message_body: str|None`, `.welcome_support_phone: str|None`; `SmsMessage.category: str|None`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_reseller_welcome.py`:

```python
import pytest
from sqlalchemy import select

from app.db.models import MessagingSettings, SmsMessage, SmsMessageKind, SmsMessageStatus


@pytest.mark.asyncio
async def test_new_columns_exist_and_default(db):
    db.add(MessagingSettings(id=1))
    await db.commit()
    s = await db.get(MessagingSettings, 1)
    assert s.welcome_enabled is True
    assert s.welcome_subject is None
    assert s.welcome_message_body is None
    assert s.welcome_support_phone is None

    row = SmsMessage(user_id=1, recipient_phone="254700000000", body="hi",
                     segments=1, credits_charged=1,
                     kind=SmsMessageKind.ADMIN_TO_RESELLER,
                     status=SmsMessageStatus.QUEUED, category="reseller_welcome")
    db.add(row)
    await db.commit()
    got = (await db.execute(select(SmsMessage))).scalars().one()
    assert got.category == "reseller_welcome"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_reseller_welcome.py -q`
Expected: FAIL — `TypeError`/`AttributeError` for unknown `welcome_enabled` / `category`.

- [ ] **Step 3: Add the model columns**

In `app/db/models.py`, in `class MessagingSettings`, after the `bundles` column add:

```python
    welcome_enabled = Column(Boolean, nullable=False, default=True, server_default="true")
    welcome_subject = Column(String(200), nullable=True)
    welcome_message_body = Column(String(2000), nullable=True)
    welcome_support_phone = Column(String(20), nullable=True)
```

In `class SmsMessage`, after the `error` column add:

```python
    category = Column(String(40), nullable=True)
```

- [ ] **Step 4: Wire the idempotent startup migration**

In `main.py`, inside the messaging migration block (right after the existing
`ALTER TABLE messaging_settings ... SET DEFAULT 'talksasa'` statement, before the
`INSERT INTO messaging_settings ... ON CONFLICT` statement), add:

```python
        await conn.execute(text(
            "ALTER TABLE messaging_settings "
            "ADD COLUMN IF NOT EXISTS welcome_enabled BOOLEAN NOT NULL DEFAULT true, "
            "ADD COLUMN IF NOT EXISTS welcome_subject VARCHAR(200) NULL, "
            "ADD COLUMN IF NOT EXISTS welcome_message_body VARCHAR(2000) NULL, "
            "ADD COLUMN IF NOT EXISTS welcome_support_phone VARCHAR(20) NULL"
        ))
        await conn.execute(text(
            "ALTER TABLE sms_messages "
            "ADD COLUMN IF NOT EXISTS category VARCHAR(40) NULL"
        ))
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python -m pytest tests/test_reseller_welcome.py -q`
Expected: PASS (1 test).

- [ ] **Step 6: Commit**

```bash
git add app/db/models.py main.py tests/test_reseller_welcome.py
git commit -m "Add welcome message columns + sms category, with startup migration"
```

---

### Task 2: `reseller_welcome` service

**Files:**
- Create: `app/services/reseller_welcome.py`
- Test: `tests/test_reseller_welcome.py` (extend)

**Interfaces:**
- Consumes: `MessagingSettings`, `ResellerInboxMessage`, `SmsMessage`, `User` (Task 1 columns); `app.services.messaging.count_segments`.
- Produces:
  - `WELCOME_CATEGORY = "reseller_welcome"`, `DEFAULT_WELCOME_SUBJECT`, `DEFAULT_WELCOME_BODY`, `DEFAULT_SUPPORT_PHONE_FALLBACK`
  - `effective_welcome_settings(settings_row) -> dict` keys: `enabled, subject, body, support_phone`
  - `render_welcome_body(body_template, *, org, support_phone) -> str`
  - `async queue_reseller_welcome(db, reseller) -> list[int]` (returns QUEUED SmsMessage ids; does NOT commit)

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_reseller_welcome.py`:

```python
from app.db.models import ResellerInboxMessage, UserRole
from app.services.reseller_welcome import (
    queue_reseller_welcome, render_welcome_body, effective_welcome_settings,
    WELCOME_CATEGORY, DEFAULT_WELCOME_BODY,
)
from tests.factories import make_reseller


@pytest.mark.asyncio
async def test_queue_creates_inbox_and_sms_when_enabled_with_phone(db):
    admin = await make_reseller(db, role=UserRole.ADMIN)
    reseller = await make_reseller(db, support_phone="254700111222",
                                   organization_name="Acme Net")
    db.add(MessagingSettings(id=1, welcome_support_phone="254799000000"))
    await db.commit()

    sms_ids = await queue_reseller_welcome(db, reseller)
    await db.commit()

    inbox = (await db.execute(select(ResellerInboxMessage).where(
        ResellerInboxMessage.recipient_user_id == reseller.id))).scalars().all()
    assert len(inbox) == 1
    assert inbox[0].sender_user_id == admin.id
    assert inbox[0].sent_sms is True

    sms = (await db.execute(select(SmsMessage).where(
        SmsMessage.user_id == reseller.id))).scalars().all()
    assert len(sms) == 1
    assert sms[0].kind == SmsMessageKind.ADMIN_TO_RESELLER
    assert sms[0].category == WELCOME_CATEGORY
    assert sms[0].status == SmsMessageStatus.QUEUED
    assert sms[0].recipient_phone == "254700111222"
    assert "254799000000" in sms[0].body
    assert "Acme Net" in sms[0].body
    assert sms_ids == [sms[0].id]


@pytest.mark.asyncio
async def test_queue_no_phone_creates_inbox_only(db):
    await make_reseller(db, role=UserRole.ADMIN)
    reseller = await make_reseller(db, support_phone=None)
    db.add(MessagingSettings(id=1))
    await db.commit()

    sms_ids = await queue_reseller_welcome(db, reseller)
    await db.commit()

    assert sms_ids == []
    inbox = (await db.execute(select(ResellerInboxMessage).where(
        ResellerInboxMessage.recipient_user_id == reseller.id))).scalars().all()
    assert len(inbox) == 1
    assert inbox[0].sent_sms is False
    assert (await db.execute(select(SmsMessage))).scalars().all() == []


@pytest.mark.asyncio
async def test_queue_disabled_creates_nothing(db):
    await make_reseller(db, role=UserRole.ADMIN)
    reseller = await make_reseller(db, support_phone="254700111222")
    db.add(MessagingSettings(id=1, welcome_enabled=False))
    await db.commit()

    sms_ids = await queue_reseller_welcome(db, reseller)
    await db.commit()

    assert sms_ids == []
    assert (await db.execute(select(ResellerInboxMessage))).scalars().all() == []
    assert (await db.execute(select(SmsMessage))).scalars().all() == []


def test_render_welcome_body_substitutes_placeholders():
    out = render_welcome_body("Hi {org}, call {support_phone}.",
                              org="Acme", support_phone="0712")
    assert out == "Hi Acme, call 0712."


def test_render_welcome_body_handles_missing_phone():
    out = render_welcome_body("Call {support_phone} now.", org="Acme",
                              support_phone=None)
    assert "{support_phone}" not in out
    assert "our support line" in out


def test_effective_welcome_settings_defaults_when_null():
    cfg = effective_welcome_settings(None)
    assert cfg["enabled"] is True
    assert cfg["body"] == DEFAULT_WELCOME_BODY
    assert cfg["support_phone"] is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_reseller_welcome.py -q`
Expected: FAIL — `ModuleNotFoundError: app.services.reseller_welcome`.

- [ ] **Step 3: Implement the service**

Create `app/services/reseller_welcome.py`:

```python
"""Welcome message for newly-registered resellers.

On reseller signup we always create an in-app inbox message and, when the
reseller has a phone number on file, queue a welcome SMS via the existing
admin->reseller dispatch path. All work here is DB-only; the provider send
happens later in sms_dispatch.dispatch_admin_sms_messages with no session held.
"""

import logging
from typing import Optional

from sqlalchemy import select

from app.db.models import (
    MessagingSettings,
    ResellerInboxMessage,
    SmsMessage, SmsMessageKind, SmsMessageStatus,
    User, UserRole,
)
from app.services.messaging import count_segments

logger = logging.getLogger(__name__)

WELCOME_CATEGORY = "reseller_welcome"

DEFAULT_WELCOME_SUBJECT = "Welcome aboard"
DEFAULT_WELCOME_BODY = (
    "Hi {org}, welcome aboard! Your reseller account is ready. Need help adding "
    "your first router? We'll set it up for you for FREE - just call "
    "{support_phone}. Log in any time to get started."
)
DEFAULT_SUPPORT_PHONE_FALLBACK = "our support line"


def effective_welcome_settings(settings_row: Optional[MessagingSettings]) -> dict:
    """Resolve welcome settings, applying code defaults for null/missing fields."""
    enabled = True
    subject = DEFAULT_WELCOME_SUBJECT
    body = DEFAULT_WELCOME_BODY
    support_phone = None
    if settings_row is not None:
        if settings_row.welcome_enabled is not None:
            enabled = settings_row.welcome_enabled
        if settings_row.welcome_subject:
            subject = settings_row.welcome_subject
        if settings_row.welcome_message_body:
            body = settings_row.welcome_message_body
        support_phone = settings_row.welcome_support_phone or None
    return {"enabled": enabled, "subject": subject, "body": body,
            "support_phone": support_phone}


def render_welcome_body(body_template: str, *, org: str,
                        support_phone: Optional[str]) -> str:
    """Substitute {org} and {support_phone}; never leak a literal placeholder."""
    phone = support_phone or DEFAULT_SUPPORT_PHONE_FALLBACK
    out = body_template.replace("{org}", org or "there")
    out = out.replace("{support_phone}", phone)
    return out


async def _resolve_sender_admin_id(db, reseller: User) -> Optional[int]:
    """Pick an admin user id to attribute the inbox message to."""
    if reseller.created_by:
        admin = (await db.execute(
            select(User.id).where(User.id == reseller.created_by,
                                  User.role == UserRole.ADMIN)
        )).scalar_one_or_none()
        if admin is not None:
            return admin
    return (await db.execute(
        select(User.id).where(User.role == UserRole.ADMIN)
        .order_by(User.id).limit(1)
    )).scalar_one_or_none()


async def queue_reseller_welcome(db, reseller: User) -> list[int]:
    """Create welcome inbox + optional SMS rows. DB-only; caller commits.

    Returns ids of QUEUED SmsMessage rows to hand to the dispatcher.
    """
    settings_row = await db.get(MessagingSettings, 1)
    cfg = effective_welcome_settings(settings_row)
    if not cfg["enabled"]:
        return []

    body = render_welcome_body(cfg["body"], org=reseller.organization_name,
                               support_phone=cfg["support_phone"])

    phone = (reseller.support_phone or "").strip()
    messaging_enabled = bool(settings_row.enabled) if settings_row else True
    send_sms = bool(phone) and messaging_enabled

    sender_admin_id = await _resolve_sender_admin_id(db, reseller)
    if sender_admin_id is not None:
        db.add(ResellerInboxMessage(
            recipient_user_id=reseller.id,
            sender_user_id=sender_admin_id,
            subject=cfg["subject"],
            body=body,
            sent_sms=send_sms,
        ))
    else:
        logger.warning(
            "No admin user found; skipping welcome inbox for reseller %s",
            reseller.id)

    sms_ids: list[int] = []
    if send_sms:
        segments = count_segments(body)
        row = SmsMessage(
            user_id=reseller.id,
            recipient_phone=phone,
            body=body,
            segments=segments,
            credits_charged=segments,
            kind=SmsMessageKind.ADMIN_TO_RESELLER,
            category=WELCOME_CATEGORY,
            status=SmsMessageStatus.QUEUED,
        )
        db.add(row)
        await db.flush()
        sms_ids.append(row.id)

    return sms_ids
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_reseller_welcome.py -q`
Expected: PASS (all tests in the file).

- [ ] **Step 5: Commit**

```bash
git add app/services/reseller_welcome.py tests/test_reseller_welcome.py
git commit -m "Add reseller_welcome service (inbox + optional welcome SMS)"
```

---

### Task 3: Registration hook

**Files:**
- Modify: `app/api/auth_routes.py` (imports + `register_user_api`)
- Test: `tests/test_reseller_welcome.py` (extend)

**Interfaces:**
- Consumes: `queue_reseller_welcome` (Task 2), `app.services.sms_dispatch.dispatch_admin_sms_messages`, `app.services.messaging.resolve_sender_id`.
- Produces: reseller signup creates welcome rows and schedules the SMS dispatch background task; never fails registration on messaging error.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_reseller_welcome.py`:

```python
@pytest.mark.asyncio
async def test_registration_triggers_welcome(db, session_factory, monkeypatch):
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient
    from app.api.auth_routes import router as auth_router
    from app.db.database import get_db

    await make_reseller(db, role=UserRole.ADMIN)
    db.add(MessagingSettings(id=1, welcome_support_phone="254799000000"))
    await db.commit()

    application = FastAPI()
    application.include_router(auth_router)

    async def _override_get_db():
        async with session_factory() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise
    application.dependency_overrides[get_db] = _override_get_db

    dispatched = []

    async def _fake_dispatch(message_ids, sender_id):
        dispatched.append((message_ids, sender_id))
    monkeypatch.setattr(
        "app.services.sms_dispatch.dispatch_admin_sms_messages", _fake_dispatch)

    async with AsyncClient(transport=ASGITransport(app=application),
                           base_url="http://test") as client:
        resp = await client.post("/api/users/register", json={
            "email": "newreseller@example.com", "password": "secret123",
            "role": "reseller", "organization_name": "Newbie ISP",
            "support_phone": "254700111222"})
    assert resp.status_code == 200

    sms = (await db.execute(select(SmsMessage).where(
        SmsMessage.category == WELCOME_CATEGORY))).scalars().all()
    assert len(sms) == 1
    assert dispatched and dispatched[0][0] == [sms[0].id]


@pytest.mark.asyncio
async def test_registration_survives_welcome_failure(db, session_factory, monkeypatch):
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient
    from app.api.auth_routes import router as auth_router
    from app.db.database import get_db
    from app.db.models import User

    application = FastAPI()
    application.include_router(auth_router)

    async def _override_get_db():
        async with session_factory() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise
    application.dependency_overrides[get_db] = _override_get_db

    async def _boom(db, reseller):
        raise RuntimeError("boom")
    monkeypatch.setattr(
        "app.services.reseller_welcome.queue_reseller_welcome", _boom)

    async with AsyncClient(transport=ASGITransport(app=application),
                           base_url="http://test") as client:
        resp = await client.post("/api/users/register", json={
            "email": "survivor@example.com", "password": "secret123",
            "role": "reseller", "organization_name": "Survivor ISP",
            "support_phone": "254700111222"})
    assert resp.status_code == 200
    user = (await db.execute(select(User).where(
        User.email == "survivor@example.com"))).scalar_one_or_none()
    assert user is not None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_reseller_welcome.py -k registration -q`
Expected: FAIL — welcome rows/dispatch not created (no hook yet); `_boom` patch unused.

- [ ] **Step 3: Add `BackgroundTasks` import and parameter**

In `app/api/auth_routes.py`, change the FastAPI import line:

```python
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
```

Change the `register_user_api` signature to add the background param:

```python
@router.post("/api/users/register")
async def register_user_api(
    request: UserRegisterRequest,
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
```

- [ ] **Step 4: Add the welcome hook**

In `register_user_api`, inside `if role_enum == UserRole.RESELLER:`, AFTER the
existing lead-link try/except block, add:

```python
            try:
                from app.services.reseller_welcome import queue_reseller_welcome
                from app.services import sms_dispatch
                from app.services.messaging import resolve_sender_id
                from app.db.models import MessagingSettings

                sms_ids = await queue_reseller_welcome(db, user)
                settings_row = await db.get(MessagingSettings, 1)
                sender_id = resolve_sender_id(
                    settings_row.sender_id
                    if settings_row and settings_row.sender_id else None
                )
                await db.commit()
                if sms_ids:
                    background.add_task(
                        sms_dispatch.dispatch_admin_sms_messages,
                        sms_ids, sender_id)
            except Exception as welcome_err:
                logger.warning(
                    f"Reseller welcome message failed (non-fatal): {welcome_err}")
                try:
                    await db.rollback()
                except Exception:
                    pass
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_reseller_welcome.py -q`
Expected: PASS (whole file).

- [ ] **Step 6: Commit**

```bash
git add app/api/auth_routes.py tests/test_reseller_welcome.py
git commit -m "Send reseller welcome message on signup (non-fatal, background SMS)"
```

---

### Task 4: Admin settings API + SMS category filter

**Files:**
- Modify: `app/api/admin_messaging_routes.py` (`SettingsIn`, `get_settings`, `update_settings`, `list_admin_sms`)
- Test: `tests/test_admin_messaging_routes.py` (extend)

**Interfaces:**
- Consumes: `effective_welcome_settings` (Task 2); Task 1 columns.
- Produces: GET settings returns `welcome_enabled/subject/message_body/support_phone` (subject+body never null); PUT persists them (empty string → NULL); `list_admin_sms` returns `category` per message and accepts `?category=`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_admin_messaging_routes.py`:

```python
@pytest.mark.asyncio
async def test_settings_returns_welcome_defaults(db, client, monkeypatch):
    admin = await make_reseller(db, role=UserRole.ADMIN)
    _auth_as(monkeypatch, admin)
    resp = await client.get("/api/admin/messaging/settings")
    body = resp.json()
    assert body["welcome_enabled"] is True
    assert body["welcome_subject"]
    assert body["welcome_message_body"]
    assert "welcome_support_phone" in body


@pytest.mark.asyncio
async def test_settings_update_welcome_fields(db, client, monkeypatch):
    admin = await make_reseller(db, role=UserRole.ADMIN)
    db.add(MessagingSettings(id=1))
    await db.commit()
    _auth_as(monkeypatch, admin)
    resp = await client.put("/api/admin/messaging/settings", json={
        "welcome_enabled": False,
        "welcome_message_body": "Custom welcome for {org}",
        "welcome_support_phone": "254700999888"})
    assert resp.status_code == 200
    s = await db.get(MessagingSettings, 1)
    assert s.welcome_enabled is False
    assert s.welcome_message_body == "Custom welcome for {org}"
    assert s.welcome_support_phone == "254700999888"


@pytest.mark.asyncio
async def test_admin_sms_history_filters_by_category(db, client, monkeypatch):
    admin = await make_reseller(db, role=UserRole.ADMIN)
    r1 = await make_reseller(db, organization_name="Welcome ISP")
    r2 = await make_reseller(db, organization_name="Promo ISP")
    db.add_all([
        SmsMessage(user_id=r1.id, recipient_phone="254700000001", body="Welcome",
                   segments=1, credits_charged=1,
                   kind=SmsMessageKind.ADMIN_TO_RESELLER,
                   status=SmsMessageStatus.SENT, category="reseller_welcome"),
        SmsMessage(user_id=r2.id, recipient_phone="254700000002", body="Promo",
                   segments=1, credits_charged=1,
                   kind=SmsMessageKind.ADMIN_TO_RESELLER,
                   status=SmsMessageStatus.SENT, category=None),
    ])
    await db.commit()
    _auth_as(monkeypatch, admin)
    resp = await client.get("/api/admin/messaging/sms?category=reseller_welcome")
    msgs = resp.json()["messages"]
    assert len(msgs) == 1
    assert msgs[0]["category"] == "reseller_welcome"
    assert msgs[0]["reseller_name"] == "Welcome ISP"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_admin_messaging_routes.py -k "welcome or category" -q`
Expected: FAIL — KeyError on missing welcome fields / `category` not filtered.

- [ ] **Step 3: Extend `SettingsIn`**

In `app/api/admin_messaging_routes.py`, add to `class SettingsIn`:

```python
    welcome_enabled: Optional[bool] = None
    welcome_subject: Optional[str] = None
    welcome_message_body: Optional[str] = None
    welcome_support_phone: Optional[str] = None
```

- [ ] **Step 4: Extend `get_settings` return**

In `get_settings`, replace the `return {...}` with one that appends welcome
fields via the effective resolver:

```python
    from app.services.reseller_welcome import effective_welcome_settings
    cfg = effective_welcome_settings(s)
    return {
        "price_per_sms_kes": float(s.price_per_sms_kes),
        "min_purchase_credits": s.min_purchase_credits,
        "sender_id": s.sender_id,
        "enabled": s.enabled,
        "message_retention_days": s.message_retention_days,
        "bundles": s.bundles or [],
        "welcome_enabled": cfg["enabled"],
        "welcome_subject": cfg["subject"],
        "welcome_message_body": cfg["body"],
        "welcome_support_phone": cfg["support_phone"],
    }
```

- [ ] **Step 5: Extend `update_settings`**

In `update_settings`, before `await db.commit()`, add:

```python
    if body.welcome_enabled is not None:
        s.welcome_enabled = body.welcome_enabled
    if body.welcome_subject is not None:
        s.welcome_subject = body.welcome_subject or None
    if body.welcome_message_body is not None:
        s.welcome_message_body = body.welcome_message_body or None
    if body.welcome_support_phone is not None:
        s.welcome_support_phone = body.welcome_support_phone or None
```

- [ ] **Step 6: Add `category` to `list_admin_sms`**

In `list_admin_sms`, add the query param and filter, and return `category`.
Change the signature to:

```python
@router.get("/api/admin/messaging/sms")
async def list_admin_sms(limit: int = Query(100, ge=1, le=500),
                         category: Optional[str] = Query(None),
                         db: AsyncSession = Depends(get_db),
                         token: str = Depends(verify_token)):
```

Replace the messages query so the filter is applied:

```python
    msg_stmt = (
        select(SmsMessage, User)
        .join(User, SmsMessage.user_id == User.id)
        .where(SmsMessage.kind == kind)
    )
    if category:
        msg_stmt = msg_stmt.where(SmsMessage.category == category)
    rows = (await db.execute(
        msg_stmt.order_by(SmsMessage.created_at.desc()).limit(limit)
    )).all()
```

In the returned per-message dict, add:

```python
            "category": m.category,
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `python -m pytest tests/test_admin_messaging_routes.py -q`
Expected: PASS (existing + new tests).

- [ ] **Step 8: Run the full messaging + welcome suite**

Run: `python -m pytest tests/test_reseller_welcome.py tests/test_admin_messaging_routes.py tests/test_messaging_dispatch.py -q`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add app/api/admin_messaging_routes.py tests/test_admin_messaging_routes.py
git commit -m "Expose welcome settings + SMS category filter in admin messaging API"
```

---

### Task 5: Frontend — welcome settings form (separate `isp-billing-admin` worktree)

**Files (read first, then modify the canonical, non-worktree copies):**
- Modify: `app/messaging/MessagingIsland.tsx` (settings panel)
- Modify: `app/lib/api.ts` (+ `types.ts` if settings types live there)

**Interfaces (backend contract from Task 4):**
- GET `/api/admin/messaging/settings` now also returns: `welcome_enabled: boolean`, `welcome_subject: string`, `welcome_message_body: string`, `welcome_support_phone: string | null`.
- PUT `/api/admin/messaging/settings` accepts those same four optional fields.

- [ ] **Step 1: Set up the frontend worktree**

This is a different repo. Create and enter a SEPARATE worktree for
`isp-billing-admin` (never reuse the backend worktree). From the admin repo root,
branch from local HEAD into `.claude/worktrees/reseller-welcome-message`, then run
`npm install`.

- [ ] **Step 2: Read the current settings panel + API client**

Read `app/messaging/MessagingIsland.tsx` and `app/lib/api.ts` to learn the exact
settings type name, the GET/PUT helper names, and the existing form-field style
(labels, inputs, save handler). Match that style exactly.

- [ ] **Step 3: Extend the settings type + API client**

Add the four `welcome_*` fields to the settings TypeScript type and ensure the
GET/PUT client functions pass them through. Mirror the existing fields' typing
(`welcome_support_phone` is `string | null`).

- [ ] **Step 4: Add the form controls (pre-filled, editable)**

In the settings panel, add: a toggle bound to `welcome_enabled`; a text input for
`welcome_subject`; a `<textarea>` for `welcome_message_body`; a text input for
`welcome_support_phone`. Initialize each from the GET response (defaults arrive
pre-filled from the backend). Add a small helper line listing the available
placeholders: `{org}` and `{support_phone}`. Save through the existing PUT handler.

- [ ] **Step 5: Verify the build**

Run: `npm run build`
Expected: build succeeds with no type errors.

- [ ] **Step 6: Commit (in the frontend worktree)**

```bash
git add app/messaging/MessagingIsland.tsx app/lib/api.ts
git commit -m "Add editable, pre-filled reseller welcome settings to admin messaging"
```

---

### Task 6: Frontend — welcome badge + filter in SMS history

**Files:**
- Modify: `app/messaging/MessagingIsland.tsx` (admin SMS history view)
- Modify: `app/lib/api.ts` (SMS message type + list call)

**Interfaces (backend contract from Task 4):**
- GET `/api/admin/messaging/sms` now returns `category: string | null` per message and accepts `?category=reseller_welcome`.

- [ ] **Step 1: Add `category` to the SMS message type + list call**

In `app/lib/api.ts`, add `category: string | null` to the admin SMS message type,
and allow the list helper to pass an optional `category` query param.

- [ ] **Step 2: Render the "Welcome" badge**

In the SMS history rows in `MessagingIsland.tsx`, when
`message.category === 'reseller_welcome'`, render a small "Welcome" badge next to
the row (reuse the existing badge/status styling).

- [ ] **Step 3: Add the filter control**

Add a filter (chip or dropdown) above the SMS history list with an option to show
only welcome messages; when selected, call the list endpoint with
`?category=reseller_welcome`. Match the existing filter/control styling.

- [ ] **Step 4: Verify the build**

Run: `npm run build`
Expected: build succeeds with no type errors.

- [ ] **Step 5: Commit (in the frontend worktree)**

```bash
git add app/messaging/MessagingIsland.tsx app/lib/api.ts
git commit -m "Show welcome badge + filter in admin SMS history"
```

---

## Self-Review

**Spec coverage:**
- Channels (inbox + SMS) → Task 2 `queue_reseller_welcome`. ✓
- Editable content in DB, pre-filled defaults → Task 1 columns, Task 2 `effective_welcome_settings`, Task 4 GET/PUT, Task 5 form. ✓
- Admin visibility / tag in SMS history → Task 1 `category`, Task 4 filter+field, Task 6 badge/filter. ✓
- Auto-send with master toggle → Task 2 `welcome_enabled` gate, Task 3 hook, Task 4/5 toggle. ✓
- DB session discipline / non-fatal → Task 2 (DB-only, no commit) + Task 3 (try/except, background dispatch). ✓
- Startup migration (First Rule) → Task 1 Step 4. ✓
- Worktrees per repo → Global Constraints + Task 5 Step 1. ✓

**Placeholder scan:** Backend tasks contain complete code. Frontend tasks (Tasks 5–6) intentionally describe changes against files that must be read first (cross-repo, in-progress messaging-rebuild) and give the exact API contract + field names/types — the implementer reads the canonical components and matches their style.

**Type consistency:** `WELCOME_CATEGORY="reseller_welcome"` used consistently; `effective_welcome_settings` keys (`enabled/subject/body/support_phone`) consistent across Tasks 2 and 4; `queue_reseller_welcome(db, reseller) -> list[int]` signature consistent across Tasks 2 and 3.
