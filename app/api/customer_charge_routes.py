"""Owner-entered installation ledger; receipts here never collect or allocate money."""
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.db.database import get_db
from app.db.models import Customer, CustomerCharge
from app.services.auth import get_current_user, verify_token
from app.services.staff_access import current_staff, require_permission
from app.services.subscription import enforce_active_subscription
from app.services import customer_charges

router = APIRouter(prefix="/api/customers", tags=["installation-charges"])
TECHMID_OWNER_ID = 597  # Verified reseller identity; no general rollout in this phase.
Money = Annotated[int, Field(strict=True, gt=0, le=100_000_000)]
Reason = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=500)]
Key = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{16,80}$")]


class ChargeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    idempotency_key: Key
    amount_minor: Money
    description: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]


class SettlementInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    idempotency_key: Key
    kind: Literal["external_payment", "waiver"]
    amount_minor: Money
    reason: Reason
    external_reference: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)] | None = None


class ReversalInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    idempotency_key: Key
    reason: Reason


def can_create(customer) -> bool:
    connection_type = customer.plan.connection_type if customer.plan else None
    return getattr(connection_type, "value", connection_type) in ("pppoe", "static_ip")


async def context(db, token, customer_id, *, write=False):
    user = await get_current_user(token, db)
    if not settings.TECHMID_INSTALLATION_CHARGES_ENABLED or user.id != TECHMID_OWNER_ID or user.role.value != "reseller":
        raise HTTPException(404, "Installation charges are not enabled")
    require_permission("customers.view")
    if write and (current_staff() is not None or token.get("staff_id") is not None):
        raise HTTPException(403, "Only the account owner can change installation charges")
    if write:
        enforce_active_subscription(user)
    stmt = select(Customer).options(selectinload(Customer.plan)).where(Customer.id == customer_id, Customer.user_id == user.id)
    if write:
        stmt = stmt.with_for_update()
    customer = (await db.execute(stmt)).scalar_one_or_none()
    if customer is None:
        raise HTTPException(404, "Customer not found")
    return user, customer


@router.get("/{customer_id}/installation-charges")
async def list_charges(customer_id: int, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0),
                       db: AsyncSession = Depends(get_db), token=Depends(verify_token)):
    user, customer = await context(db, token, customer_id)
    rows = (await db.execute(select(CustomerCharge).where(CustomerCharge.owner_id == user.id,
        CustomerCharge.customer_id == customer.id).order_by(CustomerCharge.id.desc()).offset(offset).limit(limit + 1))).scalars().all()
    return {"charges": [await customer_charges.view(db, c) for c in rows[:limit]], "can_create": can_create(customer),
            "next_offset": offset + limit if len(rows) > limit else None}


@router.post("/{customer_id}/installation-charges", status_code=201)
async def create_charge(customer_id: int, body: ChargeInput, db: AsyncSession = Depends(get_db), token=Depends(verify_token)):
    user, customer = await context(db, token, customer_id, write=True)
    if not can_create(customer):
        raise HTTPException(409, "New installation charges are for PPPoE and static customers")
    return await customer_charges.record(db, owner_id=user.id, customer=customer,
        key=body.idempotency_key, kind="charge", amount_minor=body.amount_minor,
        description=body.description, reason=body.description)


@router.post("/{customer_id}/installation-charges/{charge_id}/events", status_code=201)
async def settle_charge(customer_id: int, charge_id: int, body: SettlementInput,
                        db: AsyncSession = Depends(get_db), token=Depends(verify_token)):
    user, customer = await context(db, token, customer_id, write=True)
    if body.kind == "waiver" and body.external_reference:
        raise HTTPException(422, "A waiver is not an external receipt")
    return await customer_charges.record(db, owner_id=user.id, customer=customer, charge_id=charge_id,
        key=body.idempotency_key, kind=body.kind, amount_minor=body.amount_minor,
        reason=body.reason, external_reference=body.external_reference)


@router.post("/{customer_id}/installation-charges/{charge_id}/events/{event_id}/reversal", status_code=201)
async def reverse_event(customer_id: int, charge_id: int, event_id: int, body: ReversalInput,
                        db: AsyncSession = Depends(get_db), token=Depends(verify_token)):
    user, customer = await context(db, token, customer_id, write=True)
    return await customer_charges.record(db, owner_id=user.id, customer=customer, charge_id=charge_id,
        key=body.idempotency_key, kind="reversal", reason=body.reason, reverses_event_id=event_id)
