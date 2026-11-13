"""Independent, append-only installation debt records. Never allocates service money."""
from __future__ import annotations

import hashlib
import json

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import CustomerCharge, CustomerChargeEvent


def fingerprint(payload: dict) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


async def replay(db: AsyncSession, owner_id: int, key: str, digest: str):
    event = (await db.execute(select(CustomerChargeEvent).where(
        CustomerChargeEvent.owner_id == owner_id,
        CustomerChargeEvent.idempotency_key == key,
    ))).scalar_one_or_none()
    if event and event.request_hash != digest:
        raise HTTPException(409, "This request key was already used for a different action.")
    return event


async def view(db: AsyncSession, charge: CustomerCharge) -> dict:
    events = (await db.execute(select(CustomerChargeEvent).where(
        CustomerChargeEvent.charge_id == charge.id,
    ).order_by(CustomerChargeEvent.id))).scalars().all()
    reversed_ids = {e.reverses_event_id for e in events if e.kind == "reversal"}
    return {
        "id": charge.id, "customer_id": charge.customer_id,
        "customer_id_snapshot": charge.customer_id_snapshot,
        "customer_name": charge.customer_name_snapshot,
        "description": charge.description, "currency": charge.currency,
        "original_minor": charge.original_minor,
        "outstanding_minor": sum(e.delta_minor for e in events),
        "payments_minor": sum(-e.delta_minor for e in events if e.kind == "external_payment" and e.id not in reversed_ids),
        "waivers_minor": sum(-e.delta_minor for e in events if e.kind == "waiver" and e.id not in reversed_ids),
        "reversed": any(e.kind == "charge" and e.id in reversed_ids for e in events),
        "created_at": charge.created_at,
        "events": [{"id": e.id, "kind": e.kind, "delta_minor": e.delta_minor,
                    "reason": e.reason, "external_reference": e.external_reference,
                    "reverses_event_id": e.reverses_event_id,
                    "actor_id": e.actor_id, "created_at": e.created_at,
                    "reversed": e.id in reversed_ids} for e in events],
    }


async def record(db: AsyncSession, *, owner_id: int, customer, key: str,
                 kind: str, amount_minor: int | None = None, description: str = "",
                 reason: str = "", external_reference: str | None = None,
                 charge_id: int | None = None, reverses_event_id: int | None = None) -> dict:
    """Caller locks the customer for creates. Existing charge writes lock that row.

    Commit only our new rows; no customer assignment, payment helper, router,
    provider, SMS or background job belongs in this module.
    """
    digest = fingerprint(dict(customer_id=customer.id, kind=kind, amount_minor=amount_minor,
                              description=description, reason=reason, external_reference=external_reference,
                              charge_id=charge_id, reverses_event_id=reverses_event_id))
    previous = await replay(db, owner_id, key, digest)
    if previous:
        return await view(db, await db.get(CustomerCharge, previous.charge_id))

    if kind == "charge":
        charge = CustomerCharge(owner_id=owner_id, customer_id=customer.id,
                                customer_id_snapshot=customer.id, customer_name_snapshot=(customer.name or "Unnamed customer")[:255],
                                description=description, original_minor=amount_minor)
        db.add(charge)
        await db.flush()
        delta = amount_minor
    else:
        charge = (await db.execute(select(CustomerCharge).where(
            CustomerCharge.id == charge_id, CustomerCharge.owner_id == owner_id,
            CustomerCharge.customer_id == customer.id,
        ).with_for_update())).scalar_one_or_none()
        if charge is None:
            raise HTTPException(404, "Charge not found")
        # The lock waiter must recheck the committed idempotency record.
        previous = await replay(db, owner_id, key, digest)
        if previous:
            return await view(db, charge)
        state = await view(db, charge)
        if kind == "reversal":
            target = next((e for e in state["events"] if e["id"] == reverses_event_id), None)
            if target is None or target["kind"] == "reversal" or target["reversed"]:
                raise HTTPException(409, "Only an unreversed original event can be reversed.")
            delta = -target["delta_minor"]
            if state["outstanding_minor"] + delta < 0:
                raise HTTPException(409, "Reverse the recorded payments and waivers before reversing this charge.")
        else:
            if state["reversed"] or amount_minor > state["outstanding_minor"]:
                raise HTTPException(409, "Amount exceeds the outstanding charge.")
            delta = -amount_minor
    db.add(CustomerChargeEvent(
        charge_id=charge.id, owner_id=owner_id, actor_id=owner_id, kind=kind,
        delta_minor=delta, reason=reason, external_reference=external_reference,
        reverses_event_id=reverses_event_id, idempotency_key=key, request_hash=digest,
    ))
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        previous = await replay(db, owner_id, key, digest)
        if not previous:
            raise HTTPException(409, "This event was already reversed. Refresh the ledger.")
        charge = await db.get(CustomerCharge, previous.charge_id)
    await db.refresh(charge)
    return await view(db, charge)
