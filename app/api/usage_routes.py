"""Customer usage / FUP read endpoints (frontend-facing)."""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.database import get_db
from app.db.models import (
    ConnectionType,
    Customer,
    CustomerUsagePeriod,
    Plan,
    Router,
    UserRole,
)
from app.services import realtime_state
from app.services.auth import verify_token, get_current_user
from app.services.usage_tracking import get_open_period

router = APIRouter(tags=["usage"])


# ------------------------------ Pydantic models ------------------------------


class PeriodOut(BaseModel):
    id: int
    period_start: datetime
    period_end: datetime
    upload_mb: float
    download_mb: float
    total_mb: float
    cap_mb: Optional[int]
    percent_used: Optional[float]
    fup_action: Optional[str]
    fup_triggered_at: Optional[datetime]
    fup_action_taken: Optional[str]
    fup_reverted_at: Optional[datetime]
    fup_active: bool
    closed_at: Optional[datetime]


class LiveOut(BaseModel):
    """Seconds-fresh view of one device, from the real-time push pilot."""

    online: bool
    ip: Optional[str]
    rate_down_bps: Optional[float]
    rate_up_bps: Optional[float]
    seen_at: datetime
    reported_at: datetime
    report_age_seconds: float
    interval_seconds: int
    queue_status: str
    max_limit: Optional[str]


class UsageOut(BaseModel):
    customer_id: int
    connection_type: Optional[str]
    pppoe_username: Optional[str]
    plan_name: Optional[str]
    plan_data_cap_mb: Optional[int]
    plan_fup_action: Optional[str]
    period: Optional[PeriodOut]
    live: Optional[LiveOut] = None


class BulkUsageRequest(BaseModel):
    customer_ids: list[int]


class TopUsageItem(BaseModel):
    customer_id: int
    customer_name: Optional[str]
    connection_type: Optional[str]
    pppoe_username: Optional[str]
    identifier: Optional[str]
    plan_name: Optional[str]
    cap_mb: Optional[int]
    total_mb: float
    percent_used: Optional[float]
    fup_active: bool


# ------------------------------ Helpers ------------------------------


def _bytes_to_mb(b: int) -> float:
    if not b:
        return 0.0
    return round(int(b) / (1024 * 1024), 2)


def _percent(used_bytes: int, cap_mb: Optional[int]) -> Optional[float]:
    if not cap_mb or cap_mb <= 0:
        return None
    cap_bytes = int(cap_mb) * 1024 * 1024
    if cap_bytes <= 0:
        return None
    return round((int(used_bytes) / cap_bytes) * 100, 2)


def _serialize_period(p: CustomerUsagePeriod) -> PeriodOut:
    fup_active = bool(p.fup_triggered_at and not p.fup_reverted_at)
    return PeriodOut(
        id=p.id,
        period_start=p.period_start,
        period_end=p.period_end,
        upload_mb=_bytes_to_mb(p.upload_bytes or 0),
        download_mb=_bytes_to_mb(p.download_bytes or 0),
        total_mb=_bytes_to_mb(p.total_bytes or 0),
        cap_mb=p.cap_mb_snapshot,
        percent_used=_percent(p.total_bytes or 0, p.cap_mb_snapshot),
        fup_action=p.fup_action_snapshot.value if p.fup_action_snapshot else None,
        fup_triggered_at=p.fup_triggered_at,
        fup_action_taken=p.fup_action_taken.value if p.fup_action_taken else None,
        fup_reverted_at=p.fup_reverted_at,
        fup_active=fup_active,
        closed_at=p.closed_at,
    )


def _live_for(customer: Customer) -> Optional[LiveOut]:
    router_live = realtime_state.get_router_live(customer.router_id) if customer.router_id else None
    device = realtime_state.get_device_live(customer.router_id, customer.mac_address)
    if router_live is None or device is None:
        return None
    return LiveOut(
        online=device.online,
        ip=device.ip or None,
        rate_down_bps=device.rate_down_bps,
        rate_up_bps=device.rate_up_bps,
        seen_at=device.seen_at,
        reported_at=router_live.received_at,
        report_age_seconds=round((datetime.utcnow() - router_live.received_at).total_seconds(), 1),
        interval_seconds=router_live.interval_seconds,
        queue_status=device.queue_status,
        max_limit=device.max_limit,
    )


def _serialize_usage(
    customer: Customer,
    open_period: Optional[CustomerUsagePeriod],
) -> UsageOut:
    plan = customer.plan
    return UsageOut(
        customer_id=customer.id,
        connection_type=plan.connection_type.value if (plan and plan.connection_type) else None,
        pppoe_username=customer.pppoe_username,
        plan_name=plan.name if plan else None,
        plan_data_cap_mb=plan.data_cap_mb if plan else None,
        plan_fup_action=plan.fup_action.value if (plan and plan.fup_action) else None,
        period=_serialize_period(open_period) if open_period else None,
        live=_live_for(customer),
    )


async def _load_customer_scoped(
    db: AsyncSession, customer_id: int, user
) -> Customer:
    """Load a customer enforcing reseller scoping (admins see all)."""
    stmt = (
        select(Customer)
        .options(selectinload(Customer.plan))
        .where(Customer.id == customer_id)
    )
    if user.role != UserRole.ADMIN:
        stmt = stmt.where(Customer.user_id == user.id)
    result = await db.execute(stmt)
    customer = result.scalar_one_or_none()
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found or not accessible")
    return customer


# ------------------------------ Endpoints ------------------------------


@router.get("/api/customers/{customer_id}/usage", response_model=UsageOut)
async def get_customer_usage(
    customer_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Current open billing period for the customer + FUP status."""
    user = await get_current_user(token, db)
    customer = await _load_customer_scoped(db, customer_id, user)
    open_period = await get_open_period(db, customer.id)

    return _serialize_usage(customer, open_period)


@router.post("/api/customers/usage/bulk", response_model=list[UsageOut])
async def get_customer_usage_bulk(
    body: BulkUsageRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Current usage for up to 100 customers in one bounded DB round-trip set."""
    if not body.customer_ids:
        raise HTTPException(status_code=400, detail="customer_ids must not be empty")
    if len(body.customer_ids) > 100:
        raise HTTPException(status_code=400, detail="A maximum of 100 customer IDs is allowed")
    if any(customer_id <= 0 for customer_id in body.customer_ids):
        raise HTTPException(status_code=400, detail="customer_ids must contain positive integers")

    requested_ids = list(dict.fromkeys(body.customer_ids))
    user = await get_current_user(token, db)

    customer_stmt = (
        select(Customer)
        .options(selectinload(Customer.plan))
        .where(Customer.id.in_(requested_ids))
    )
    if user.role != UserRole.ADMIN:
        customer_stmt = customer_stmt.where(Customer.user_id == user.id)

    customers = (await db.execute(customer_stmt)).scalars().all()
    customers_by_id = {customer.id: customer for customer in customers}
    accessible_ids = list(customers_by_id)

    periods_by_customer_id: dict[int, CustomerUsagePeriod] = {}
    if accessible_ids:
        periods = (
            await db.execute(
                select(CustomerUsagePeriod)
                .where(
                    CustomerUsagePeriod.customer_id.in_(accessible_ids),
                    CustomerUsagePeriod.closed_at.is_(None),
                )
                .order_by(
                    CustomerUsagePeriod.customer_id,
                    CustomerUsagePeriod.period_start.desc(),
                )
            )
        ).scalars().all()
        for period in periods:
            periods_by_customer_id.setdefault(period.customer_id, period)

    return [
        _serialize_usage(
            customers_by_id[customer_id],
            periods_by_customer_id.get(customer_id),
        )
        for customer_id in requested_ids
        if customer_id in customers_by_id
    ]


@router.get(
    "/api/customers/{customer_id}/usage/history",
    response_model=list[PeriodOut],
)
async def get_customer_usage_history(
    customer_id: int,
    limit: int = Query(6, ge=1, le=60),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Past usage periods (most recent first), capped at ``limit``."""
    user = await get_current_user(token, db)
    customer = await _load_customer_scoped(db, customer_id, user)

    result = await db.execute(
        select(CustomerUsagePeriod)
        .where(CustomerUsagePeriod.customer_id == customer.id)
        .order_by(CustomerUsagePeriod.period_start.desc())
        .limit(limit)
    )
    return [_serialize_period(p) for p in result.scalars().all()]


@router.get(
    "/api/resellers/me/usage/top",
    response_model=list[TopUsageItem],
)
async def get_top_usage_for_reseller(
    limit: int = Query(20, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Top customers by current-period bandwidth (hotspot + PPPoE)."""
    user = await get_current_user(token, db)

    customer_filter = [Plan.connection_type.in_([ConnectionType.HOTSPOT, ConnectionType.PPPOE])]
    if user.role != UserRole.ADMIN:
        customer_filter.append(Customer.user_id == user.id)

    stmt = (
        select(
            Customer.id.label("customer_id"),
            Customer.name.label("customer_name"),
            Customer.mac_address.label("mac_address"),
            Customer.pppoe_username.label("pppoe_username"),
            Plan.connection_type.label("connection_type"),
            Plan.name.label("plan_name"),
            CustomerUsagePeriod.cap_mb_snapshot.label("cap_mb"),
            CustomerUsagePeriod.total_bytes.label("total_bytes"),
            CustomerUsagePeriod.fup_triggered_at.label("fup_triggered_at"),
            CustomerUsagePeriod.fup_reverted_at.label("fup_reverted_at"),
        )
        .join(Plan, Customer.plan_id == Plan.id)
        .join(CustomerUsagePeriod, CustomerUsagePeriod.customer_id == Customer.id)
        .where(
            CustomerUsagePeriod.closed_at.is_(None),
            *customer_filter,
        )
        .order_by(CustomerUsagePeriod.total_bytes.desc())
        .limit(limit)
    )
    rows = (await db.execute(stmt)).all()

    out: list[TopUsageItem] = []
    for r in rows:
        cap_mb = r.cap_mb
        total_bytes = int(r.total_bytes or 0)
        connection_type = (
            r.connection_type.value
            if hasattr(r.connection_type, "value")
            else r.connection_type
        )
        identifier = r.pppoe_username if connection_type == "pppoe" else r.mac_address
        out.append(
            TopUsageItem(
                customer_id=r.customer_id,
                customer_name=r.customer_name,
                connection_type=connection_type,
                pppoe_username=r.pppoe_username,
                identifier=identifier,
                plan_name=r.plan_name,
                cap_mb=cap_mb,
                total_mb=_bytes_to_mb(total_bytes),
                percent_used=_percent(total_bytes, cap_mb),
                fup_active=bool(r.fup_triggered_at and not r.fup_reverted_at),
            )
        )
    return out



# ------------------------------ Router live view ------------------------------


class LiveDeviceOut(BaseModel):
    customer_id: Optional[int]
    customer_name: Optional[str]
    mac: str
    ip: Optional[str]
    online: bool
    rate_down_bps: Optional[float]
    rate_up_bps: Optional[float]
    session_download_bytes: int
    session_upload_bytes: int
    seen_at: datetime
    queue_status: str
    max_limit: Optional[str]


class RouterLiveOut(BaseModel):
    router_id: int
    reported_at: datetime
    report_age_seconds: float
    interval_seconds: int
    pushes_since_restart: int
    cpu_load: Optional[int]
    free_memory: Optional[int]
    total_memory: Optional[int]
    uptime: str
    version: str
    board: str
    wan_rx_bps: Optional[float]
    wan_tx_bps: Optional[float]
    hotspot_active: int
    pppoe_active: int
    queue_count: int
    orphan_queues: int
    shadowed: int
    no_limit: int
    last_repair_at: Optional[datetime]
    last_repair_result: Optional[dict]
    devices: list[LiveDeviceOut]


@router.get("/api/routers/{router_id}/live", response_model=RouterLiveOut)
async def get_router_live(
    router_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Seconds-fresh router and per-device state (real-time push pilot routers).

    Served from memory; 404 when the router is not reporting live.
    """
    user = await get_current_user(token, db)
    stmt = select(Router.id).where(Router.id == router_id)
    if user.role != UserRole.ADMIN:
        stmt = stmt.where(Router.user_id == user.id)
    if (await db.execute(stmt)).scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Router not found or not accessible")

    state = realtime_state.get_router_live(router_id)
    if state is None:
        raise HTTPException(status_code=404, detail="This router is not reporting live data")

    customer_ids = [d.customer_id for d in state.devices.values() if d.customer_id]
    names = {}
    if customer_ids:
        rows = await db.execute(select(Customer.id, Customer.name).where(Customer.id.in_(customer_ids)))
        names = {cid: name for cid, name in rows.all()}

    devices = sorted(
        state.devices.values(),
        key=lambda d: (not d.online, -(d.rate_down_bps or 0), d.mac),
    )
    return RouterLiveOut(
        router_id=router_id,
        reported_at=state.received_at,
        report_age_seconds=round((datetime.utcnow() - state.received_at).total_seconds(), 1),
        interval_seconds=state.interval_seconds,
        pushes_since_restart=state.pushes,
        cpu_load=state.cpu_load,
        free_memory=state.free_memory,
        total_memory=state.total_memory,
        uptime=state.uptime,
        version=state.version,
        board=state.board,
        wan_rx_bps=state.wan_rx_bps,
        wan_tx_bps=state.wan_tx_bps,
        hotspot_active=state.hotspot_active,
        pppoe_active=state.pppoe_active,
        queue_count=state.queue_count,
        orphan_queues=state.orphan_queues,
        shadowed=state.shadowed,
        no_limit=state.no_limit,
        last_repair_at=state.last_repair_at,
        last_repair_result=state.last_repair_result,
        devices=[
            LiveDeviceOut(
                customer_id=d.customer_id,
                customer_name=names.get(d.customer_id),
                mac=d.mac,
                ip=d.ip or None,
                online=d.online,
                rate_down_bps=d.rate_down_bps,
                rate_up_bps=d.rate_up_bps,
                session_download_bytes=d.bytes_out,
                session_upload_bytes=d.bytes_in,
                seen_at=d.seen_at,
                queue_status=d.queue_status,
                max_limit=d.max_limit,
            )
            for d in devices
        ],
    )


@router.get("/api/realtime/routers", response_model=list[int])
async def list_live_router_ids(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Ids of the caller's routers that are reporting live right now."""
    user = await get_current_user(token, db)
    ids = [
        rid for rid in realtime_state.pilot_router_ids()
        if (state := realtime_state.get_router_live(rid)) is not None
        and (datetime.utcnow() - state.received_at).total_seconds() < 300
    ]
    if not ids:
        return []
    stmt = select(Router.id).where(Router.id.in_(ids))
    if user.role != UserRole.ADMIN:
        stmt = stmt.where(Router.user_id == user.id)
    return sorted((await db.execute(stmt)).scalars().all())
