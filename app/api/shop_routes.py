import uuid
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.db.database import get_db
from app.db.models import (
    ShopOrder, ShopOrderItem, ShopOrderPaymentStatus, ShopOrderStatus,
    ShopOrderTracking, ShopProduct, User,
)
from app.services.auth import verify_token, get_current_user
from app.services.mpesa import initiate_stk_push_direct

logger = logging.getLogger(__name__)

router = APIRouter(tags=["shop"])


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class ProductCreateRequest(BaseModel):
    name: str
    description: Optional[str] = None
    price: float
    stock_quantity: int = 0
    image_url: Optional[str] = None
    category: Optional[str] = None
    is_active: bool = True


class ProductUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = None
    stock_quantity: Optional[int] = None
    image_url: Optional[str] = None
    category: Optional[str] = None
    is_active: Optional[bool] = None


class OrderItemRequest(BaseModel):
    product_id: int
    quantity: int


class PlaceOrderRequest(BaseModel):
    buyer_name: str
    buyer_phone: str
    buyer_email: Optional[str] = None
    delivery_address: Optional[str] = None
    items: List[OrderItemRequest]
    notes: Optional[str] = None


class PayOrderRequest(BaseModel):
    phone: str


class UpdateOrderStatusRequest(BaseModel):
    status: str


class AddTrackingRequest(BaseModel):
    status_label: str
    note: Optional[str] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _product_dict(p: ShopProduct) -> dict:
    return {
        "id": p.id,
        "name": p.name,
        "description": p.description,
        "price": float(p.price),
        "stock_quantity": p.stock_quantity,
        "image_url": p.image_url,
        "category": p.category,
        "is_active": p.is_active,
        "created_at": p.created_at.isoformat() if p.created_at else None,
    }


def _tracking_dict(t: ShopOrderTracking) -> dict:
    return {
        "id": t.id,
        "status_label": t.status_label,
        "note": t.note,
        "created_at": t.created_at.isoformat() if t.created_at else None,
    }


def _order_dict(o: ShopOrder, include_items: bool = True) -> dict:
    data = {
        "id": o.id,
        "order_number": o.order_number,
        "buyer_name": o.buyer_name,
        "buyer_phone": o.buyer_phone,
        "buyer_email": o.buyer_email,
        "delivery_address": o.delivery_address,
        "total_amount": float(o.total_amount),
        "status": o.status.value if hasattr(o.status, "value") else o.status,
        "payment_status": o.payment_status.value if hasattr(o.payment_status, "value") else o.payment_status,
        "mpesa_receipt_number": o.mpesa_receipt_number,
        "notes": o.notes,
        "created_at": o.created_at.isoformat() if o.created_at else None,
    }
    if include_items:
        data["items"] = [
            {
                "id": i.id,
                "product_id": i.product_id,
                "product_name": i.product_name,
                "product_price": float(i.product_price),
                "quantity": i.quantity,
                "subtotal": float(i.subtotal),
            }
            for i in (o.items or [])
        ]
        data["tracking_history"] = [_tracking_dict(t) for t in (o.tracking_history or [])]
    return data


def _generate_order_number() -> str:
    return f"ORD{uuid.uuid4().hex[:8].upper()}"


# ---------------------------------------------------------------------------
# Admin: Product management
# ---------------------------------------------------------------------------

@router.post("/api/shop/products")
async def create_product(
    body: ProductCreateRequest,
    token: str = Depends(verify_token),
    db: AsyncSession = Depends(get_db),
):
    user = await get_current_user(token, db)
    product = ShopProduct(
        user_id=user.id,
        name=body.name,
        description=body.description,
        price=Decimal(str(body.price)),
        stock_quantity=body.stock_quantity,
        image_url=body.image_url,
        category=body.category,
        is_active=body.is_active,
    )
    db.add(product)
    await db.commit()
    await db.refresh(product)
    return _product_dict(product)


@router.get("/api/shop/admin/products")
async def list_admin_products(
    token: str = Depends(verify_token),
    db: AsyncSession = Depends(get_db),
):
    user = await get_current_user(token, db)
    result = await db.execute(
        select(ShopProduct)
        .where(ShopProduct.user_id == user.id)
        .order_by(ShopProduct.created_at.desc())
    )
    products = result.scalars().all()
    return [_product_dict(p) for p in products]


@router.put("/api/shop/products/{product_id}")
async def update_product(
    product_id: int,
    body: ProductUpdateRequest,
    token: str = Depends(verify_token),
    db: AsyncSession = Depends(get_db),
):
    user = await get_current_user(token, db)
    result = await db.execute(
        select(ShopProduct).where(
            ShopProduct.id == product_id,
            ShopProduct.user_id == user.id,
        )
    )
    product = result.scalar_one_or_none()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    if body.name is not None:
        product.name = body.name
    if body.description is not None:
        product.description = body.description
    if body.price is not None:
        product.price = Decimal(str(body.price))
    if body.stock_quantity is not None:
        product.stock_quantity = body.stock_quantity
    if body.image_url is not None:
        product.image_url = body.image_url
    if body.category is not None:
        product.category = body.category
    if body.is_active is not None:
        product.is_active = body.is_active

    await db.commit()
    await db.refresh(product)
    return _product_dict(product)


@router.delete("/api/shop/products/{product_id}")
async def delete_product(
    product_id: int,
    token: str = Depends(verify_token),
    db: AsyncSession = Depends(get_db),
):
    user = await get_current_user(token, db)
    result = await db.execute(
        select(ShopProduct).where(
            ShopProduct.id == product_id,
            ShopProduct.user_id == user.id,
        )
    )
    product = result.scalar_one_or_none()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    # Soft delete — preserves FK integrity from order_items and keeps order history intact.
    # Set stock to 0 so no new orders can be placed against this product.
    product.is_active = False
    product.stock_quantity = 0
    await db.commit()
    return {"message": "Product removed from shop"}


# ---------------------------------------------------------------------------
# Admin: Order management
# ---------------------------------------------------------------------------

@router.get("/api/shop/admin/orders")
async def list_admin_orders(
    status: Optional[str] = None,
    payment_status: Optional[str] = None,
    token: str = Depends(verify_token),
    db: AsyncSession = Depends(get_db),
):
    user = await get_current_user(token, db)
    stmt = (
        select(ShopOrder)
        .where(ShopOrder.user_id == user.id)
        .options(
            selectinload(ShopOrder.items),
            selectinload(ShopOrder.tracking_history),
        )
        .order_by(ShopOrder.created_at.desc())
    )
    if status:
        try:
            stmt = stmt.where(ShopOrder.status == ShopOrderStatus(status))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status '{status}'. Valid: {[s.value for s in ShopOrderStatus]}")
    if payment_status:
        try:
            stmt = stmt.where(ShopOrder.payment_status == ShopOrderPaymentStatus(payment_status))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid payment_status '{payment_status}'. Valid: {[s.value for s in ShopOrderPaymentStatus]}")

    result = await db.execute(stmt)
    orders = result.scalars().all()
    return [_order_dict(o) for o in orders]


@router.get("/api/shop/admin/orders/{order_id}")
async def get_admin_order(
    order_id: int,
    token: str = Depends(verify_token),
    db: AsyncSession = Depends(get_db),
):
    user = await get_current_user(token, db)
    result = await db.execute(
        select(ShopOrder)
        .where(ShopOrder.id == order_id, ShopOrder.user_id == user.id)
        .options(
            selectinload(ShopOrder.items),
            selectinload(ShopOrder.tracking_history),
        )
    )
    order = result.scalar_one_or_none()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    return _order_dict(order)


@router.put("/api/shop/admin/orders/{order_id}/status")
async def update_order_status(
    order_id: int,
    body: UpdateOrderStatusRequest,
    token: str = Depends(verify_token),
    db: AsyncSession = Depends(get_db),
):
    user = await get_current_user(token, db)
    result = await db.execute(
        select(ShopOrder).where(
            ShopOrder.id == order_id,
            ShopOrder.user_id == user.id,
        )
    )
    order = result.scalar_one_or_none()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    try:
        new_status = ShopOrderStatus(body.status)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid status '{body.status}'. Valid: {[s.value for s in ShopOrderStatus]}")

    order.status = new_status
    await db.commit()
    return {"message": "Status updated", "status": body.status}


@router.post("/api/shop/admin/orders/{order_id}/tracking")
async def add_tracking_update(
    order_id: int,
    body: AddTrackingRequest,
    token: str = Depends(verify_token),
    db: AsyncSession = Depends(get_db),
):
    user = await get_current_user(token, db)
    result = await db.execute(
        select(ShopOrder).where(
            ShopOrder.id == order_id,
            ShopOrder.user_id == user.id,
        )
    )
    order = result.scalar_one_or_none()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    tracking = ShopOrderTracking(
        order_id=order.id,
        status_label=body.status_label,
        note=body.note,
        updated_by_user_id=user.id,
    )
    db.add(tracking)
    await db.commit()
    await db.refresh(tracking)
    return _tracking_dict(tracking)


# ---------------------------------------------------------------------------
# Public: Product listing
# ---------------------------------------------------------------------------

@router.get("/api/shop/products")
async def list_products(
    category: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(ShopProduct).where(ShopProduct.is_active == True)
    if category:
        stmt = stmt.where(ShopProduct.category == category)
    stmt = stmt.order_by(ShopProduct.created_at.desc())

    result = await db.execute(stmt)
    products = result.scalars().all()
    return [_product_dict(p) for p in products]


@router.get("/api/shop/products/{product_id}")
async def get_product(product_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ShopProduct).where(
            ShopProduct.id == product_id,
            ShopProduct.is_active == True,
        )
    )
    product = result.scalar_one_or_none()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return _product_dict(product)


# ---------------------------------------------------------------------------
# Public: Orders
# ---------------------------------------------------------------------------

@router.post("/api/shop/orders")
async def place_order(body: PlaceOrderRequest, db: AsyncSession = Depends(get_db)):
    if not body.items:
        raise HTTPException(status_code=400, detail="Order must have at least one item")

    # Load and validate products — shop owner is determined from the products themselves
    order_items = []
    total = Decimal("0.00")
    shop_owner_id: Optional[int] = None

    for item_req in body.items:
        if item_req.quantity < 1:
            raise HTTPException(status_code=400, detail="Quantity must be at least 1")
        # Lock the product row so concurrent requests can't oversell the same stock.
        product_result = await db.execute(
            select(ShopProduct)
            .where(
                ShopProduct.id == item_req.product_id,
                ShopProduct.is_active == True,
            )
            .with_for_update()
        )
        product = product_result.scalar_one_or_none()
        if not product:
            raise HTTPException(
                status_code=404,
                detail=f"Product {item_req.product_id} not found or unavailable",
            )
        if product.stock_quantity < item_req.quantity:
            raise HTTPException(
                status_code=400,
                detail=f"Insufficient stock for '{product.name}' (available: {product.stock_quantity})",
            )
        if shop_owner_id is None:
            shop_owner_id = product.user_id

        subtotal = product.price * item_req.quantity
        total += subtotal
        order_items.append((product, item_req.quantity, subtotal))

    # Create order
    order = ShopOrder(
        order_number=_generate_order_number(),
        user_id=shop_owner_id,
        buyer_name=body.buyer_name,
        buyer_phone=body.buyer_phone,
        buyer_email=body.buyer_email,
        delivery_address=body.delivery_address,
        total_amount=total,
        notes=body.notes,
    )
    db.add(order)
    await db.flush()

    for product, qty, subtotal in order_items:
        db.add(ShopOrderItem(
            order_id=order.id,
            product_id=product.id,
            product_name=product.name,
            product_price=product.price,
            quantity=qty,
            subtotal=subtotal,
        ))
        product.stock_quantity -= qty

    await db.commit()
    await db.refresh(order)

    return {
        "order_id": order.id,
        "order_number": order.order_number,
        "total_amount": float(order.total_amount),
        "status": order.status.value if hasattr(order.status, "value") else order.status,
        "payment_status": order.payment_status.value if hasattr(order.payment_status, "value") else order.payment_status,
    }


@router.post("/api/shop/orders/{order_id}/pay")
async def initiate_order_payment(
    order_id: int,
    body: PayOrderRequest,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(ShopOrder).where(ShopOrder.id == order_id))
    order = result.scalar_one_or_none()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    if order.payment_status == ShopOrderPaymentStatus.PAID:
        raise HTTPException(status_code=400, detail="Order already paid")

    # Normalise phone to 254XXXXXXXXX
    phone = body.phone.strip().replace(" ", "")
    if phone.startswith("0"):
        phone = "254" + phone[1:]
    elif phone.startswith("+"):
        phone = phone[1:]

    callback_url = f"{settings.PROVISION_BASE_URL}/api/shop/mpesa/callback"

    try:
        stk = await initiate_stk_push_direct(
            phone_number=phone,
            amount=float(order.total_amount),
            reference=order.order_number,
            callback_url=callback_url,
            account_reference=order.order_number,
        )
    except Exception as exc:
        logger.error("Shop STK push failed: %s", exc)
        raise HTTPException(status_code=502, detail=f"M-Pesa error: {exc}")

    if not stk:
        raise HTTPException(status_code=502, detail="Failed to initiate M-Pesa payment")

    order.mpesa_checkout_request_id = stk.checkout_request_id
    await db.commit()

    return {
        "message": "STK push sent. Enter M-Pesa PIN on your phone.",
        "checkout_request_id": stk.checkout_request_id,
        "order_number": order.order_number,
    }


@router.get("/api/shop/orders/{order_id}/payment-status")
async def get_order_payment_status(order_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ShopOrder).where(ShopOrder.id == order_id))
    order = result.scalar_one_or_none()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    return {
        "payment_status": order.payment_status.value if hasattr(order.payment_status, "value") else order.payment_status,
        "status": order.status.value if hasattr(order.status, "value") else order.status,
        "mpesa_receipt_number": order.mpesa_receipt_number,
    }


@router.get("/api/shop/orders/track/{order_number}")
async def track_order(
    order_number: str,
    phone: str,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ShopOrder)
        .where(ShopOrder.order_number == order_number.upper())
        .options(
            selectinload(ShopOrder.items),
            selectinload(ShopOrder.tracking_history),
        )
    )
    order = result.scalar_one_or_none()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    # Verify caller owns the order (partial phone match for UX tolerance)
    normalised_input = phone.strip().replace(" ", "").lstrip("+")
    if normalised_input.startswith("254"):
        normalised_input = "0" + normalised_input[3:]
    order_phone = order.buyer_phone.strip().lstrip("+")
    if order_phone.startswith("254"):
        order_phone = "0" + order_phone[3:]

    if normalised_input not in (order.buyer_phone, order_phone):
        raise HTTPException(status_code=403, detail="Phone number does not match order")

    return _order_dict(order)


# ---------------------------------------------------------------------------
# M-Pesa callback for shop orders
# ---------------------------------------------------------------------------

@router.post("/api/shop/mpesa/callback")
async def shop_mpesa_callback(payload: dict, db: AsyncSession = Depends(get_db)):
    logger.info("Shop M-Pesa callback: %s", payload)
    try:
        stk = payload.get("Body", {}).get("stkCallback", {})
        checkout_request_id = stk.get("CheckoutRequestID")
        result_code = stk.get("ResultCode")
        result_desc = stk.get("ResultDesc", "")

        if not checkout_request_id:
            return {"ResultCode": 0, "ResultDesc": "Accepted"}

        result = await db.execute(
            select(ShopOrder).where(
                ShopOrder.mpesa_checkout_request_id == checkout_request_id
            )
        )
        order = result.scalar_one_or_none()
        if not order:
            logger.warning("No shop order for checkout_request_id %s", checkout_request_id)
            return {"ResultCode": 0, "ResultDesc": "Accepted"}

        if result_code == 0:
            # Extract receipt from callback metadata
            receipt = None
            items = stk.get("CallbackMetadata", {}).get("Item", [])
            for item in items:
                if item.get("Name") == "MpesaReceiptNumber":
                    receipt = item.get("Value")
                    break

            order.payment_status = ShopOrderPaymentStatus.PAID
            order.status = ShopOrderStatus.CONFIRMED
            order.mpesa_receipt_number = receipt
            db.add(ShopOrderTracking(
                order_id=order.id,
                status_label="Payment confirmed",
                note=f"M-Pesa receipt: {receipt}",
            ))
        else:
            logger.info("Shop payment failed: %s - %s", result_code, result_desc)

        await db.commit()
    except Exception as exc:
        logger.error("Shop callback error: %s", exc)
        await db.rollback()

    return {"ResultCode": 0, "ResultDesc": "Accepted"}


# ---------------------------------------------------------------------------
# Reporting helpers (shared by dashboard and analytics endpoints)
# ---------------------------------------------------------------------------

def _resolve_period(
    preset: Optional[str],
    start_date: Optional[str],
    end_date: Optional[str],
    now: datetime,
) -> tuple[datetime, datetime, str]:
    today_start = datetime(now.year, now.month, now.day)
    today_end = today_start + timedelta(days=1)

    if start_date or end_date:
        try:
            fs = datetime.strptime(start_date, "%Y-%m-%d") if start_date else today_start
            fe = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1) if end_date else today_end
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format, use YYYY-MM-DD")
        return fs, fe, f"{start_date or 'start'} → {end_date or 'today'}"

    presets: dict = {
        "today":        (today_start, today_end),
        "yesterday":    (today_start - timedelta(days=1), today_start),
        "this_week":    (today_start - timedelta(days=today_start.weekday()), today_end),
        "this_month":   (datetime(now.year, now.month, 1), today_end),
        "last_30_days": (today_start - timedelta(days=29), today_end),
        "last_90_days": (today_start - timedelta(days=89), today_end),
        "this_year":    (datetime(now.year, 1, 1), today_end),
        "all_time":     (datetime(2020, 1, 1), today_end),
    }
    if preset and preset not in presets:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid preset. Valid: {', '.join(presets)}",
        )
    fs, fe = presets.get(preset or "this_month", presets["this_month"])
    return fs, fe, (preset or "this_month").replace("_", " ").title()


async def _shop_revenue_block(db: AsyncSession, user_id: int, now: datetime) -> dict:
    """Four standard revenue windows for a user's shop (paid orders only)."""
    today_start = datetime(now.year, now.month, now.day)
    week_start = today_start - timedelta(days=today_start.weekday())
    month_start = datetime(now.year, now.month, 1)

    base = (
        select(func.coalesce(func.sum(ShopOrder.total_amount), 0))
        .where(
            ShopOrder.user_id == user_id,
            ShopOrder.payment_status == ShopOrderPaymentStatus.PAID,
        )
    )

    async def _q(extra):
        return float((await db.execute(base.where(extra))).scalar())

    return {
        "today":      await _q(ShopOrder.created_at >= today_start),
        "this_week":  await _q(ShopOrder.created_at >= week_start),
        "this_month": await _q(ShopOrder.created_at >= month_start),
        "all_time":   float((await db.execute(base)).scalar()),
    }


# ---------------------------------------------------------------------------
# GET /api/shop/dashboard
# ---------------------------------------------------------------------------

@router.get("/api/shop/dashboard")
async def shop_dashboard(
    token: str = Depends(verify_token),
    db: AsyncSession = Depends(get_db),
):
    """
    Shop-specific dashboard.

    Returns:
    - revenue: today / this_week / this_month / all_time (paid orders only)
    - orders: counts by status and payment_status, plus action badges
    - top_products: top 10 products by all-time revenue
    - recent_orders: last 10 paid orders
    """
    user = await get_current_user(token, db)
    now = datetime.utcnow()

    revenue = await _shop_revenue_block(db, user.id, now)

    status_rows = (await db.execute(
        select(ShopOrder.status, func.count(ShopOrder.id))
        .where(ShopOrder.user_id == user.id)
        .group_by(ShopOrder.status)
    )).all()
    orders_by_status = {
        (row[0].value if hasattr(row[0], "value") else row[0]): row[1]
        for row in status_rows
    }

    pay_rows = (await db.execute(
        select(ShopOrder.payment_status, func.count(ShopOrder.id))
        .where(ShopOrder.user_id == user.id)
        .group_by(ShopOrder.payment_status)
    )).all()
    orders_by_payment = {
        (row[0].value if hasattr(row[0], "value") else row[0]): row[1]
        for row in pay_rows
    }

    top_products_rows = (await db.execute(
        select(
            ShopOrderItem.product_id,
            ShopOrderItem.product_name,
            func.sum(ShopOrderItem.quantity).label("units_sold"),
            func.sum(ShopOrderItem.subtotal).label("revenue"),
        )
        .join(ShopOrder, ShopOrder.id == ShopOrderItem.order_id)
        .where(
            ShopOrder.user_id == user.id,
            ShopOrder.payment_status == ShopOrderPaymentStatus.PAID,
        )
        .group_by(ShopOrderItem.product_id, ShopOrderItem.product_name)
        .order_by(func.sum(ShopOrderItem.subtotal).desc())
        .limit(10)
    )).all()

    top_products = [
        {
            "product_id": r.product_id,
            "product_name": r.product_name,
            "units_sold": int(r.units_sold or 0),
            "revenue": float(r.revenue or 0),
        }
        for r in top_products_rows
    ]

    recent_result = await db.execute(
        select(ShopOrder)
        .where(
            ShopOrder.user_id == user.id,
            ShopOrder.payment_status == ShopOrderPaymentStatus.PAID,
        )
        .order_by(ShopOrder.created_at.desc())
        .limit(10)
    )
    recent_orders = [_order_dict(o, include_items=False) for o in recent_result.scalars().all()]

    return {
        "revenue": revenue,
        "orders": {
            "total": sum(orders_by_status.values()),
            "by_status": orders_by_status,
            "by_payment": orders_by_payment,
            "pending_payment": orders_by_payment.get("unpaid", 0),
            "needs_fulfillment": (
                orders_by_status.get("confirmed", 0)
                + orders_by_status.get("processing", 0)
            ),
        },
        "top_products": top_products,
        "recent_orders": recent_orders,
        "generated_at": now.isoformat(),
    }


# ---------------------------------------------------------------------------
# GET /api/shop/analytics
# ---------------------------------------------------------------------------

@router.get("/api/shop/analytics")
async def shop_analytics(
    preset: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    token: str = Depends(verify_token),
    db: AsyncSession = Depends(get_db),
):
    """
    Time-series analytics for the shop.

    Query params (priority: start_date/end_date > preset):
    - preset: today | yesterday | this_week | this_month | last_30_days |
              last_90_days | this_year | all_time  (default: this_month)
    - start_date / end_date: YYYY-MM-DD

    Returns:
    - period
    - summary: total_revenue, total_orders, unique_buyers, avg_order_value
    - daily_trend:     [{date, label, orders, revenue}]
    - hourly_pattern:  [{hour, label, orders, revenue}]
    - top_products:    top 10 by revenue in period
    - revenue_by_status: [{status, orders, revenue}] (all orders, not just paid)
    """
    user = await get_current_user(token, db)
    now = datetime.utcnow()

    filter_start, filter_end, period_label = _resolve_period(
        preset, start_date, end_date, now
    )

    orders_result = await db.execute(
        select(ShopOrder)
        .where(
            ShopOrder.user_id == user.id,
            ShopOrder.payment_status == ShopOrderPaymentStatus.PAID,
            ShopOrder.created_at >= filter_start,
            ShopOrder.created_at < filter_end,
        )
        .options(selectinload(ShopOrder.items))
        .order_by(ShopOrder.created_at)
    )
    orders = orders_result.scalars().all()

    daily: dict = defaultdict(lambda: {"orders": 0, "revenue": 0.0})
    hourly: dict = {h: {"orders": 0, "revenue": 0.0} for h in range(24)}
    product_totals: dict = defaultdict(lambda: {"units_sold": 0, "revenue": 0.0, "name": ""})
    unique_phones: set = set()

    for o in orders:
        dk = o.created_at.strftime("%Y-%m-%d")
        amount = float(o.total_amount)
        daily[dk]["orders"] += 1
        daily[dk]["revenue"] += amount
        hourly[o.created_at.hour]["orders"] += 1
        hourly[o.created_at.hour]["revenue"] += amount
        unique_phones.add(o.buyer_phone)
        for item in o.items:
            pid = item.product_id or item.product_name
            product_totals[pid]["units_sold"] += item.quantity
            product_totals[pid]["revenue"] += float(item.subtotal)
            product_totals[pid]["name"] = item.product_name

    # Fill every calendar day in the range (no gaps in chart)
    daily_trend = []
    cursor = filter_start
    while cursor < filter_end and cursor <= now:
        dk = cursor.strftime("%Y-%m-%d")
        daily_trend.append({
            "date": dk,
            "label": cursor.strftime("%b %d"),
            "orders": daily[dk]["orders"],
            "revenue": round(daily[dk]["revenue"], 2),
        })
        cursor += timedelta(days=1)

    total_revenue = sum(d["revenue"] for d in daily.values())
    total_orders = len(orders)

    top_products = sorted(
        [
            {
                "product_id": pid if isinstance(pid, int) else None,
                "product_name": data["name"],
                "units_sold": data["units_sold"],
                "revenue": round(data["revenue"], 2),
            }
            for pid, data in product_totals.items()
        ],
        key=lambda x: x["revenue"],
        reverse=True,
    )[:10]

    hourly_pattern = [
        {
            "hour": h,
            "label": f"{h:02d}:00",
            "orders": hourly[h]["orders"],
            "revenue": round(hourly[h]["revenue"], 2),
        }
        for h in range(24)
    ]

    status_revenue_rows = (await db.execute(
        select(
            ShopOrder.status,
            func.count(ShopOrder.id),
            func.coalesce(func.sum(ShopOrder.total_amount), 0),
        )
        .where(
            ShopOrder.user_id == user.id,
            ShopOrder.created_at >= filter_start,
            ShopOrder.created_at < filter_end,
        )
        .group_by(ShopOrder.status)
    )).all()

    revenue_by_status = [
        {
            "status": row[0].value if hasattr(row[0], "value") else row[0],
            "orders": row[1],
            "revenue": float(row[2]),
        }
        for row in status_revenue_rows
    ]

    return {
        "period": {
            "label": period_label,
            "start": filter_start.strftime("%Y-%m-%d"),
            "end": (filter_end - timedelta(days=1)).strftime("%Y-%m-%d"),
        },
        "summary": {
            "total_revenue": round(total_revenue, 2),
            "total_orders": total_orders,
            "unique_buyers": len(unique_phones),
            "avg_order_value": round(total_revenue / total_orders, 2) if total_orders else 0,
        },
        "daily_trend": daily_trend,
        "hourly_pattern": hourly_pattern,
        "top_products": top_products,
        "revenue_by_status": revenue_by_status,
        "generated_at": now.isoformat(),
    }
