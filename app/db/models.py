from sqlalchemy import Column, Integer, String, Enum, DateTime, ForeignKey, Float, Boolean, BigInteger, DECIMAL, Index, UniqueConstraint
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import relationship
from datetime import datetime
import enum
from sqlalchemy import JSON
from app.db.database import Base  # Import Base from database.py

class MpesaTransactionStatus(enum.Enum):
    pending = "pending"
    completed = "completed"
    failed = "failed"
    expired = "expired"

class FailureSource(str, enum.Enum):
    CLIENT = "client"          # Customer-side: cancelled, insufficient funds, wrong PIN
    MPESA_API = "mpesa_api"    # Safaricom API: rejected STK push, auth failure, network error
    SERVER = "server"          # Our server: crash during callback processing, DB error
    TIMEOUT = "timeout"        # No response: STK push sent but no callback received

class UserRole(str, enum.Enum):
    ADMIN = "admin"
    RESELLER = "reseller"

class ConnectionType(str, enum.Enum):
    HOTSPOT = "hotspot"
    PPPOE = "pppoe"
    STATIC_IP = "static_ip"


class RouterAuthMethod(str, enum.Enum):
    """Authentication method used by a router for hotspot users"""
    DIRECT_API = "DIRECT_API"  # Current method - direct MikroTik API calls
    RADIUS = "RADIUS"          # New method - FreeRADIUS server

class CustomerStatus(str, enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING = "pending"

class PaymentStatus(str, enum.Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"
    REFUNDED = "refunded"


class ProvisioningAttemptSource(str, enum.Enum):
    MPESA_TRANSACTION = "mpesa_transaction"
    CUSTOMER_PAYMENT = "customer_payment"


class ProvisioningAttemptEntrypoint(str, enum.Enum):
    HOTSPOT_PAYMENT = "hotspot_payment"
    HOTSPOT_RECONCILIATION = "hotspot_reconciliation"
    VOUCHER_DIRECT_API = "voucher_direct_api"
    MANUAL_TRANSACTION_PROVISION = "manual_transaction_provision"


class ProvisioningState(str, enum.Enum):
    SCHEDULED = "scheduled"
    IN_PROGRESS = "in_progress"
    RETRY_PENDING = "retry_pending"
    ROUTER_UPDATED = "router_updated"
    FAILED = "failed"


class ProvisioningOnlineState(str, enum.Enum):
    UNKNOWN = "unknown"
    OFFLINE = "offline"
    ONLINE = "online"

class PaymentMethod(str, enum.Enum):
    CASH = "cash"
    MOBILE_MONEY = "mobile_money"
    BANK_TRANSFER = "bank_transfer"
    CARD = "card"
    OTHER = "other"

class CollectionMode(str, enum.Enum):
    DIRECT = "direct"
    SYSTEM_COLLECTED = "system_collected"

class DurationUnit(str, enum.Enum):
    MINUTES = "MINUTES"
    HOURS = "HOURS"
    DAYS = "DAYS"

class PlanType(str, enum.Enum):
    REGULAR = "regular"
    EMERGENCY = "emergency"
    SPECIAL_OFFER = "special_offer"

class FupAction(str, enum.Enum):
    THROTTLE = "throttle"
    BLOCK = "block"
    NOTIFY_ONLY = "notify_only"

class SubscriptionStatus(str, enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    TRIAL = "trial"
    SUSPENDED = "suspended"

class InvoiceStatus(str, enum.Enum):
    PENDING = "pending"
    PAID = "paid"
    OVERDUE = "overdue"
    WAIVED = "waived"

class SubscriptionPaymentStatus(str, enum.Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_code = Column(BigInteger, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(Enum(UserRole, name="userrole"), nullable=False)
    organization_name = Column(String, nullable=False)
    business_name = Column(String(255), nullable=True)
    support_phone = Column(String(20), nullable=True)
    mpesa_shortcode = Column(String(20), nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login_at = Column(DateTime, nullable=True)
    subscription_status = Column(
        Enum(SubscriptionStatus, name="subscriptionstatus",
             values_callable=lambda e: [x.value for x in e]),
        nullable=False,
        default=SubscriptionStatus.TRIAL,
        server_default="trial"
    )
    subscription_expires_at = Column(DateTime, nullable=True)

class Customer(Base):
    __tablename__ = "customers"
    __table_args__ = (
        UniqueConstraint("mac_address", "user_id", name="uq_customer_mac_per_reseller"),
    )
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=True)
    phone = Column(String, nullable=False)
    mac_address = Column(String)
    pppoe_username = Column(String)
    pppoe_password = Column(String)
    static_ip = Column(String)
    status = Column(Enum(CustomerStatus), nullable=False, default=CustomerStatus.INACTIVE)
    expiry = Column(DateTime)
    plan_id = Column(Integer, ForeignKey("plans.id"))
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    plan = relationship("Plan")
    router_id = Column(Integer, ForeignKey("routers.id"), nullable=True)
    pending_update_data = Column(JSON, nullable=True)
    router = relationship("Router")
    # Location fields for mapping
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    location_captured_at = Column(DateTime, nullable=True)

class CustomerRating(Base):
    """Customer ratings/feedback after purchase - identified by phone number"""
    __tablename__ = "customer_ratings"
    id = Column(Integer, primary_key=True, autoincrement=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=True)  # Nullable to allow non-customers
    phone = Column(String, nullable=False, index=True)  # For lookup by phone
    rating = Column(Integer, nullable=False)  # 1-5 stars
    comment = Column(String(500), nullable=True)
    service_quality = Column(Integer, nullable=True)  # Optional: 1-5
    support_rating = Column(Integer, nullable=True)  # Optional: 1-5
    value_for_money = Column(Integer, nullable=True)  # Optional: 1-5
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    # Store location snapshot at time of rating
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    customer = relationship("Customer", backref="ratings")


class Plan(Base):
    __tablename__ = "plans"
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    speed = Column(String, nullable=False)
    price = Column(Integer, nullable=False)
    duration_value = Column(Integer, nullable=False)
    duration_unit = Column(Enum(DurationUnit), nullable=False)
    connection_type = Column(Enum(ConnectionType), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    router_profile = Column(String)
    plan_type = Column(
        Enum(PlanType, name="plantype", values_callable=lambda e: [x.value for x in e]),
        nullable=False,
        default=PlanType.REGULAR,
        server_default="regular"
    )
    is_hidden = Column(Boolean, nullable=False, default=False, server_default="false")
    badge_text = Column(String(100), nullable=True)
    original_price = Column(Integer, nullable=True)
    valid_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    data_cap_mb = Column(BigInteger, nullable=True)
    fup_action = Column(
        Enum(FupAction, name="fupaction", values_callable=lambda e: [x.value for x in e]),
        nullable=True,
    )
    fup_throttle_profile = Column(String(100), nullable=True)

class Payment(Base):
    __tablename__ = "payments"
    id = Column(Integer, primary_key=True, autoincrement=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)
    amount = Column(Integer, nullable=False)
    days_paid_for = Column(Integer, nullable=False)
    paid_on = Column(DateTime, default=datetime.utcnow)
    customer = relationship("Customer")

class CustomerPayment(Base):
    __tablename__ = "customer_payments"
    id = Column(Integer, primary_key=True, autoincrement=True)
    # Nullable so that deleting a customer preserves the payment history (SET NULL, not CASCADE DELETE)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=True)
    reseller_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    amount = Column(Float, nullable=False)
    payment_method = Column(Enum(PaymentMethod), nullable=False, default=PaymentMethod.CASH)
    payment_reference = Column(String(100), nullable=True)
    payment_date = Column(DateTime, default=datetime.utcnow)
    days_paid_for = Column(Integer, nullable=False)
    status = Column(Enum(PaymentStatus), default=PaymentStatus.COMPLETED)
    notes = Column(String(500), nullable=True)
    # Snapshot of customer name at payment time — preserved after customer deletion
    customer_name = Column(String(255), nullable=True)
    lipay_tx_no = Column(String(255), nullable=True)
    collection_mode = Column(
        Enum(CollectionMode, name="collectionmode",
             values_callable=lambda e: [x.value for x in e]),
        nullable=True,
    )
    created_at = Column(DateTime, default=datetime.utcnow)
    customer = relationship("Customer", backref="customer_payments")
    reseller = relationship("User", backref="received_payments", foreign_keys=[reseller_id])


class ResellerFinancials(Base):
    __tablename__ = "reseller_financials"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    total_revenue = Column(Float, default=0.00)
    total_customers = Column(Integer, default=0)
    active_customers = Column(Integer, default=0)
    last_payment_date = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    # One-time correction applied when historical payment rows were lost due to
    # cascading deletes. Always >= 0. Repaired via /api/admin/repair-balance.
    balance_correction = Column(Float, default=0.0, nullable=False)
    balance_corrected_at = Column(DateTime, nullable=True)
    user = relationship("User", backref="financials")

class Subscription(Base):
    __tablename__ = "subscriptions"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    status = Column(
        Enum(SubscriptionStatus, name="subscriptionstatus",
             values_callable=lambda e: [x.value for x in e]),
        nullable=False,
        default=SubscriptionStatus.TRIAL,
    )
    current_period_start = Column(DateTime, nullable=True)
    current_period_end = Column(DateTime, nullable=True)
    trial_ends_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user = relationship("User", backref="subscription")

    # Legacy columns kept for migration compatibility
    is_active = Column(Boolean, nullable=True)
    paid_on = Column(DateTime, nullable=True)
    expires_on = Column(DateTime, nullable=True)
    plan_type = Column(String, nullable=True)
    cost = Column(Float, nullable=True)


class SubscriptionInvoice(Base):
    __tablename__ = "subscription_invoices"
    __table_args__ = (
        UniqueConstraint("user_id", "period_start", name="uq_subscription_invoice_user_period"),
    )
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    period_start = Column(DateTime, nullable=False)
    period_end = Column(DateTime, nullable=False)
    hotspot_revenue = Column(Float, nullable=False, default=0)
    hotspot_charge = Column(Float, nullable=False, default=0)
    pppoe_user_count = Column(Integer, nullable=False, default=0)
    pppoe_charge = Column(Float, nullable=False, default=0)
    gross_charge = Column(Float, nullable=False, default=0)
    final_charge = Column(Float, nullable=False, default=0)
    status = Column(
        Enum(InvoiceStatus, name="invoicestatus",
             values_callable=lambda e: [x.value for x in e]),
        nullable=False,
        default=InvoiceStatus.PENDING,
    )
    due_date = Column(DateTime, nullable=False)
    paid_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", backref="subscription_invoices")


class SubscriptionPayment(Base):
    __tablename__ = "subscription_payments"
    id = Column(Integer, primary_key=True, autoincrement=True)
    invoice_id = Column(Integer, ForeignKey("subscription_invoices.id"), nullable=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    amount = Column(Float, nullable=False)
    payment_method = Column(String(50), nullable=False, default="mpesa")
    payment_reference = Column(String(255), nullable=True)
    mpesa_checkout_request_id = Column(String(255), nullable=True, unique=True, index=True)
    phone_number = Column(String(20), nullable=True)
    status = Column(
        Enum(SubscriptionPaymentStatus, name="subscriptionpaymentstatus",
             values_callable=lambda e: [x.value for x in e]),
        nullable=False,
        default=SubscriptionPaymentStatus.PENDING,
    )
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", backref="subscription_payments")
    invoice = relationship("SubscriptionInvoice", backref="payments")


class Router(Base):
    __tablename__ = "routers"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=False)
    identity = Column(String, nullable=True, unique=True)  # MikroTik system identity for frontend lookup
    ip_address = Column(String, nullable=False)
    username = Column(String, nullable=False)
    password = Column(String, nullable=False)
    port = Column(Integer, nullable=False, default=8728)
    created_at = Column(DateTime, default=datetime.utcnow)
    # RADIUS authentication fields (new - does not affect existing routers)
    auth_method = Column(
        Enum(RouterAuthMethod, name="routerauthmethod"), 
        nullable=False, 
        default=RouterAuthMethod.DIRECT_API,
        server_default="DIRECT_API"
    )
    radius_secret = Column(String(255), nullable=True)  # Shared secret for RADIUS
    radius_nas_identifier = Column(String(100), nullable=True)  # NAS-Identifier for this router
    payment_methods = Column(JSON, nullable=False, server_default='["mpesa", "voucher"]')
    pppoe_ports = Column(JSON, nullable=True)  # e.g. ["ether4", "ether5"]
    plain_ports = Column(JSON, nullable=True)  # e.g. ["ether6", "ether7"]
    dual_ports = Column(JSON, nullable=True)   # e.g. ["ether3"] — PPPoE + Hotspot on same port
    last_status = Column(Boolean, nullable=True)
    last_checked_at = Column(DateTime, nullable=True)
    last_online_at = Column(DateTime, nullable=True)
    last_status_source = Column(String(50), nullable=True)
    availability_checks = Column(Integer, nullable=False, default=0, server_default="0")
    availability_successes = Column(Integer, nullable=False, default=0, server_default="0")
    emergency_active = Column(Boolean, nullable=False, default=False, server_default="false")
    emergency_message = Column(String(500), nullable=True)
    payment_method_id = Column(Integer, ForeignKey("reseller_payment_methods.id"), nullable=True)
    assigned_payment_method = relationship("ResellerPaymentMethod", back_populates="routers")

class ProvisioningLog(Base):
    __tablename__ = "provisioning_logs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)
    router_id = Column(Integer, ForeignKey("routers.id"), nullable=True)
    attempt_id = Column(Integer, ForeignKey("provisioning_attempts.id"), nullable=True)
    mac_address = Column(String(50), nullable=True)
    action = Column(String, nullable=False)
    status = Column(String, nullable=False)
    error = Column(String(255))
    details = Column(String(255))
    log_date = Column(DateTime, default=datetime.utcnow)


class ProvisioningAttempt(Base):
    __tablename__ = "provisioning_attempts"
    __table_args__ = (
        UniqueConstraint("source_table", "source_pk", name="uq_provisioning_attempt_source"),
        Index("idx_provisioning_attempt_state_updated", "provisioning_state", "updated_at"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False, index=True)
    router_id = Column(Integer, ForeignKey("routers.id"), nullable=True, index=True)
    mac_address = Column(String(50), nullable=True, index=True)
    source_table = Column(
        Enum(
            ProvisioningAttemptSource,
            name="provisioningattemptsource",
            values_callable=lambda enum_cls: [item.value for item in enum_cls],
        ),
        nullable=False,
    )
    source_pk = Column(Integer, nullable=False)
    external_reference = Column(String(255), nullable=True, index=True)
    entrypoint = Column(
        Enum(
            ProvisioningAttemptEntrypoint,
            name="provisioningattemptentrypoint",
            values_callable=lambda enum_cls: [item.value for item in enum_cls],
        ),
        nullable=False,
    )
    provisioning_state = Column(
        Enum(
            ProvisioningState,
            name="provisioningstate",
            values_callable=lambda enum_cls: [item.value for item in enum_cls],
        ),
        nullable=False,
        default=ProvisioningState.SCHEDULED,
        server_default=ProvisioningState.SCHEDULED.value,
    )
    online_state = Column(
        Enum(
            ProvisioningOnlineState,
            name="provisioningonlinestate",
            values_callable=lambda enum_cls: [item.value for item in enum_cls],
        ),
        nullable=False,
        default=ProvisioningOnlineState.UNKNOWN,
        server_default=ProvisioningOnlineState.UNKNOWN.value,
    )
    attempt_count = Column(Integer, nullable=False, default=0, server_default="0")
    last_error = Column(String(255), nullable=True)
    last_attempt_at = Column(DateTime, nullable=True)
    router_updated_at = Column(DateTime, nullable=True)
    last_online_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

class MpesaTransaction(Base):
    __tablename__ = "mpesa_transactions"
    id = Column(Integer, primary_key=True, index=True)
    checkout_request_id = Column(String(255), unique=True, nullable=False, index=True)
    phone_number = Column(String(20), nullable=False)
    amount = Column(DECIMAL(10, 2), nullable=False)
    reference = Column(String(255), nullable=False)
    lipay_tx_no = Column(String(255), nullable=True)  # <-- Add this line
    status = Column(Enum(MpesaTransactionStatus), default=MpesaTransactionStatus.pending)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=True)
    merchant_request_id = Column(String(255), nullable=True)
    mpesa_receipt_number = Column(String(255), nullable=True)
    result_code = Column(String(50), nullable=True)
    result_desc = Column(String(500), nullable=True)
    failure_source = Column(
        Enum(
            FailureSource,
            name="failuresource",
            values_callable=lambda enum_cls: [item.value for item in enum_cls]
        ),
        nullable=True
    )
    transaction_date = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class BandwidthSnapshot(Base):
    __tablename__ = "bandwidth_snapshots"
    id = Column(Integer, primary_key=True, autoincrement=True)
    router_id = Column(Integer, ForeignKey("routers.id"), nullable=True)
    total_upload_bps = Column(BigInteger, default=0)
    total_download_bps = Column(BigInteger, default=0)
    avg_upload_bps = Column(Float, default=0)
    avg_download_bps = Column(Float, default=0)
    active_queues = Column(Integer, default=0)  # combined hotspot hosts + PPPoE sessions (legacy field; kept for back-compat)
    active_hotspot_users = Column(Integer, default=0)  # hotspot-only host count at snapshot time (authorized + bypassed)
    active_sessions = Column(Integer, default=0)
    # Interface-based counters for accurate averaging
    interface_rx_bytes = Column(BigInteger, default=0)
    interface_tx_bytes = Column(BigInteger, default=0)
    recorded_at = Column(DateTime, default=datetime.utcnow, index=True)


class UserBandwidthUsage(Base):
    """Track cumulative bandwidth usage per user for top downloaders.

    ``upload_bytes`` / ``download_bytes`` keep the latest cumulative router
    counter (legacy semantics, used by existing UIs).  ``last_upload_bytes`` /
    ``last_download_bytes`` record the *previous* sample so the snapshot job
    can compute reset-safe deltas and add them into ``CustomerUsagePeriod``.
    """
    __tablename__ = "user_bandwidth_usage"
    id = Column(Integer, primary_key=True, autoincrement=True)
    mac_address = Column(String(50), index=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=True)
    queue_name = Column(String(100))
    target_ip = Column(String(50))
    upload_bytes = Column(BigInteger, default=0)
    download_bytes = Column(BigInteger, default=0)
    last_upload_bytes = Column(BigInteger, default=0, server_default="0")
    last_download_bytes = Column(BigInteger, default=0, server_default="0")
    max_limit = Column(String(50))
    last_updated = Column(DateTime, default=datetime.utcnow, index=True)


class CustomerUsagePeriod(Base):
    """Per-customer billing-period bandwidth aggregate, anchored to ``customer.expiry``.

    A new row is opened on each renewal (payment that extends ``expiry``) and the
    previous row is closed.  ``cap_mb_snapshot`` and ``fup_action_snapshot``
    capture the plan's FUP settings *at the time the period opened* so mid-period
    plan changes don't corrupt history.
    """
    __tablename__ = "customer_usage_periods"
    __table_args__ = (
        UniqueConstraint("customer_id", "period_start", name="uq_customer_period_start"),
        Index("ix_customer_usage_periods_customer_open", "customer_id", "closed_at"),
    )
    id = Column(Integer, primary_key=True, autoincrement=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False, index=True)
    period_start = Column(DateTime, nullable=False, index=True)
    period_end = Column(DateTime, nullable=False)
    upload_bytes = Column(BigInteger, default=0, server_default="0", nullable=False)
    download_bytes = Column(BigInteger, default=0, server_default="0", nullable=False)
    total_bytes = Column(BigInteger, default=0, server_default="0", nullable=False)
    cap_mb_snapshot = Column(BigInteger, nullable=True)
    fup_action_snapshot = Column(
        Enum(FupAction, name="fupaction", values_callable=lambda e: [x.value for x in e]),
        nullable=True,
    )
    fup_triggered_at = Column(DateTime, nullable=True)
    fup_action_taken = Column(
        Enum(FupAction, name="fupaction", values_callable=lambda e: [x.value for x in e]),
        nullable=True,
    )
    fup_reverted_at = Column(DateTime, nullable=True)
    closed_at = Column(DateTime, nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    customer = relationship("Customer", backref="usage_periods")


# ========================================
# ADS MODELS
# ========================================

class VoucherStatus(str, enum.Enum):
    AVAILABLE = "available"
    REDEEMED = "redeemed"
    EXPIRED = "expired"
    DISABLED = "disabled"


class AdBadgeType(str, enum.Enum):
    HOT = "hot"
    NEW = "new"
    SALE = "sale"

class AdClickType(str, enum.Enum):
    VIEW_DETAILS = "view_details"
    CALL = "call"
    WHATSAPP = "whatsapp"

class Voucher(Base):
    __tablename__ = "vouchers"
    id = Column(Integer, primary_key=True, autoincrement=True)
    code = Column(String(9), unique=True, nullable=False, index=True)  # 8 digits (new) or legacy "XXXX-XXXX"
    plan_id = Column(Integer, ForeignKey("plans.id"), nullable=False)
    router_id = Column(Integer, ForeignKey("routers.id"), nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    status = Column(
        Enum(VoucherStatus, name="voucherstatus", values_callable=lambda e: [x.value for x in e]),
        nullable=False, default=VoucherStatus.AVAILABLE
    )
    batch_id = Column(String(36), nullable=True, index=True)
    redeemed_by = Column(Integer, ForeignKey("customers.id"), nullable=True)
    redeemed_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    plan = relationship("Plan")
    router = relationship("Router")
    user = relationship("User", backref="vouchers")
    customer = relationship("Customer", foreign_keys=[redeemed_by])


class Advertiser(Base):
    __tablename__ = "advertisers"
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    business_name = Column(String(150), nullable=True)
    phone_number = Column(String(20), nullable=False)
    email = Column(String(100), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    ads = relationship("Ad", back_populates="advertiser")

class Ad(Base):
    __tablename__ = "ads"
    id = Column(Integer, primary_key=True, autoincrement=True)
    advertiser_id = Column(Integer, ForeignKey("advertisers.id"), nullable=False)
    title = Column(String(150), nullable=False)
    description = Column(String(500), nullable=True)
    image_url = Column(String(500), nullable=False)
    seller_name = Column(String(100), nullable=False)
    seller_location = Column(String(200), nullable=True)
    phone_number = Column(String(20), nullable=False)
    whatsapp_number = Column(String(20), nullable=True)
    price = Column(String(50), nullable=True)
    price_value = Column(Float, nullable=True)
    badge_type = Column(Enum(AdBadgeType, name="adbadgetype"), nullable=True)
    badge_text = Column(String(50), nullable=True)
    category = Column(String(50), nullable=True)
    is_active = Column(Boolean, default=True, index=True)
    priority = Column(Integer, default=0, index=True)
    views_count = Column(Integer, default=0)
    clicks_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True, index=True)
    advertiser = relationship("Advertiser", back_populates="ads")

class AdClick(Base):
    __tablename__ = "ad_clicks"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ad_id = Column(Integer, ForeignKey("ads.id"), nullable=False, index=True)
    click_type = Column(Enum(AdClickType, name="adclicktype"), nullable=False)
    device_id = Column(String(100), nullable=True)
    user_agent = Column(String(500), nullable=True)
    session_id = Column(String(100), nullable=True, index=True)
    referrer = Column(String(100), nullable=True)
    mac_address = Column(String(50), nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    ad = relationship("Ad")

class AdImpression(Base):
    __tablename__ = "ad_impressions"
    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String(100), nullable=True)
    session_id = Column(String(100), nullable=True, index=True)
    placement = Column(String(100), nullable=True)
    ad_ids = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class ProvisioningTokenStatus(str, enum.Enum):
    PENDING = "pending"
    PROVISIONED = "provisioned"
    EXPIRED = "expired"


class ProvisioningToken(Base):
    __tablename__ = "provisioning_tokens"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    token = Column(String(64), unique=True, nullable=False, index=True)
    router_name = Column(String, nullable=False)
    identity = Column(String, nullable=False)
    vpn_type = Column(String(20), nullable=False, server_default="wireguard")
    wireguard_ip = Column(String(15), nullable=False)
    ssid = Column(String(100), nullable=False, default="Bitwave WiFi")
    router_admin_password = Column(String, nullable=False, default="admin")
    wg_private_key = Column(String, nullable=True)
    wg_public_key = Column(String, nullable=True)
    l2tp_username = Column(String, nullable=True)
    l2tp_password = Column(String, nullable=True)
    server_wg_pubkey = Column(String, nullable=True)
    server_public_ip = Column(String(45), nullable=False)
    payment_methods = Column(JSON, nullable=False, server_default='["mpesa", "voucher"]')
    # Opt-in flag for the legacy v6 RouterBOARD split-filesystem workaround.
    # When True (and vpn_type == "l2tp"), the .rsc generator points the hotspot
    # html-directory at `flash/hotspot` so our custom login.html survives reboot
    # on hEX / hAP / RB-series boards whose root filesystem is RAM-backed
    # (tmpfs) and only `flash/` is NAND-persistent. When False (default), we use
    # plain `hotspot` -- the safe path that works on CHR, x86, and on every v6
    # board whose RouterOS build uses a unified persistent filesystem. v7 always
    # ignores this flag because v7 has a unified filesystem on all platforms.
    is_routerboard = Column(Boolean, nullable=False, server_default="false", default=False)
    status = Column(
        Enum(ProvisioningTokenStatus, name="provisioningtokenstatus", values_callable=lambda e: [x.value for x in e]),
        nullable=False,
        default=ProvisioningTokenStatus.PENDING,
        server_default="pending"
    )
    created_at = Column(DateTime, default=datetime.utcnow)
    provisioned_at = Column(DateTime, nullable=True)
    router_id = Column(Integer, ForeignKey("routers.id"), nullable=True)


class RouterLogSeverity(str, enum.Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class RouterLogEntry(Base):
    """Notable router log entries persisted for historical tracking."""
    __tablename__ = "router_log_entries"
    id = Column(Integer, primary_key=True, autoincrement=True)
    router_id = Column(Integer, ForeignKey("routers.id"), nullable=False, index=True)
    topic = Column(String(50), nullable=False, index=True)
    message = Column(String(1000), nullable=False)
    username = Column(String(255), nullable=True, index=True)
    severity = Column(
        Enum(RouterLogSeverity, name="routerlogseverity", values_callable=lambda e: [x.value for x in e]),
        nullable=False,
        default=RouterLogSeverity.INFO,
    )
    router_timestamp = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    router = relationship("Router")


class RouterAvailabilityCheck(Base):
    """Per-poll router reachability history used for uptime reporting."""
    __tablename__ = "router_availability_checks"
    __table_args__ = (
        Index("idx_router_availability_router_checked", "router_id", "checked_at"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    # RESTRICT (not CASCADE) — router deletion must explicitly clean these rows
    router_id = Column(Integer, ForeignKey("routers.id", ondelete="RESTRICT"), nullable=False, index=True)
    checked_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    is_online = Column(Boolean, nullable=False, index=True)
    source = Column(String(50), nullable=False, default="unknown")

    router = relationship("Router")


# ========================================
# RESELLER PAYMENT METHODS
# ========================================

class ResellerPaymentMethodType(str, enum.Enum):
    BANK_ACCOUNT = "bank_account"
    MPESA_PAYBILL = "mpesa_paybill"
    MPESA_PAYBILL_WITH_KEYS = "mpesa_paybill_with_keys"
    ZENOPAY = "zenopay"
    MTN_MOMO = "mtn_momo"


class ZenoPayTransactionStatus(str, enum.Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"


class MtnMomoTransactionStatus(str, enum.Enum):
    PENDING = "pending"
    SUCCESSFUL = "successful"
    FAILED = "failed"


class ResellerPaymentMethod(Base):
    """Payment method configured by a reseller, assignable to individual routers."""
    __tablename__ = "reseller_payment_methods"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    method_type = Column(
        Enum(ResellerPaymentMethodType, name="resellerpaymentmethodtype",
             values_callable=lambda e: [x.value for x in e]),
        nullable=False,
    )
    label = Column(String(100), nullable=False)
    is_active = Column(Boolean, nullable=False, default=True, server_default="true")

    # Bank Account fields
    bank_paybill_number = Column(String(20), nullable=True)
    bank_account_number = Column(String(50), nullable=True)

    # M-Pesa Paybill without API keys
    mpesa_paybill_number = Column(String(20), nullable=True)

    # M-Pesa Paybill/Till with API keys (encrypted at rest)
    mpesa_shortcode = Column(String(20), nullable=True)
    mpesa_passkey_encrypted = Column(String(500), nullable=True)
    mpesa_consumer_key_encrypted = Column(String(500), nullable=True)
    mpesa_consumer_secret_encrypted = Column(String(500), nullable=True)

    # ZenoPay (Tanzania)
    zenopay_api_key_encrypted = Column(String(500), nullable=True)
    zenopay_account_id = Column(String(100), nullable=True)

    # MTN Mobile Money (Collection / RequestToPay)
    mtn_api_user = Column(String(64), nullable=True)
    mtn_api_key_encrypted = Column(String(500), nullable=True)
    mtn_subscription_key_encrypted = Column(String(500), nullable=True)
    mtn_target_environment = Column(String(50), nullable=True)  # sandbox | mtnuganda | mtnghana | ...
    mtn_base_url = Column(String(255), nullable=True)  # https://sandbox.momodeveloper.mtn.com or prod host
    mtn_currency = Column(String(10), nullable=True)   # EUR for sandbox, UGX/GHS/... for prod

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship("User", backref="payment_methods")
    routers = relationship("Router", back_populates="assigned_payment_method")


class ZenoPayTransaction(Base):
    """Tracks ZenoPay payment lifecycle (analogous to MpesaTransaction)."""
    __tablename__ = "zenopay_transactions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    order_id = Column(String(255), unique=True, nullable=False, index=True)
    reseller_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=True, index=True)
    amount = Column(DECIMAL(10, 2), nullable=False)
    status = Column(
        Enum(ZenoPayTransactionStatus, name="zenopaytransactionstatus",
             values_callable=lambda e: [x.value for x in e]),
        nullable=False,
        default=ZenoPayTransactionStatus.PENDING,
    )
    reference = Column(String(255), nullable=True)
    channel = Column(String(50), nullable=True)
    buyer_phone = Column(String(20), nullable=False)
    buyer_name = Column(String(100), nullable=True)
    buyer_email = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    customer = relationship("Customer")
    reseller = relationship("User")


class MtnMomoTransaction(Base):
    """Tracks MTN MoMo Collection (RequestToPay) lifecycle per reseller."""
    __tablename__ = "mtn_momo_transactions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    # X-Reference-Id we generated (UUID v4) — doubles as the resource ID used by
    # GET /requesttopay/{referenceId} and as our local unique key.
    reference_id = Column(String(64), unique=True, nullable=False, index=True)
    # We also send this as `externalId` in the RequestToPay body for reconciliation.
    external_id = Column(String(64), nullable=True, index=True)

    reseller_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=True, index=True)

    amount = Column(DECIMAL(10, 2), nullable=False)
    currency = Column(String(10), nullable=False)
    phone = Column(String(20), nullable=False)

    status = Column(
        Enum(MtnMomoTransactionStatus, name="mtnmomotransactionstatus",
             values_callable=lambda e: [x.value for x in e]),
        nullable=False,
        default=MtnMomoTransactionStatus.PENDING,
    )
    # Returned by MTN once the payment succeeds
    financial_transaction_id = Column(String(128), nullable=True)
    # Populated on FAILED responses (code + message)
    reason_code = Column(String(100), nullable=True)
    reason_message = Column(String(500), nullable=True)

    target_environment = Column(String(50), nullable=False)
    payer_message = Column(String(160), nullable=True)
    payee_note = Column(String(160), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    customer = relationship("Customer")
    reseller = relationship("User")


class ResellerPayout(Base):
    """Manual payout recorded by admin when system-collected funds are sent to a reseller."""
    __tablename__ = "reseller_payouts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    reseller_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    amount = Column(Float, nullable=False)
    payment_method = Column(String(50), nullable=False)
    reference = Column(String(255), nullable=True)
    notes = Column(String(500), nullable=True)
    period_start = Column(DateTime, nullable=True)
    period_end = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    reseller = relationship("User", backref="payouts")


class ResellerTransactionCharge(Base):
    """Deduction recorded by admin against a reseller's balance (e.g. bank fees, M-Pesa charges)."""
    __tablename__ = "reseller_transaction_charges"

    id = Column(Integer, primary_key=True, autoincrement=True)
    reseller_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    amount = Column(Float, nullable=False)
    description = Column(String(255), nullable=False)
    reference = Column(String(255), nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    reseller = relationship("User", foreign_keys=[reseller_id], backref="transaction_charges")
    admin = relationship("User", foreign_keys=[created_by])


class B2BTransactionStatus(str, enum.Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class B2BTransaction(Base):
    """Tracks M-Pesa B2B payout API calls to resellers."""
    __tablename__ = "b2b_transactions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    reseller_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    conversation_id = Column(String(255), unique=True, nullable=True, index=True)
    originator_conversation_id = Column(String(255), nullable=True)
    amount = Column(Float, nullable=False)
    fee = Column(Float, nullable=False, default=0)
    net_amount = Column(Float, nullable=False)
    party_a = Column(String(20), nullable=False)
    party_b = Column(String(20), nullable=False)
    account_reference = Column(String(255), nullable=True)
    command_id = Column(String(50), nullable=False, default="BusinessPayBill")
    remarks = Column(String(255), nullable=True)
    status = Column(
        Enum(B2BTransactionStatus, name="b2btransactionstatus",
             values_callable=lambda e: [x.value for x in e]),
        nullable=False,
        default=B2BTransactionStatus.PENDING,
    )
    result_code = Column(String(50), nullable=True)
    result_desc = Column(String(500), nullable=True)
    transaction_id = Column(String(255), nullable=True)
    payout_id = Column(Integer, ForeignKey("reseller_payouts.id"), nullable=True)
    charge_id = Column(Integer, ForeignKey("reseller_transaction_charges.id"), nullable=True)
    triggered_by = Column(String(20), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    completed_at = Column(DateTime, nullable=True)

    reseller = relationship("User", backref="b2b_transactions")
    payout = relationship("ResellerPayout")
    charge = relationship("ResellerTransactionCharge")


class DeviceType(str, enum.Enum):
    TV = "tv"
    CONSOLE = "console"
    LAPTOP = "laptop"
    IOT = "iot"
    OTHER = "other"


class DevicePairing(Base):
    """Tracks companion device pairings (TVs, consoles, etc.) linked to a customer."""
    __tablename__ = "device_pairings"
    __table_args__ = (
        UniqueConstraint("device_mac", "router_id", name="uq_device_mac_per_router"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False, index=True)
    device_mac = Column(String, nullable=False, index=True)
    device_name = Column(String(100), nullable=True)
    device_type = Column(
        Enum(DeviceType, name="devicetype", values_callable=lambda e: [x.value for x in e]),
        nullable=False,
        default=DeviceType.TV,
    )
    router_id = Column(Integer, ForeignKey("routers.id"), nullable=False)
    plan_id = Column(Integer, ForeignKey("plans.id"), nullable=True)
    is_active = Column(Boolean, default=True)
    provisioned_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    customer = relationship("Customer", backref="paired_devices")
    router = relationship("Router")
    plan = relationship("Plan")


class GrowthTarget(Base):
    __tablename__ = "growth_targets"
    id = Column(Integer, primary_key=True, autoincrement=True)
    target_id = Column(String(100), unique=True, nullable=False)
    label = Column(String(255), nullable=False)
    target_value = Column(Float, nullable=False)
    unit = Column(String(50), nullable=False)
    period = Column(String(100), nullable=False)
    inverse = Column(Boolean, default=False, server_default="false")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ReconnectionAttempt(Base):
    """Tracks self-service reconnection attempts for rate limiting and audit."""
    __tablename__ = "reconnection_attempts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    phone = Column(String, nullable=False, index=True)
    mac_address = Column(String, nullable=False, index=True)
    router_id = Column(Integer, ForeignKey("routers.id"), nullable=False)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=True)
    success = Column(Boolean, nullable=False, default=False)
    failure_reason = Column(String(255), nullable=True)
    old_mac_address = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


# ========================================
# LEAD PIPELINE / CRM MODELS
# ========================================

class LeadStage(str, enum.Enum):
    NEW_LEAD = "new_lead"
    CONTACTED = "contacted"
    TALKING = "talking"
    INSTALLATION_HELP = "installation_help"
    SIGNED_UP = "signed_up"
    PAYING = "paying"
    CHURNED = "churned"
    LOST = "lost"


class LeadActivityType(str, enum.Enum):
    NOTE = "note"
    CALL = "call"
    DM = "dm"
    EMAIL = "email"
    MEETING = "meeting"
    STAGE_CHANGE = "stage_change"
    FOLLOWUP_COMPLETED = "followup_completed"
    OTHER = "other"


class LeadSource(Base):
    """Managed list of lead sources for consistent analytics."""
    __tablename__ = "lead_sources"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False, unique=True)
    description = Column(String(255), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True, server_default="true")
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")


class Lead(Base):
    """Tracks potential reseller customers through the sales pipeline."""
    __tablename__ = "leads"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    phone = Column(String(20), nullable=True)
    email = Column(String(255), nullable=True)
    social_platform = Column(String(50), nullable=True)
    social_handle = Column(String(100), nullable=True)
    source_id = Column(Integer, ForeignKey("lead_sources.id"), nullable=True, index=True)
    source_detail = Column(String(500), nullable=True)
    stage = Column(
        Enum(LeadStage, name="leadstage", values_callable=lambda e: [x.value for x in e]),
        nullable=False,
        default=LeadStage.NEW_LEAD,
        server_default="new_lead",
    )
    stage_changed_at = Column(DateTime, default=datetime.utcnow)
    next_followup_at = Column(DateTime, nullable=True, index=True)
    notes = Column(String(2000), nullable=True)
    converted_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    lost_reason = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    owner = relationship("User", foreign_keys=[user_id], backref="leads")
    converted_user = relationship("User", foreign_keys=[converted_user_id])
    source = relationship("LeadSource", backref="leads")
    activities = relationship("LeadActivity", back_populates="lead", order_by="LeadActivity.created_at.desc()")
    follow_ups = relationship("LeadFollowUp", back_populates="lead", order_by="LeadFollowUp.due_at.asc()")


class LeadActivity(Base):
    """Timeline entry recording an interaction or event on a lead."""
    __tablename__ = "lead_activities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    lead_id = Column(Integer, ForeignKey("leads.id", ondelete="CASCADE"), nullable=False, index=True)
    activity_type = Column(
        Enum(LeadActivityType, name="leadactivitytype", values_callable=lambda e: [x.value for x in e]),
        nullable=False,
    )
    description = Column(String(2000), nullable=True)
    old_stage = Column(String(50), nullable=True)
    new_stage = Column(String(50), nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    lead = relationship("Lead", back_populates="activities")
    creator = relationship("User")


class LeadFollowUp(Base):
    """Scheduled follow-up reminder on a lead."""
    __tablename__ = "lead_follow_ups"

    id = Column(Integer, primary_key=True, autoincrement=True)
    lead_id = Column(Integer, ForeignKey("leads.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    due_at = Column(DateTime, nullable=False, index=True)
    is_completed = Column(Boolean, nullable=False, default=False, server_default="false")
    completed_at = Column(DateTime, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    lead = relationship("Lead", back_populates="follow_ups")
    creator = relationship("User")


# ========================================
# ACCESS CREDENTIALS (reseller-managed comp accounts)
# ========================================

class AccessCredStatus(str, enum.Enum):
    ACTIVE = "active"
    REVOKED = "revoked"


class AccessCredential(Base):
    """Persistent username/password credential a reseller hands to someone for free
    hotspot access. Not tied to a Plan, no expiry, single concurrent device enforced
    via ``bound_mac_address`` plus MikroTik ``shared-users=1`` / RADIUS ``Simultaneous-Use``.
    """
    __tablename__ = "access_credentials"
    __table_args__ = (
        UniqueConstraint("router_id", "username", name="uq_access_cred_router_username"),
        Index("idx_access_cred_user", "user_id"),
        Index("idx_access_cred_router", "router_id"),
        Index("idx_access_cred_bound_mac", "bound_mac_address"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    router_id = Column(Integer, ForeignKey("routers.id"), nullable=False)

    username = Column(String(64), nullable=False)
    password = Column(String(128), nullable=False)

    rate_limit = Column(String(50), nullable=True)  # e.g. "5M/2M"; null = no throttle
    data_cap_mb = Column(BigInteger, nullable=True)  # null = unlimited
    label = Column(String(255), nullable=True)

    status = Column(
        Enum(AccessCredStatus, name="accesscredstatus",
             values_callable=lambda e: [x.value for x in e]),
        nullable=False,
        default=AccessCredStatus.ACTIVE,
        server_default="active",
    )

    bound_mac_address = Column(String(50), nullable=True)
    bound_at = Column(DateTime, nullable=True)
    last_login_at = Column(DateTime, nullable=True)
    last_seen_at = Column(DateTime, nullable=True)
    last_seen_ip = Column(String(45), nullable=True)
    total_bytes_in = Column(BigInteger, nullable=False, default=0, server_default="0")
    total_bytes_out = Column(BigInteger, nullable=False, default=0, server_default="0")

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    revoked_at = Column(DateTime, nullable=True)

    user = relationship("User", backref="access_credentials")
    router = relationship("Router")


# ========================================
# SHOP / E-COMMERCE MODELS
# ========================================

class ShopOrderStatus(str, enum.Enum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    PROCESSING = "processing"
    SHIPPED = "shipped"
    DELIVERED = "delivered"
    CANCELLED = "cancelled"


class ShopOrderPaymentStatus(str, enum.Enum):
    UNPAID = "unpaid"
    PAID = "paid"
    REFUNDED = "refunded"


class ShopProduct(Base):
    __tablename__ = "shop_products"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(String(2000), nullable=True)
    price = Column(DECIMAL(10, 2), nullable=False)
    stock_quantity = Column(Integer, default=0, server_default="0")
    image_url = Column(String(500), nullable=True)
    category = Column(String(100), nullable=True)
    is_active = Column(Boolean, default=True, server_default="true", index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship("User", backref="shop_products")
    order_items = relationship("ShopOrderItem", back_populates="product")


class ShopOrder(Base):
    __tablename__ = "shop_orders"

    id = Column(Integer, primary_key=True, autoincrement=True)
    order_number = Column(String(20), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    buyer_name = Column(String(255), nullable=False)
    buyer_phone = Column(String(20), nullable=False)
    buyer_email = Column(String(100), nullable=True)
    delivery_address = Column(String(500), nullable=True)
    total_amount = Column(DECIMAL(10, 2), nullable=False)
    status = Column(
        Enum(ShopOrderStatus, name="shoporderstatus",
             values_callable=lambda e: [x.value for x in e]),
        nullable=False,
        default=ShopOrderStatus.PENDING,
        server_default="pending",
    )
    payment_status = Column(
        Enum(ShopOrderPaymentStatus, name="shoporderpaymentstatus",
             values_callable=lambda e: [x.value for x in e]),
        nullable=False,
        default=ShopOrderPaymentStatus.UNPAID,
        server_default="unpaid",
    )
    mpesa_checkout_request_id = Column(String(255), nullable=True, unique=True, index=True)
    mpesa_receipt_number = Column(String(255), nullable=True)
    notes = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship("User", backref="shop_orders")
    items = relationship("ShopOrderItem", back_populates="order", cascade="all, delete-orphan")
    tracking_history = relationship(
        "ShopOrderTracking", back_populates="order",
        order_by="ShopOrderTracking.created_at.asc()",
    )


class ShopOrderItem(Base):
    __tablename__ = "shop_order_items"

    id = Column(Integer, primary_key=True, autoincrement=True)
    order_id = Column(Integer, ForeignKey("shop_orders.id", ondelete="CASCADE"), nullable=False, index=True)
    product_id = Column(Integer, ForeignKey("shop_products.id"), nullable=True)
    product_name = Column(String(255), nullable=False)
    product_price = Column(DECIMAL(10, 2), nullable=False)
    quantity = Column(Integer, nullable=False)
    subtotal = Column(DECIMAL(10, 2), nullable=False)

    order = relationship("ShopOrder", back_populates="items")
    product = relationship("ShopProduct", back_populates="order_items")


class ShopOrderTracking(Base):
    __tablename__ = "shop_order_tracking"

    id = Column(Integer, primary_key=True, autoincrement=True)
    order_id = Column(Integer, ForeignKey("shop_orders.id", ondelete="CASCADE"), nullable=False, index=True)
    status_label = Column(String(100), nullable=False)
    note = Column(String(500), nullable=True)
    updated_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    order = relationship("ShopOrder", back_populates="tracking_history")
    updated_by = relationship("User", foreign_keys=[updated_by_user_id])
