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
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)
    reseller_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    amount = Column(Float, nullable=False)
    payment_method = Column(Enum(PaymentMethod), nullable=False, default=PaymentMethod.CASH)
    payment_reference = Column(String(100), nullable=True)
    payment_date = Column(DateTime, default=datetime.utcnow)
    days_paid_for = Column(Integer, nullable=False)
    status = Column(Enum(PaymentStatus), default=PaymentStatus.COMPLETED)
    notes = Column(String(500), nullable=True)
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
    active_queues = Column(Integer, default=0)
    active_sessions = Column(Integer, default=0)
    # Interface-based counters for accurate averaging
    interface_rx_bytes = Column(BigInteger, default=0)
    interface_tx_bytes = Column(BigInteger, default=0)
    recorded_at = Column(DateTime, default=datetime.utcnow, index=True)


class UserBandwidthUsage(Base):
    """Track cumulative bandwidth usage per user for top downloaders"""
    __tablename__ = "user_bandwidth_usage"
    id = Column(Integer, primary_key=True, autoincrement=True)
    mac_address = Column(String(50), index=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=True)
    queue_name = Column(String(100))
    target_ip = Column(String(50))
    upload_bytes = Column(BigInteger, default=0)
    download_bytes = Column(BigInteger, default=0)
    max_limit = Column(String(50))
    last_updated = Column(DateTime, default=datetime.utcnow, index=True)


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
    code = Column(String(9), unique=True, nullable=False, index=True)  # XXXX-XXXX
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
    router_id = Column(Integer, ForeignKey("routers.id", ondelete="CASCADE"), nullable=False, index=True)
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


class ZenoPayTransactionStatus(str, enum.Enum):
    PENDING = "pending"
    COMPLETED = "completed"
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
