from sqlalchemy import Column, Integer, String, Enum, DateTime, ForeignKey, Float, Boolean, BigInteger, DECIMAL
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

class PaymentMethod(str, enum.Enum):
    CASH = "cash"
    MOBILE_MONEY = "mobile_money"
    BANK_TRANSFER = "bank_transfer"
    CARD = "card"
    OTHER = "other"

class DurationUnit(str, enum.Enum):
    MINUTES = "MINUTES"
    HOURS = "HOURS"
    DAYS = "DAYS"

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_code = Column(BigInteger, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(Enum(UserRole, name="userrole"), nullable=False)
    organization_name = Column(String, nullable=False)
    business_name = Column(String(255), nullable=True)
    mpesa_shortcode = Column(String(20), nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class Customer(Base):
    __tablename__ = "customers"
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=True)
    phone = Column(String, nullable=False)
    mac_address = Column(String, unique=True)
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
    lipay_tx_no = Column(String(255), nullable=True)  # <-- Add this line
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
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)
    paid_on = Column(DateTime, default=datetime.utcnow)
    expires_on = Column(DateTime)
    plan_type = Column(String, nullable=False)
    cost = Column(Float, nullable=False)

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

class ProvisioningLog(Base):
    __tablename__ = "provisioning_logs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)
    router_id = Column(Integer, ForeignKey("routers.id"), nullable=True)
    mac_address = Column(String(50), nullable=True)
    action = Column(String, nullable=False)
    status = Column(String, nullable=False)
    error = Column(String(255))
    details = Column(String(255))
    log_date = Column(DateTime, default=datetime.utcnow)

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

class AdBadgeType(str, enum.Enum):
    HOT = "hot"
    NEW = "new"
    SALE = "sale"

class AdClickType(str, enum.Enum):
    VIEW_DETAILS = "view_details"
    CALL = "call"
    WHATSAPP = "whatsapp"

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
