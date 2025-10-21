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

class UserRole(str, enum.Enum):
    ADMIN = "admin"
    RESELLER = "reseller"

class ConnectionType(str, enum.Enum):
    HOTSPOT = "hotspot"
    PPPOE = "pppoe"
    STATIC_IP = "static_ip"

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
    ip_address = Column(String, nullable=False)
    username = Column(String, nullable=False)
    password = Column(String, nullable=False)
    port = Column(Integer, nullable=False, default=8728)
    created_at = Column(DateTime, default=datetime.utcnow)

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
    transaction_date = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

