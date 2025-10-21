import strawberry
from typing import Optional, List
from datetime import datetime

@strawberry.type
class UserType:
    id: int
    email: Optional[str]  # Changed from str to Optional[str]
    role: str
    organization_name: Optional[str]
    user_code: int

@strawberry.type
class PlanType:
    id: int
    name: str
    speed: str
    price: int
    duration_value: int  # Duration in either hours or days
    duration_unit: str  # Either "HOURS" or "DAYS"
    connection_type: str

@strawberry.type
class CustomerType:
    id: int
    name: Optional[str] = None
    phone: str
    mac_address: Optional[str]
    pppoe_username: Optional[str]
    static_ip: Optional[str]
    status: str
    expiry: Optional[float]
    plan: Optional[PlanType]

@strawberry.type
class PaymentType:
    id: int
    amount: int
    days_paid_for: int
    paid_on: str

@strawberry.type
class CustomerPaymentType:
    id: int
    customer_id: int
    customer_name: str
    amount: float
    payment_method: str
    payment_reference: Optional[str]
    payment_date: str
    days_paid_for: int
    status: str
    notes: Optional[str]

@strawberry.type
class ResellerFinancialSummary:
    total_revenue: float
    total_customers: int
    active_customers: int
    last_payment_date: Optional[str]
    monthly_revenue: float
    this_month_customers: int

@strawberry.type
class PaymentSummary:
    today: float
    this_week: float
    this_month: float
    total: float
    today_count: int
    week_count: int
    month_count: int

@strawberry.type
class SubscriptionType:
    id: int
    is_active: bool
    paid_on: str
    expires_on: Optional[str]
    plan_type: str
    cost: float

@strawberry.type
class DashboardMetricsType:
    total_customers: int
    active_customers: int
    inactive_customers: int
    total_revenue: int
    expiring_soon: int
    subscription_days_left: int

@strawberry.type
class PlanMetricsType:
    plan_id: int
    plan_name: str
    customer_count: int
    total_revenue: int

@strawberry.type
class RouterType:
    id: int
    name: str
    ip_address: str
    port: int

@strawberry.type
class ProvisioningLogType:
    id: int
    router_id: int
    customer_id: Optional[int]
    action: str
    status: str
    details: str
    mac_address: Optional[str]
    log_date: str