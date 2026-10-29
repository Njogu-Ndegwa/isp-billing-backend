"""Staff permissions: the catalog, the presets, and which routes each one opens.

A staff token authenticates as the owning reseller (so every existing endpoint
scopes data to the owner unchanged) and ``enforce_staff_access`` looks the
request up here before the handler runs. The rule is DENY BY DEFAULT: a route
that is not listed below is refused for every staff member, so an endpoint
added later stays owner-only until someone deliberately grants it here.

Each rule is (methods, path template, requirement, summary):

* requirement is a permission key, a tuple of keys (any one is enough), or
  ``ANY_STAFF`` for harmless reads every staff member needs (plan and router
  pickers, their own identity);
* the template uses FastAPI's syntax (``{router_id}``, ``{rest:path}``); when
  two templates match, the one with more literal segments wins, so
  ``/api/customers/usage/bulk`` beats ``/api/customers/{customer_id}``;
* summary is the human line written to the activity log for writes.

``staff.manage`` is owner-only and can never be granted: no rule references it
and ``clean_permissions`` strips it from anything an owner submits.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional, Union

ANY_STAFF = "__any_staff__"

STAFF_MANAGE = "staff.manage"

# key -> (label, description, group, sensitive)
PERMISSIONS: dict[str, tuple[str, str, str, bool]] = {
    "dashboard.view": (
        "View dashboard", "Revenue and usage overview on the dashboard.", "General", False),
    "customers.view": (
        "View customers", "Customer list, details, usage, devices and history.", "Customers", False),
    "customers.manage": (
        "Manage customers",
        "Add, edit, delete, suspend and reconnect customers, change expiry and grace, "
        "outage compensation and access credentials.",
        "Customers", False),
    "plans.manage": (
        "Manage plans", "Create, edit and delete plans; emergency mode.", "Customers", False),
    "vouchers.generate": (
        "Vouchers", "Generate, download and disable vouchers.", "Customers", False),
    "routers.view": (
        "View routers", "Router list, status, live users, logs and read-only diagnostics.",
        "Routers", False),
    "routers.manage": (
        "Manage routers",
        "Add, edit, reboot and repair routers, ports, load balancing, walled garden, "
        "remote access and WebFig.",
        "Routers", False),
    "transactions.view": (
        "View transactions", "Payment transactions and unmatched paybill payments.",
        "Money", False),
    "transactions.manage": (
        "Fix payments",
        "Attribute unmatched paybill payments to customers and manually provision paid "
        "transactions.",
        "Money", True),
    "account_statement.view": (
        "View account statement", "Balance, payouts and statement.", "Money", False),
    "money.withdraw": (
        "Withdraw money", "Request a withdrawal of the account balance.", "Money", True),
    "payment_methods.manage": (
        "Manage payment methods",
        "Add or change where customer payments go (paybill, till, bank), payout settings "
        "and which payment method each router uses.",
        "Money", True),
    "settlement.manage": (
        "Change settlement mode", "Switch between direct and platform settlement.",
        "Money", True),
    "subscription.manage": (
        "Manage subscription", "View invoices and pay the Bitwave subscription and SMS credits.",
        "Money", True),
    "messaging.send": (
        "Send SMS", "Send SMS to customers, templates and campaigns.", "Messaging", False),
    "messaging.settings": (
        "SMS settings", "Automatic customer SMS, expiry reminders and SMS provider accounts.",
        "Messaging", False),
    "portal.manage": (
        "Captive portal", "Portal customization and portal ads.", "Settings", False),
}

SENSITIVE_PERMISSIONS = frozenset(k for k, v in PERMISSIONS.items() if v[3])

PRESETS: list[dict] = [
    {
        "key": "technician",
        "label": "Technician",
        "description": "Routers and read-only customers.",
        "permissions": ["routers.view", "routers.manage", "customers.view"],
    },
    {
        "key": "cashier",
        "label": "Cashier",
        "description": "Customers, vouchers and transactions (read-only money).",
        "permissions": ["customers.view", "vouchers.generate", "transactions.view"],
    },
    {
        "key": "manager",
        "label": "Manager",
        "description": "Everything except money movement and payment settings.",
        "permissions": [k for k, v in PERMISSIONS.items() if not v[3]],
    },
]


def clean_permissions(values: Optional[Iterable[str]]) -> list[str]:
    """Known, grantable permission keys from ``values``, de-duplicated, catalog order.

    Unknown keys and ``staff.manage`` are dropped silently -- never grantable.
    """
    wanted = {str(v).strip() for v in (values or []) if v is not None}
    return [k for k in PERMISSIONS if k in wanted]


def unknown_permissions(values: Optional[Iterable[str]]) -> list[str]:
    return sorted(
        {str(v).strip() for v in (values or []) if v is not None}
        - set(PERMISSIONS)
    )


def catalog() -> dict:
    return {
        "permissions": [
            {"key": k, "label": label, "description": desc, "group": group, "sensitive": sens}
            for k, (label, desc, group, sens) in PERMISSIONS.items()
        ],
        "presets": PRESETS,
        "owner_only": [STAFF_MANAGE],
    }


# ---------------------------------------------------------------------------
# Route rules
# ---------------------------------------------------------------------------

Requirement = Union[str, tuple]

R = "GET"
W_ALL = ("POST", "PUT", "PATCH", "DELETE")
ALL = ("GET", "POST", "PUT", "PATCH", "DELETE")

_RULES_SPEC: list[tuple[tuple, str, Requirement, Optional[str]]] = [
    # --- every staff member -------------------------------------------------
    ((R,), "/api/staff/me", ANY_STAFF, None),
    ((R,), "/api/profile", ANY_STAFF, None),
    ((R,), "/api/subscription", ANY_STAFF, None),
    ((R,), "/api/plans", ("plans.manage", "customers.view", "customers.manage", "vouchers.generate", "routers.view", "routers.manage", "portal.manage"), None),
    ((R,), "/api/plans/by-router/{router_id}", ("plans.manage", "customers.view", "customers.manage", "vouchers.generate", "routers.view", "routers.manage", "portal.manage"), None),
    ((R,), "/api/routers", ("routers.view", "routers.manage", "customers.view", "customers.manage", "plans.manage", "vouchers.generate", "messaging.send", "portal.manage", "dashboard.view"), None),

    # --- dashboard ----------------------------------------------------------
    ((R,), "/api/dashboard/overview", "dashboard.view", None),
    ((R,), "/api/dashboard/stats", "dashboard.view", None),
    ((R,), "/api/dashboard/analytics", "dashboard.view", None),
    ((R,), "/api/dashboard/daily-revenue", "dashboard.view", None),
    ((R,), "/api/dashboard/revenue-over-time", "dashboard.view", None),
    ((R,), "/api/dashboard/transactions-daily", "dashboard.view", None),
    ((R,), "/api/plans/performance", "dashboard.view", None),

    # --- customers: read ----------------------------------------------------
    ((R,), "/api/customers", "customers.view", None),
    ((R,), "/api/customers/active", "customers.view", None),
    ((R,), "/api/customers/map", "customers.view", None),
    ((R,), "/api/customers/{customer_id}", "customers.view", None),
    ((R,), "/api/customers/{customer_id}/audit-log", "customers.view", None),
    (("POST",), "/api/customers/{customer_id}/audit-log/router-logs", "customers.view",
     "Read router logs for customer {customer_id}"),
    ((R,), "/api/customers/{customer_id}/devices", "customers.view", None),
    ((R,), "/api/customers/{customer_id}/payment-summary", "customers.view", None),
    ((R,), "/api/customers/{customer_id}/static/status", "customers.view", None),
    ((R,), "/api/customers/{customer_id}/usage", "customers.view", None),
    ((R,), "/api/customers/{customer_id}/usage/history", "customers.view", None),
    ((R,), "/api/customers/{customer_id}/usage/timeline", "customers.view", None),
    (("POST",), "/api/customers/usage/bulk", "customers.view", None),
    ((R,), "/api/pppoe/customers/{customer_id}/presence", "customers.view", None),
    ((R,), "/api/session-monitor", "customers.view", None),
    ((R,), "/api/session-monitor/customer/{customer_id}", "customers.view", None),
    ((R,), "/api/realtime/customers/online", "customers.view", None),
    ((R,), "/api/resellers/me/usage/top", "customers.view", None),
    ((R,), "/api/ratings", "customers.view", None),
    ((R,), "/api/ratings/by-location", "customers.view", None),
    ((R,), "/api/ratings/summary", "customers.view", None),
    ((R,), "/api/access-credentials", "customers.view", None),
    ((R,), "/api/access-credentials/{cred_id}", "customers.view", None),
    ((R,), "/api/compensation/outage/history", "customers.view", None),
    ((R,), "/api/compensation/outage/{compensation_id}", "customers.view", None),
    (("POST",), "/api/compensation/outage/preview", "customers.view", None),

    # --- customers: write ---------------------------------------------------
    (("POST",), "/api/customers/register", "customers.manage", "Added a customer"),
    (("PUT",), "/api/customers/{customer_id}", "customers.manage",
     "Edited customer {customer_id}"),
    (("DELETE",), "/api/customers/{customer_id}", "customers.manage",
     "Deleted customer {customer_id}"),
    (("POST",), "/api/customers/{customer_id}/activate-pppoe", "customers.manage",
     "Activated PPPoE customer {customer_id}"),
    (("POST",), "/api/customers/{customer_id}/deactivate-pppoe", "customers.manage",
     "Deactivated PPPoE customer {customer_id}"),
    (("POST",), "/api/customers/{customer_id}/activate-static", "customers.manage",
     "Activated static customer {customer_id}"),
    (("POST",), "/api/customers/{customer_id}/suspend-static", "customers.manage",
     "Suspended static customer {customer_id}"),
    (("POST",), "/api/customers/{customer_id}/resume-static", "customers.manage",
     "Resumed static customer {customer_id}"),
    (("POST",), "/api/customers/{customer_id}/pause", "customers.manage",
     "Paused customer {customer_id}"),
    (("POST",), "/api/customers/{customer_id}/resume", "customers.manage",
     "Resumed customer {customer_id}"),
    (("POST",), "/api/customers/{customer_id}/static/pin", "customers.manage",
     "Pinned static IP for customer {customer_id}"),
    (("POST",), "/api/customers/{customer_id}/static/sync", "customers.manage",
     "Synced static customer {customer_id}"),
    (("POST",), "/api/customers/{customer_id}/regenerate-pppoe-password", "customers.manage",
     "Regenerated PPPoE password for customer {customer_id}"),
    (("POST",), "/api/customers/{customer_id}/reset-session", "customers.manage",
     "Reset session for customer {customer_id}"),
    (("POST",), "/api/customers/{customer_id}/location", "customers.manage",
     "Set location for customer {customer_id}"),
    (("POST",), "/api/customers/location/by-phone", "customers.manage",
     "Set a customer location by phone"),
    (("PUT",), "/api/customers/{customer_id}/device-limit", "customers.manage",
     "Changed device limit for customer {customer_id}"),
    (("PUT",), "/api/customers/{customer_id}/grace-period", "customers.manage",
     "Changed grace period for customer {customer_id}"),
    (("POST",), "/api/customers/{customer_id}/devices", "customers.manage",
     "Added a device to customer {customer_id}"),
    (("DELETE",), "/api/customers/{customer_id}/devices/{pairing_id}", "customers.manage",
     "Removed a device from customer {customer_id}"),
    ((R,), "/api/customers/{customer_id}/pppoe-credentials", "customers.manage", None),
    ((R, "POST", "DELETE"), "/api/remove-user/{router_id}/{mac_address}", "customers.manage",
     "Removed device {mac_address} from router {router_id}"),
    (("POST",), "/api/mpesa/initiate-payment", "customers.manage",
     "Sent an M-Pesa payment prompt to a customer"),
    (("POST",), "/api/access-credentials", "customers.manage", "Created an access credential"),
    (("PATCH",), "/api/access-credentials/{cred_id}", "customers.manage",
     "Edited access credential {cred_id}"),
    (("DELETE",), "/api/access-credentials/{cred_id}", "customers.manage",
     "Deleted access credential {cred_id}"),
    (("POST",), "/api/access-credentials/{cred_id}/force-logout", "customers.manage",
     "Logged out access credential {cred_id}"),
    (("POST",), "/api/access-credentials/{cred_id}/restore", "customers.manage",
     "Restored access credential {cred_id}"),
    (("POST",), "/api/access-credentials/{cred_id}/revoke", "customers.manage",
     "Revoked access credential {cred_id}"),
    (("POST",), "/api/access-credentials/{cred_id}/rotate-password", "customers.manage",
     "Rotated password of access credential {cred_id}"),
    (("POST",), "/api/access-credentials/{cred_id}/sync", "customers.manage",
     "Synced access credential {cred_id}"),
    (("POST",), "/api/compensation/outage", "customers.manage", "Gave outage compensation"),
    (("POST",), "/api/compensation/outage/{compensation_id}/retry-provisioning",
     "customers.manage", "Retried compensation {compensation_id}"),
    (("POST",), "/api/routers/{router_id}/pppoe-customers/import", "customers.manage",
     "Imported PPPoE customers on router {router_id}"),
    (("POST",), "/api/routers/{source_router_id}/pppoe-customers/transfer", "customers.manage",
     "Transferred PPPoE customers from router {source_router_id}"),
    (("POST",), "/api/routers/{router_id}/static-customers/import", "customers.manage",
     "Imported static customers on router {router_id}"),
    ((R,), "/api/static-customers/import-template", "customers.manage", None),

    # --- plans --------------------------------------------------------------
    (("POST",), "/api/plans/create", "plans.manage", "Created a plan"),
    (("PUT",), "/api/plans/{plan_id}", "plans.manage", "Edited plan {plan_id}"),
    (("DELETE",), "/api/plans/{plan_id}", "plans.manage", "Deleted plan {plan_id}"),
    (("POST",), "/api/plans/activate-emergency", "plans.manage", "Turned emergency mode on"),
    (("POST",), "/api/plans/deactivate-emergency", "plans.manage", "Turned emergency mode off"),

    # --- vouchers -----------------------------------------------------------
    ((R,), "/api/vouchers", "vouchers.generate", None),
    ((R,), "/api/vouchers/stats", "vouchers.generate", None),
    ((R,), "/api/vouchers/download", "vouchers.generate", None),
    ((R,), "/api/vouchers/compensation-allowance", "vouchers.generate", None),
    (("POST",), "/api/vouchers/generate", "vouchers.generate", "Generated vouchers"),
    (("PATCH",), "/api/vouchers/{voucher_id}/disable", "vouchers.generate",
     "Disabled voucher {voucher_id}"),

    # --- routers: read ------------------------------------------------------
    ((R,), "/api/routers/{router_id}/uptime", "routers.view", None),
    ((R,), "/api/routers/{router_id}/live", "routers.view", None),
    ((R,), "/api/routers/{router_id}/bandwidth-check", "routers.view", None),
    ((R,), "/api/routers/{router_id}/diagnose/{mac_address}", "routers.view", None),
    ((R,), "/api/routers/{router_id}/illegal-connections", "routers.view", None),
    ((R,), "/api/routers/{router_id}/interfaces", "routers.view", None),
    ((R,), "/api/routers/{router_id}/interfaces/restart-options", "routers.view", None),
    ((R,), "/api/routers/{router_id}/access-points", "routers.view", None),
    ((R,), "/api/routers/{router_id}/access-points/{ap_mac}/status", "routers.view", None),
    ((R,), "/api/routers/{router_id}/load-balancing", "routers.view", None),
    ((R,), "/api/routers/{router_id}/port-analytics", "routers.view", None),
    ((R,), "/api/routers/{router_id}/port-config-jobs/{job_id}", "routers.view", None),
    ((R,), "/api/routers/{router_id}/ports", "routers.view", None),
    ((R,), "/api/routers/{router_id}/users", "routers.view", None),
    ((R,), "/api/router_stats/{router_id}", "routers.view", None),
    ((R,), "/api/routers/by-identity/{identity}", "routers.view", None),
    ((R,), "/api/routers/by-identity/{identity}/device-mode", "routers.view", None),
    ((R,), "/api/routers/by-identity/{identity}/files", "routers.view", None),
    ((R,), "/api/routers/by-identity/{identity}/hotspot-diagnostics", "routers.view", None),
    ((R,), "/api/hotspot/{router_id}/logs", "routers.view", None),
    ((R,), "/api/hotspot/{router_id}/overview", "routers.view", None),
    ((R,), "/api/hotspot/{router_id}/users", "routers.view", None),
    ((R,), "/api/pppoe/{router_id}/client-details/{username}", "routers.view", None),
    ((R,), "/api/pppoe/{router_id}/diagnose/{username}", "routers.view", None),
    ((R,), "/api/pppoe/{router_id}/logs", "routers.view", None),
    ((R,), "/api/pppoe/{router_id}/overview", "routers.view", None),
    ((R,), "/api/pppoe/{router_id}/users", "routers.view", None),
    ((R,), "/api/mikrotik/active-sessions", "routers.view", None),
    ((R,), "/api/mikrotik/bandwidth-history", "routers.view", None),
    ((R,), "/api/mikrotik/health", "routers.view", None),
    ((R,), "/api/mikrotik/top-users", "routers.view", None),
    ((R,), "/api/mikrotik/traffic", "routers.view", None),
    ((R,), "/api/mikrotik/walled-garden", "routers.view", None),
    ((R,), "/api/mikrotik/{router_id}/pppoe/active", "routers.view", None),
    ((R,), "/api/dashboard/mikrotik", "routers.view", None),
    ((R,), "/api/realtime/routers", "routers.view", None),
    ((R,), "/api/session-monitor/router/{router_id}", "routers.view", None),

    # --- routers: write (includes diagnostics that change things, WebFig) --
    (("POST",), "/api/routers/create", "routers.manage", "Added a router"),
    (("PUT",), "/api/routers/{router_id}", "routers.manage", "Edited router {router_id}"),
    (("DELETE",), "/api/routers/{router_id}", "routers.manage", "Deleted router {router_id}"),
    (("PUT",), "/api/routers/{router_id}/identity", "routers.manage",
     "Renamed router {router_id}"),
    (("PUT",), "/api/routers/{router_id}/status-alerts", "routers.manage",
     "Changed status alerts on router {router_id}"),
    (("POST",), "/api/routers/{router_id}/remediate-captive-portal", "routers.manage",
     "Repaired captive portal on router {router_id}"),
    (("POST",), "/api/routers/anti-tethering/enable", "routers.manage",
     "Turned anti-tethering on"),
    (("POST",), "/api/routers/anti-tethering/disable", "routers.manage",
     "Turned anti-tethering off"),
    (("POST",), "/api/routers/{router_id}/apply-access-defaults", "routers.manage",
     "Applied access defaults on router {router_id}"),
    (("POST",), "/api/routers/{router_id}/cleanup-bypassing", "routers.manage",
     "Cleaned bypassing users on router {router_id}"),
    (("POST",), "/api/routers/{router_id}/cleanup-expired", "routers.manage",
     "Cleaned expired users on router {router_id}"),
    (("POST",), "/api/routers/{router_id}/diagnose/dual-port", "routers.manage",
     "Ran dual-port diagnosis on router {router_id}"),
    (("POST",), "/api/routers/{router_id}/heal-dual-mode", "routers.manage",
     "Healed dual mode on router {router_id}"),
    (("POST",), "/api/routers/{router_id}/reboot", "routers.manage",
     "Rebooted router {router_id}"),
    (("POST",), "/api/routers/{router_id}/interfaces/{interface_name}/restart", "routers.manage",
     "Restarted port {interface_name} on router {router_id}"),
    (("PUT",), "/api/routers/{router_id}/access-points/{ap_mac}/credential", "routers.manage",
     "Saved access-point password for {ap_mac} on router {router_id}"),
    (("DELETE",), "/api/routers/{router_id}/access-points/{ap_mac}/credential", "routers.manage",
     "Removed access-point password for {ap_mac} on router {router_id}"),
    (("POST",), "/api/routers/{router_id}/access-points/{ap_mac}/reboot", "routers.manage",
     "Rebooted access point {ap_mac} on router {router_id}"),
    (("POST",), "/api/routers/{router_id}/access-points/{ap_mac}/make-safe", "routers.manage",
     "Made access point {ap_mac} a safe AP on router {router_id}"),
    (("POST",), "/api/routers/{router_id}/remove-illegal-users", "routers.manage",
     "Removed illegal users on router {router_id}"),
    (("POST",), "/api/routers/{router_id}/sync", "routers.manage",
     "Synced router {router_id}"),
    (("PUT",), "/api/routers/{router_id}/dual-ports", "routers.manage",
     "Changed dual ports on router {router_id}"),
    (("PUT",), "/api/routers/{router_id}/plain-ports", "routers.manage",
     "Changed plain ports on router {router_id}"),
    (("PUT",), "/api/routers/{router_id}/pppoe-ports", "routers.manage",
     "Changed PPPoE ports on router {router_id}"),
    (("DELETE",), "/api/routers/{router_id}/force-remove/{mac_address}", "routers.manage",
     "Force-removed {mac_address} from router {router_id}"),
    (("DELETE",), "/api/routers/{router_id}/remove-illegal-user/{mac_address}",
     "routers.manage", "Removed illegal user {mac_address} from router {router_id}"),
    (("DELETE",), "/api/routers/{router_id}/users/{username}", "routers.manage",
     "Removed user {username} from router {router_id}"),
    (("POST",), "/api/routers/{router_id}/load-balancing/enable", "routers.manage",
     "Turned load balancing on for router {router_id}"),
    (("POST",), "/api/routers/{router_id}/load-balancing/disable", "routers.manage",
     "Turned load balancing off for router {router_id}"),
    (("POST",), "/api/routers/{router_id}/load-balancing/preflight", "routers.manage",
     "Checked load balancing on router {router_id}"),
    (("POST",), "/api/routers/{router_id}/load-balancing/verify", "routers.manage",
     "Verified load balancing on router {router_id}"),
    (("POST",), "/api/routers/by-identity/{identity}/device-mode", "routers.manage",
     "Changed device mode on router {identity}"),
    (("POST",), "/api/routers/by-identity/{identity}/sync-hotspot-files", "routers.manage",
     "Synced hotspot files on router {identity}"),
    (("POST",), "/api/routers/by-identity/{identity}/winbox-access", "routers.manage",
     "Opened WinBox access on router {identity}"),
    (("POST",), "/api/mikrotik/walled-garden/domain", "routers.manage",
     "Added a walled-garden domain"),
    (("DELETE",), "/api/mikrotik/walled-garden/domain/{entry_id}", "routers.manage",
     "Removed a walled-garden domain"),
    (("POST",), "/api/mikrotik/walled-garden/ip", "routers.manage",
     "Added a walled-garden IP"),
    (("DELETE",), "/api/mikrotik/walled-garden/ip/{entry_id}", "routers.manage",
     "Removed a walled-garden IP"),
    (("POST",), "/api/mikrotik/wireguard/update-endpoint", "routers.manage",
     "Updated a WireGuard endpoint"),
    ((R,), "/api/pppoe/{router_id}/secrets", "routers.manage", None),
    (("DELETE",), "/api/pppoe/{router_id}/users/{username}", "routers.manage",
     "Disconnected PPPoE user {username} on router {router_id}"),
    ((R,), "/api/admin/routers/{router_id}/remote-access", "routers.manage", None),
    (("POST",), "/api/admin/routers/{router_id}/remote-access", "routers.manage",
     "Changed remote access on router {router_id}"),
    (("POST",), "/api/admin/routers/{router_id}/webfig/open", "routers.manage",
     "Opened WebFig on router {router_id}"),
    (("POST",), "/api/admin/routers/{router_id}/webfig/close", "routers.manage",
     "Closed WebFig on router {router_id}"),
    (ALL, "/api/admin/routers/{router_id}/webfig", "routers.manage", None),
    (ALL, "/api/admin/routers/{router_id}/webfig/{proxy_path:path}", "routers.manage", None),
    (("POST",), "/api/provision/create", "routers.manage", "Started adding a router"),
    ((R,), "/api/provision/tokens", "routers.manage", None),

    # --- transactions -------------------------------------------------------
    ((R,), "/api/mpesa/transactions", "transactions.view", None),
    ((R,), "/api/mpesa/transactions/failed", "transactions.view", None),
    ((R,), "/api/mpesa/transactions/summary", "transactions.view", None),
    ((R,), "/api/c2b/unmatched", "transactions.view", None),
    (("POST",), "/api/c2b/unmatched/{unmatched_id}/attribute", "transactions.manage",
     "Attributed unmatched payment {unmatched_id}"),
    (("POST",), "/api/transactions/{payment_method}/{transaction_id}/manual-provision",
     "transactions.manage", "Manually provisioned transaction {transaction_id}"),

    # --- money and payment settings ----------------------------------------
    ((R,), "/api/reseller/account-statement", "account_statement.view", None),
    ((R,), "/api/reseller/payout-settings", "account_statement.view", None),
    (("POST",), "/api/reseller/withdraw", "money.withdraw", "Requested a withdrawal"),
    (("PUT",), "/api/reseller/payout-settings", "payment_methods.manage",
     "Changed payout settings"),
    (("PUT",), "/api/reseller/settlement-mode", "settlement.manage",
     "Changed settlement mode"),
    ((R,), "/api/payment-methods", "payment_methods.manage", None),
    (("POST",), "/api/payment-methods", "payment_methods.manage", "Added a payment method"),
    ((R,), "/api/payment-methods/{method_id}", "payment_methods.manage", None),
    (("PUT",), "/api/payment-methods/{method_id}", "payment_methods.manage",
     "Edited payment method {method_id}"),
    (("DELETE",), "/api/payment-methods/{method_id}", "payment_methods.manage",
     "Deleted payment method {method_id}"),
    (("POST",), "/api/payment-methods/{method_id}/register-c2b", "payment_methods.manage",
     "Registered paybill URLs for payment method {method_id}"),
    (("POST",), "/api/payment-methods/{method_id}/test", "payment_methods.manage",
     "Tested payment method {method_id}"),
    (("PUT",), "/api/routers/{router_id}/payment-method", "payment_methods.manage",
     "Changed the payment method of router {router_id}"),

    # --- subscription -------------------------------------------------------
    ((R,), "/api/subscription/current-invoice", "subscription.manage", None),
    ((R,), "/api/subscription/invoices", "subscription.manage", None),
    ((R,), "/api/subscription/invoices/{invoice_id}", "subscription.manage", None),
    ((R,), "/api/subscription/payments", "subscription.manage", None),
    (("POST",), "/api/subscription/pay", "subscription.manage", "Paid the subscription"),
    (("POST",), "/api/subscription/pay-card", "subscription.manage",
     "Paid the subscription by card"),
    (("POST",), "/api/subscription/request-invoice", "subscription.manage",
     "Requested a subscription invoice"),
    (("POST",), "/api/messaging/credits/purchase", "subscription.manage",
     "Bought SMS credits"),

    # --- messaging ----------------------------------------------------------
    ((R,), "/api/messaging/campaigns", "messaging.send", None),
    ((R,), "/api/messaging/campaigns/{campaign_id}", "messaging.send", None),
    ((R,), "/api/messaging/credits", "messaging.send", None),
    ((R,), "/api/messaging/credits/ledger", "messaging.send", None),
    ((R,), "/api/messaging/recipients", "messaging.send", None),
    ((R,), "/api/messaging/templates", "messaging.send", None),
    ((R,), "/api/messaging/gateway/status", ("messaging.send", "messaging.settings"), None),
    (("POST",), "/api/messaging/send", "messaging.send", "Sent an SMS campaign"),
    (("POST",), "/api/messaging/templates", "messaging.send", "Saved an SMS template"),
    (("DELETE",), "/api/messaging/templates/{template_id}", "messaging.send",
     "Deleted SMS template {template_id}"),
    (("POST",), "/api/messaging/customer-events/preview", "messaging.settings", None),
    ((R,), "/api/messaging/customer-events", "messaging.settings", None),
    (("PUT",), "/api/messaging/customer-events", "messaging.settings",
     "Changed automatic customer SMS"),
    ((R,), "/api/messaging/expiry-settings", "messaging.settings", None),
    (("PUT",), "/api/messaging/expiry-settings", "messaging.settings",
     "Changed expiry SMS settings"),
    ((R,), "/api/messaging/providers", "messaging.settings", None),
    ((R,), "/api/messaging/provider-accounts", "messaging.settings", None),
    (("POST",), "/api/messaging/provider-accounts", "messaging.settings",
     "Added an SMS provider account"),
    (("PUT",), "/api/messaging/provider-accounts/{account_id}", "messaging.settings",
     "Edited SMS provider account {account_id}"),
    (("DELETE",), "/api/messaging/provider-accounts/{account_id}", "messaging.settings",
     "Deleted SMS provider account {account_id}"),
    (("POST",), "/api/messaging/provider-accounts/{account_id}/test", "messaging.settings",
     "Tested SMS provider account {account_id}"),

    # --- captive portal -----------------------------------------------------
    ((R,), "/api/portal/settings", "portal.manage", None),
    (("PUT",), "/api/portal/settings", "portal.manage", "Changed portal settings"),
    (("POST",), "/api/portal/settings/reset", "portal.manage", "Reset portal settings"),
    ((R,), "/api/ads", "portal.manage", None),
    (("POST",), "/api/ads", "portal.manage", "Created a portal ad"),
    ((R,), "/api/ads/analytics", "portal.manage", None),
    (("PUT",), "/api/ads/{ad_id}", "portal.manage", "Edited portal ad {ad_id}"),
    (("DELETE",), "/api/ads/{ad_id}", "portal.manage", "Deleted portal ad {ad_id}"),
    ((R,), "/api/ads/{ad_id}/clicks", "portal.manage", None),
    ((R,), "/api/ads/{ad_id}/impressions", "portal.manage", None),
    ((R,), "/api/advertisers", "portal.manage", None),
    (("POST",), "/api/advertisers", "portal.manage", "Added an advertiser"),
]

# Endpoints that never need a user token: a staff token sent to them grants
# nothing beyond what an anonymous caller already has, so let them through.
PUBLIC_PREFIXES = ("/api/public/",)
PUBLIC_PATHS = frozenset({
    "/health", "/api/users/register", "/api/auth/login",
    "/api/auth/forgot-password", "/api/auth/reset-password",
})

# Writes by ANYONE (owner or staff) to these get an activity row and an owner
# alert, because they change where money goes. Keyed by rule template.
OWNER_ALERT_TEMPLATES = frozenset({
    "/api/payment-methods",
    "/api/payment-methods/{method_id}",
    "/api/routers/{router_id}/payment-method",
    "/api/reseller/payout-settings",
    "/api/reseller/settlement-mode",
})
# Writes by the OWNER to these are logged too (staff writes are always logged).
OWNER_LOGGED_TEMPLATES = OWNER_ALERT_TEMPLATES | frozenset({
    "/api/payment-methods/{method_id}/register-c2b",
    "/api/reseller/withdraw",
    # Port restarts drop customers for a few seconds: keep who/when/how.
    "/api/routers/{router_id}/interfaces/{interface_name}/restart",
    # AP control reboots / reconfigures a customer's access point: keep a record.
    "/api/routers/{router_id}/access-points/{ap_mac}/reboot",
    "/api/routers/{router_id}/access-points/{ap_mac}/make-safe",
    "/api/routers/{router_id}/access-points/{ap_mac}/credential",
})


@dataclass(frozen=True)
class Rule:
    methods: frozenset
    template: str
    requirement: Requirement
    summary: Optional[str]
    regex: re.Pattern
    literal_segments: int

    def allows(self, permissions: Iterable[str]) -> bool:
        if self.requirement == ANY_STAFF:
            return True
        granted = set(permissions)
        if isinstance(self.requirement, tuple):
            return any(r in granted for r in self.requirement)
        return self.requirement in granted

    @property
    def permission_label(self) -> Optional[str]:
        if self.requirement == ANY_STAFF:
            return None
        if isinstance(self.requirement, tuple):
            return self.requirement[0]
        return self.requirement


_PARAM = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)(:path)?\}")


def _compile(template: str) -> re.Pattern:
    out, pos = [], 0
    for m in _PARAM.finditer(template):
        out.append(re.escape(template[pos:m.start()]))
        name, is_path = m.group(1), m.group(2)
        out.append(f"(?P<{name}>.+)" if is_path else f"(?P<{name}>[^/]+)")
        pos = m.end()
    out.append(re.escape(template[pos:]))
    return re.compile("".join(out))


def _literal_segments(template: str) -> int:
    return sum(1 for seg in template.strip("/").split("/") if seg and "{" not in seg)


RULES: list[Rule] = [
    Rule(
        methods=frozenset(methods),
        template=template,
        requirement=req,
        summary=summary,
        regex=_compile(template),
        literal_segments=_literal_segments(template),
    )
    for methods, template, req, summary in _RULES_SPEC
]


def normalize_path(path: str) -> str:
    if len(path) > 1 and path.endswith("/"):
        return path.rstrip("/") or "/"
    return path


def is_public(path: str) -> bool:
    path = normalize_path(path)
    return path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES)


def match_rule(method: str, path: str) -> tuple[Optional[Rule], dict]:
    """The most specific rule for (method, path), and its path params."""
    method = "GET" if method.upper() == "HEAD" else method.upper()
    path = normalize_path(path)
    best: Optional[Rule] = None
    best_params: dict = {}
    for rule in RULES:
        if method not in rule.methods:
            continue
        m = rule.regex.fullmatch(path)
        if not m:
            continue
        if best is None or rule.literal_segments > best.literal_segments:
            best, best_params = rule, m.groupdict()
    return best, best_params


def summarize(rule: Optional[Rule], params: dict, method: str, path: str) -> str:
    if rule is not None and rule.summary:
        try:
            return rule.summary.format(**params)[:300]
        except (KeyError, IndexError):
            return rule.summary[:300]
    return f"{method.upper()} {path}"[:300]
