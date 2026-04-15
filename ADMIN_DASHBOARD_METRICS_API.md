# Admin Dashboard Metrics API

**Base URL**: `https://isp.bitwavetechnologies.com/api`
**Auth**: All endpoints require `Authorization: Bearer <admin_token>` header.
**Error Handling**: All endpoints return `403` if the user is not an admin, `401` if the token is invalid/expired.

---

## Quick Reference

| # | Method | Endpoint | Query Params |
|---|--------|----------|--------------|
| 1 | GET | `/admin/metrics/mrr` | -- |
| 2 | GET | `/admin/metrics/churn` | `period` |
| 3 | GET | `/admin/metrics/signups-summary` | `period` |
| 4 | GET | `/admin/dashboard` | -- *(enhanced with new fields)* |
| 5 | GET | `/admin/metrics/customer-signups` | `period` |
| 6 | GET | `/admin/metrics/subscription-revenue-history` | `period` |
| 7 | GET | `/admin/metrics/arpu` | -- |
| 8 | GET | `/admin/metrics/trial-conversion` | -- |
| 9 | GET | `/admin/metrics/activation-funnel` | -- |
| 10 | GET | `/admin/metrics/revenue-concentration` | -- |
| 11 | GET | `/admin/metrics/smart-alerts` | -- |
| 12 | GET | `/admin/metrics/revenue-forecast` | `period`, `forecast_days` |
| 13 | GET | `/admin/metrics/growth-targets` | -- |
| 13 | PUT | `/admin/metrics/growth-targets` | -- *(JSON body)* |

---

## Shared Fetch Helper (TypeScript)

```typescript
const API_BASE = "https://isp.bitwavetechnologies.com/api";

async function adminFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const token = localStorage.getItem("token"); // or however you store it
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      ...options?.headers,
    },
  });
  if (!res.ok) throw new Error(`API ${res.status}: ${res.statusText}`);
  return res.json();
}
```

---

## 1. MRR (Monthly Recurring Revenue)

**`GET /api/admin/metrics/mrr`**

No query parameters.

### Response

```json
{
  "current_mrr": 45000.00,
  "previous_period_mrr": 41500.00,
  "change_percent": 8.43,
  "currency": "KES",
  "breakdown": {
    "new_mrr": 5000.00,
    "churned_mrr": 1500.00,
    "expansion_mrr": 0.00,
    "contraction_mrr": 0.00
  },
  "by_plan": [
    { "plan_name": "Active", "reseller_count": 10, "mrr": 30000.00 },
    { "plan_name": "Trial", "reseller_count": 8, "mrr": 15000.00 }
  ],
  "period": "month",
  "calculated_at": "2026-04-15T10:00:00"
}
```

### TypeScript

```typescript
interface MRRBreakdown {
  new_mrr: number;
  churned_mrr: number;
  expansion_mrr: number;
  contraction_mrr: number;
}

interface MRRByPlan {
  plan_name: string;
  reseller_count: number;
  mrr: number;
}

interface AdminMRRMetrics {
  current_mrr: number;
  previous_period_mrr: number;
  change_percent: number;
  currency: string;
  breakdown: MRRBreakdown;
  by_plan: MRRByPlan[];
  period: string;
  calculated_at: string;
}

// Usage
const mrr = await adminFetch<AdminMRRMetrics>("/admin/metrics/mrr");
```

---

## 2. Churn Rate

**`GET /api/admin/metrics/churn`**

| Param | Type | Default | Allowed |
|-------|------|---------|---------|
| `period` | string | `month` | `week`, `month`, `quarter` |

### Response

```json
{
  "churn_rate": 3.2,
  "churned_count": 2,
  "total_at_period_start": 62,
  "previous_period_churn_rate": 4.8,
  "change_percent": -1.6,
  "net_reseller_growth": 5,
  "churned_resellers": [
    {
      "id": 12,
      "organization_name": "NetZone",
      "churned_at": "2026-04-10T00:00:00",
      "reason": "subscription_expired"
    }
  ],
  "period": "month",
  "calculated_at": "2026-04-15T10:00:00"
}
```

### TypeScript

```typescript
interface ChurnedReseller {
  id: number;
  organization_name: string;
  churned_at: string | null;
  reason: string;
}

interface AdminChurnMetrics {
  churn_rate: number;
  churned_count: number;
  total_at_period_start: number;
  previous_period_churn_rate: number;
  change_percent: number;
  net_reseller_growth: number;
  churned_resellers: ChurnedReseller[];
  period: string;
  calculated_at: string;
}

// Usage
const churn = await adminFetch<AdminChurnMetrics>("/admin/metrics/churn?period=month");
```

---

## 3. Signups Summary

**`GET /api/admin/metrics/signups-summary`**

| Param | Type | Default | Allowed |
|-------|------|---------|---------|
| `period` | string | `30d` | `7d`, `30d`, `90d`, `1y` |

### Response

```json
{
  "reseller_signups": {
    "today": 2,
    "this_week": 5,
    "this_month": 12,
    "period_total": 12,
    "previous_period_total": 9,
    "change_percent": 33.33
  },
  "customer_signups": {
    "today": 45,
    "this_week": 210,
    "this_month": 890,
    "period_total": 890,
    "previous_period_total": 720,
    "change_percent": 23.61
  },
  "period": "30d",
  "calculated_at": "2026-04-15T10:00:00"
}
```

### TypeScript

```typescript
interface SignupBucket {
  today: number;
  this_week: number;
  this_month: number;
  period_total: number;
  previous_period_total: number;
  change_percent: number;
}

interface AdminSignupsSummary {
  reseller_signups: SignupBucket;
  customer_signups: SignupBucket;
  period: string;
  calculated_at: string;
}

// Usage
const signups = await adminFetch<AdminSignupsSummary>("/admin/metrics/signups-summary?period=30d");
```

---

## 4. Admin Dashboard (v2 Enhancement)

**`GET /api/admin/dashboard`**

No query parameters. This is the existing dashboard endpoint with **new fields added** at the end of the response. All existing fields remain unchanged.

### New Fields Added

```json
{
  "...all existing fields...",

  "growth_deltas": {
    "revenue_change_percent": 12.5,
    "resellers_change_percent": 8.0,
    "customers_change_percent": 15.2,
    "comparison_period": "vs last month"
  },
  "signups_today": 3,
  "signups_this_week": 8,
  "signups_this_month": 14,
  "generated_at": "2026-04-15T10:00:00"
}
```

### TypeScript (new fields only)

```typescript
interface GrowthDeltas {
  revenue_change_percent: number;
  resellers_change_percent: number;
  customers_change_percent: number;
  comparison_period: string;
}

// Add to your existing AdminDashboard interface:
interface AdminDashboardV2 {
  // ...existing fields...
  growth_deltas: GrowthDeltas;
  signups_today: number;
  signups_this_week: number;
  signups_this_month: number;
  generated_at: string;
}

// Usage (same endpoint as before)
const dashboard = await adminFetch<AdminDashboardV2>("/admin/dashboard");
```

---

## 5. Customer Signups Time Series

**`GET /api/admin/metrics/customer-signups`**

| Param | Type | Default | Allowed |
|-------|------|---------|---------|
| `period` | string | `30d` | `7d`, `30d`, `90d`, `1y` |

### Response

```json
{
  "period": "30d",
  "customer_signups_over_time": [
    { "date": "2026-03-17", "label": "Mar 17", "count": 32 },
    { "date": "2026-03-18", "label": "Mar 18", "count": 45 },
    { "date": "2026-03-19", "label": "Mar 19", "count": 28 }
  ],
  "previous_period": [
    { "date": "2026-02-15", "label": "Feb 15", "count": 25 },
    { "date": "2026-02-16", "label": "Feb 16", "count": 30 }
  ]
}
```

### TypeScript

```typescript
interface TimeSeriesPoint {
  date: string;
  label: string;
  count: number;
}

interface AdminCustomerSignupsTimeSeries {
  period: string;
  customer_signups_over_time: TimeSeriesPoint[];
  previous_period: TimeSeriesPoint[];
}

// Usage
const signups = await adminFetch<AdminCustomerSignupsTimeSeries>(
  "/admin/metrics/customer-signups?period=30d"
);
```

---

## 6. Subscription Revenue History

**`GET /api/admin/metrics/subscription-revenue-history`**

| Param | Type | Default | Allowed |
|-------|------|---------|---------|
| `period` | string | `30d` | `7d`, `30d`, `90d`, `1y` |

### Response

```json
{
  "period": "30d",
  "subscription_revenue_over_time": [
    { "date": "2026-03-17", "label": "Mar 17", "revenue": 5000.00 },
    { "date": "2026-03-18", "label": "Mar 18", "revenue": 12000.00 },
    { "date": "2026-03-19", "label": "Mar 19", "revenue": 0.00 }
  ],
  "previous_period": [
    { "date": "2026-02-15", "label": "Feb 15", "revenue": 4500.00 },
    { "date": "2026-02-16", "label": "Feb 16", "revenue": 8000.00 }
  ]
}
```

### TypeScript

```typescript
interface RevenueTimeSeriesPoint {
  date: string;
  label: string;
  revenue: number;
}

interface AdminSubscriptionRevenueHistory {
  period: string;
  subscription_revenue_over_time: RevenueTimeSeriesPoint[];
  previous_period: RevenueTimeSeriesPoint[];
}

// Usage
const revHistory = await adminFetch<AdminSubscriptionRevenueHistory>(
  "/admin/metrics/subscription-revenue-history?period=30d"
);
```

---

## 7. ARPU (Average Revenue Per Reseller)

**`GET /api/admin/metrics/arpu`**

No query parameters.

### Response

```json
{
  "current_arpu": 4500.00,
  "previous_period_arpu": 4200.00,
  "change_percent": 7.14,
  "currency": "KES",
  "active_resellers": 10,
  "total_revenue": 45000.00,
  "period": "month",
  "calculated_at": "2026-04-15T10:00:00"
}
```

### TypeScript

```typescript
interface AdminARPUMetrics {
  current_arpu: number;
  previous_period_arpu: number;
  change_percent: number;
  currency: string;
  active_resellers: number;
  total_revenue: number;
  period: string;
  calculated_at: string;
}

// Usage
const arpu = await adminFetch<AdminARPUMetrics>("/admin/metrics/arpu");
```

---

## 8. Trial Conversion

**`GET /api/admin/metrics/trial-conversion`**

No query parameters.

### Response

```json
{
  "conversion_rate": 24.8,
  "converted_count": 5,
  "total_trials_at_start": 20,
  "current_trials": 18,
  "previous_period_rate": 22.0,
  "change_percent": 2.8,
  "avg_days_to_convert": 12,
  "period": "month",
  "calculated_at": "2026-04-15T10:00:00"
}
```

### TypeScript

```typescript
interface AdminTrialConversion {
  conversion_rate: number;
  converted_count: number;
  total_trials_at_start: number;
  current_trials: number;
  previous_period_rate: number;
  change_percent: number;
  avg_days_to_convert: number;
  period: string;
  calculated_at: string;
}

// Usage
const trial = await adminFetch<AdminTrialConversion>("/admin/metrics/trial-conversion");
```

---

## 9. Activation Funnel

**`GET /api/admin/metrics/activation-funnel`**

No query parameters.

### Response

```json
{
  "funnel": [
    { "stage": "signed_up", "label": "Signed Up", "count": 100, "percent": 100 },
    { "stage": "added_router", "label": "Added Router", "count": 72, "percent": 72.0 },
    { "stage": "first_customer", "label": "First Customer", "count": 58, "percent": 58.0 },
    { "stage": "first_revenue", "label": "First Revenue", "count": 45, "percent": 45.0 }
  ],
  "conversion_rates": {
    "signup_to_router": 72.0,
    "router_to_customer": 80.56,
    "customer_to_revenue": 77.59,
    "signup_to_revenue": 45.0
  },
  "period": "all_time",
  "calculated_at": "2026-04-15T10:00:00"
}
```

### TypeScript

```typescript
interface FunnelStage {
  stage: string;
  label: string;
  count: number;
  percent: number;
}

interface ConversionRates {
  signup_to_router: number;
  router_to_customer: number;
  customer_to_revenue: number;
  signup_to_revenue: number;
}

interface AdminActivationFunnel {
  funnel: FunnelStage[];
  conversion_rates: ConversionRates;
  period: string;
  calculated_at: string;
}

// Usage
const funnel = await adminFetch<AdminActivationFunnel>("/admin/metrics/activation-funnel");
```

---

## 10. Revenue Concentration

**`GET /api/admin/metrics/revenue-concentration`**

No query parameters.

### Response

```json
{
  "top_5_share_percent": 62.5,
  "top_10_share_percent": 85.3,
  "total_revenue": 500000.00,
  "total_resellers_with_revenue": 35,
  "top_contributors": [
    { "id": 1, "organization_name": "FastNet ISP", "revenue": 95000.00, "share_percent": 19.0 },
    { "id": 5, "organization_name": "SpeedLink", "revenue": 72000.00, "share_percent": 14.4 },
    { "id": 3, "organization_name": "ConnectPlus", "revenue": 58000.00, "share_percent": 11.6 }
  ],
  "period": "this_month",
  "calculated_at": "2026-04-15T10:00:00"
}
```

### TypeScript

```typescript
interface TopContributor {
  id: number;
  organization_name: string;
  revenue: number;
  share_percent: number;
}

interface AdminRevenueConcentration {
  top_5_share_percent: number;
  top_10_share_percent: number;
  total_revenue: number;
  total_resellers_with_revenue: number;
  top_contributors: TopContributor[];
  period: string;
  calculated_at: string;
}

// Usage
const concentration = await adminFetch<AdminRevenueConcentration>(
  "/admin/metrics/revenue-concentration"
);
```

---

## 11. Smart Alerts

**`GET /api/admin/metrics/smart-alerts`**

No query parameters.

### Response

```json
{
  "alerts": [
    {
      "id": "milestone_rev_1000000",
      "type": "milestone",
      "severity": "success",
      "title": "Revenue Milestone",
      "message": "Platform revenue crossed KES 1,000,000 this month!",
      "timestamp": "2026-04-15T10:00:00",
      "dismissed": false
    },
    {
      "id": "warning_inactive_12",
      "type": "warning",
      "severity": "warning",
      "title": "Inactive Reseller",
      "message": "NetZone ISP has had no transactions for 7+ days",
      "timestamp": "2026-04-15T10:00:00",
      "dismissed": false,
      "action_url": "/admin/resellers/12"
    },
    {
      "id": "record_signups_today",
      "type": "record",
      "severity": "info",
      "title": "New Daily Record",
      "message": "12 new signups today — highest ever!",
      "timestamp": "2026-04-15T10:00:00",
      "dismissed": false
    },
    {
      "id": "warning_expiring_soon",
      "type": "warning",
      "severity": "danger",
      "title": "Subscriptions Expiring Soon",
      "message": "3 reseller(s) have subscriptions expiring within 3 days",
      "timestamp": "2026-04-15T10:00:00",
      "dismissed": false,
      "action_url": "/admin/subscriptions/expiring-soon"
    }
  ],
  "generated_at": "2026-04-15T10:00:00"
}
```

### Alert Types

| `type` | `severity` | When Generated |
|--------|------------|----------------|
| `milestone` | `success` | Revenue crosses 100K, 500K, 1M, 2M, or 5M KES this month |
| `warning` | `warning` | Active reseller has no transactions for 7+ days |
| `warning` | `danger` | Reseller subscriptions expiring within 3 days |
| `record` | `info` | Today's signups are the highest daily count ever |

### TypeScript

```typescript
type AlertType = "milestone" | "warning" | "record" | "info";
type AlertSeverity = "success" | "warning" | "danger" | "info";

interface AdminSmartAlert {
  id: string;
  type: AlertType;
  severity: AlertSeverity;
  title: string;
  message: string;
  timestamp: string;
  dismissed: boolean;
  action_url?: string;
}

interface AdminSmartAlertsResponse {
  alerts: AdminSmartAlert[];
  generated_at: string;
}

// Usage
const alerts = await adminFetch<AdminSmartAlertsResponse>("/admin/metrics/smart-alerts");
```

---

## 12. Revenue Forecast

**`GET /api/admin/metrics/revenue-forecast`**

| Param | Type | Default | Allowed |
|-------|------|---------|---------|
| `period` | string | `30d` | `7d`, `30d`, `90d` |
| `forecast_days` | number | `30` | `1` to `365` |

### Response

```json
{
  "forecast": [
    {
      "date": "2026-04-16",
      "label": "Apr 16",
      "projected_revenue": 18500.00,
      "lower_bound": 15000.00,
      "upper_bound": 22000.00
    },
    {
      "date": "2026-04-17",
      "label": "Apr 17",
      "projected_revenue": 18700.00,
      "lower_bound": 14800.00,
      "upper_bound": 22600.00
    }
  ],
  "projected_period_end_total": 560000.00,
  "growth_rate_percent": 12.5,
  "confidence": "medium",
  "based_on_days": 30,
  "calculated_at": "2026-04-15T10:00:00"
}
```

### Confidence Levels

| Value | Meaning |
|-------|---------|
| `high` | R-squared > 0.7 -- strong trend in historical data |
| `medium` | R-squared 0.4-0.7 -- moderate trend |
| `low` | R-squared < 0.4 -- weak/no trend, or insufficient data |

### TypeScript

```typescript
interface ForecastPoint {
  date: string;
  label: string;
  projected_revenue: number;
  lower_bound: number;
  upper_bound: number;
}

interface AdminRevenueForecast {
  forecast: ForecastPoint[];
  projected_period_end_total: number;
  growth_rate_percent: number;
  confidence: "high" | "medium" | "low";
  based_on_days: number;
  calculated_at: string;
}

// Usage
const forecast = await adminFetch<AdminRevenueForecast>(
  "/admin/metrics/revenue-forecast?period=30d&forecast_days=30"
);
```

---

## 13. Growth Targets

### GET Targets

**`GET /api/admin/metrics/growth-targets`**

No query parameters. Returns current targets with live progress. On first call, seeds 3 default targets (MRR, Reseller Count, Churn Rate).

### GET Response

```json
{
  "targets": [
    {
      "id": "mrr_target",
      "label": "MRR Target",
      "current_value": 45000.00,
      "target_value": 60000.0,
      "progress_percent": 75.0,
      "unit": "KES",
      "period": "Q2 2026"
    },
    {
      "id": "reseller_target",
      "label": "Reseller Count",
      "current_value": 62.0,
      "target_value": 100.0,
      "progress_percent": 62.0,
      "unit": "resellers",
      "period": "Q2 2026"
    },
    {
      "id": "churn_target",
      "label": "Churn Rate",
      "current_value": 3.2,
      "target_value": 2.0,
      "progress_percent": 62.5,
      "unit": "%",
      "period": "Q2 2026",
      "inverse": true
    }
  ],
  "updated_at": "2026-04-01T00:00:00"
}
```

### PUT (Update Targets)

**`PUT /api/admin/metrics/growth-targets`**

### Request Body

```json
{
  "targets": [
    { "id": "mrr_target", "target_value": 75000, "period": "Q3 2026" },
    { "id": "reseller_target", "target_value": 150 }
  ]
}
```

Only `id` and `target_value` are required per target. `period`, `label`, `unit` are optional updates. If the `id` doesn't exist, a new target is created (then `target_value` and `label` are required).

### PUT Response

Same shape as GET -- returns the full updated targets list with recalculated progress.

### TypeScript

```typescript
interface AdminGrowthTarget {
  id: string;
  label: string;
  current_value: number;
  target_value: number;
  progress_percent: number;
  unit: string;
  period: string;
  inverse?: boolean;
}

interface AdminGrowthTargetsResponse {
  targets: AdminGrowthTarget[];
  updated_at: string;
}

interface GrowthTargetUpdatePayload {
  id: string;
  target_value: number;
  period?: string;
  label?: string;
  unit?: string;
  inverse?: boolean;
}

// GET
const targets = await adminFetch<AdminGrowthTargetsResponse>(
  "/admin/metrics/growth-targets"
);

// PUT
const updated = await adminFetch<AdminGrowthTargetsResponse>(
  "/admin/metrics/growth-targets",
  {
    method: "PUT",
    body: JSON.stringify({
      targets: [
        { id: "mrr_target", target_value: 75000, period: "Q3 2026" },
      ],
    }),
  }
);
```

---

## Error Responses

All endpoints return standard error shapes:

```json
// 401 Unauthorized
{ "detail": "Invalid or expired token" }

// 403 Forbidden
{ "detail": "Admin access required" }

// 400 Bad Request (only growth-targets PUT)
{ "detail": "target_value is required for target 'mrr_target'" }

// 422 Validation Error (invalid query params)
{
  "detail": [
    {
      "loc": ["query", "period"],
      "msg": "string does not match regex ...",
      "type": "value_error.str.regex"
    }
  ]
}
```

---

## Frontend Integration Pattern

All endpoints are designed so the frontend can gracefully handle missing/failed calls:

```typescript
async function safeAdminFetch<T>(path: string, fallback: T): Promise<T> {
  try {
    return await adminFetch<T>(path);
  } catch {
    return fallback;
  }
}

// Example: load all dashboard data in parallel
const [mrr, churn, signups, funnel, alerts] = await Promise.all([
  safeAdminFetch("/admin/metrics/mrr", null),
  safeAdminFetch("/admin/metrics/churn?period=month", null),
  safeAdminFetch("/admin/metrics/signups-summary?period=30d", null),
  safeAdminFetch("/admin/metrics/activation-funnel", null),
  safeAdminFetch("/admin/metrics/smart-alerts", { alerts: [], generated_at: "" }),
]);
```
