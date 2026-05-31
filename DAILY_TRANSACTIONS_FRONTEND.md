# Daily Transactions Frontend Guide

This endpoint gives the frontend daily transaction counts for charts and admin/reseller summaries.

## Endpoint

```http
GET /api/dashboard/transactions-daily
Authorization: Bearer <token>
```

The endpoint reads from `customer_payments`, which is the completed payment ledger used for revenue and balance calculations.

## Query Parameters

- `period`: `7d`, `30d`, `90d`, `6m`, `1y`. Default: `30d`.
- `start_date`: custom range start, `YYYY-MM-DD`.
- `end_date`: custom range end, `YYYY-MM-DD`.
- `router_id`: optional router filter.
- `payment_method`: optional filter, for example `mobile_money`, `cash`, `card`, `bank_transfer`, `other`.
- `status`: `completed`, `pending`, `failed`, `refunded`, or `all`. Default: `completed`.

When `start_date` and `end_date` are provided, `period` is ignored.

## Example

```http
GET /api/dashboard/transactions-daily?period=30d
```

```json
{
  "period": "30d",
  "start_date": "2026-05-02",
  "end_date": "2026-05-31",
  "router_id": null,
  "payment_method": null,
  "status": "completed",
  "data": [
    {
      "date": "2026-05-02",
      "label": "May 02",
      "transactions": 4,
      "revenue": 200.0
    }
  ],
  "totals": {
    "transactions": 81,
    "revenue": 4050.0,
    "active_days": 20,
    "avg_transactions_per_day": 2.7,
    "avg_transactions_per_active_day": 4.05
  },
  "generated_at": "2026-05-31T..."
}
```

## Frontend Notes

- The `data` array includes zero-transaction days, so charts do not need to fill gaps.
- Use `transactions` for the main chart line/bar.
- Use `revenue` as a secondary metric or tooltip.
- For normal dashboard use, poll no faster than the rest of the dashboard analytics calls.
- This is a DB-only endpoint; it does not call MikroTik.
