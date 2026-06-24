# PPPoE Router Transfer Frontend Guide

Use this to add an admin/reseller UI for moving PPPoE customers from an old
router to a replacement router.

## Endpoint

```http
POST /api/routers/{source_router_id}/pppoe-customers/transfer
```

The normal auth token is required. The backend verifies that both routers are
accessible to the current user and belong to the same owner.

## Request Body

Preview:

```json
{
  "target_router_id": 34
}
```

Apply:

```json
{
  "target_router_id": 34,
  "apply": true
}
```

Optional fields:

```ts
type TransferPPPoERequest = {
  target_router_id: number;
  apply?: boolean;                 // default false
  active_only?: boolean;           // default false
  skip_target_provision?: boolean; // default false
  sample_limit?: number;           // backend caps at 100
};
```

## Response Shape

```ts
type TransferPPPoEReport = {
  source_router_id: number;
  target_router_id: number;
  dry_run: boolean;
  active_only: boolean;
  source_router_name: string | null;
  target_router_name: string | null;
  selected: number;
  moved: number;
  active: number;
  inactive: number;
  pending: number;
  missing_passwords: number;
  missing_active_passwords: number;
  target_provision: boolean;
  target_provision_required: number;
  target_provisioned: number;
  target_provision_failed: number;
  target_provision_skipped: number;
  target_provision_failures: Array<{
    customer_id: number | null;
    pppoe_username: string | null;
    error: string;
  }>;
  usage_watch_states_updated: number;
  provisioning_attempts_updated: number;
  samples: Array<{
    customer_id: number;
    name: string | null;
    phone: string;
    pppoe_username: string;
    status: "active" | "inactive" | "pending" | string;
    expiry: string | null;
    plan_id: number | null;
    plan_name: string | null;
    plan_speed: string | null;
    password_present: boolean;
  }>;
  warnings: string[];
  errors: string[];
  success: boolean;
  has_errors: boolean;
};

type TransferPPPoEResponse = {
  success: boolean;
  stage: "transfer";
  source_router_id: number;
  source_router_name: string;
  target_router_id: number;
  target_router_name: string;
  dry_run: boolean;
  report: TransferPPPoEReport;
};
```

## UI Flow

1. Add a "Move PPPoE Customers" action on a router details/actions menu.
2. Open a modal with:
   - source router locked to the current router
   - target router selector, excluding the source router
   - checkbox: "Move active customers only" (`active_only`)
   - advanced checkbox: "Skip target router provisioning" (`skip_target_provision`)
3. On target selection, call preview with `apply: false`.
4. Show preview counts:
   - selected
   - active
   - inactive
   - pending
   - missing passwords
   - target provisioning required/skipped
5. Show warnings and sample customers before enabling Apply.
6. On Apply, send the same body with `apply: true`.
7. If `success` is false or `report.has_errors` is true, show
   `report.errors` and `report.target_provision_failures`; do not show success.
8. On success, refresh router customer counts and PPPoE views for both routers.

## Operational Rules

- Default behavior moves active, inactive, and pending PPPoE customers. This is
  best for router replacement because future renewals will use the new router.
- Active customers are created/updated on the target MikroTik before DB
  ownership is moved.
- Inactive/pending customers are moved in DB only, preserving their inactive
  state until renewal.
- Payments, transactions, customer IDs, account numbers, plans, expiry, status,
  PPPoE usernames, and PPPoE passwords are not modified.
- If target provisioning fails for any active customer, the backend does not
  move DB ownership. The frontend should display the failure list and let the
  operator retry after fixing the router issue.

