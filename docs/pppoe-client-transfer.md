# PPPoE Client Transfer

Use this for moving existing PPPoE clients from an exported `items_export` workbook into the billing database.

The transfer is DB-only. It does not connect to MikroTik and does not change live router secrets. By default, imported customers have `pppoe_password = NULL`; when a customer later renews, provisioning can update the existing RouterOS secret profile without changing its password.

## Dry Run

```powershell
myEnv\Scripts\python.exe scripts\import_pppoe_items.py `
  --file C:\path\items_export.xlsx `
  --reseller-id 12 `
  --router-id 34
```

## Apply

Use existing PPPoE plans where possible. If missing plans must be created, provide a real default price.

```powershell
myEnv\Scripts\python.exe scripts\import_pppoe_items.py `
  --file C:\path\items_export.xlsx `
  --reseller-id 12 `
  --router-id 34 `
  --create-missing-plans `
  --default-plan-price 1000 `
  --apply
```

For workbook package names that should map to a specific existing plan, pass one
or more explicit overrides:

```powershell
myEnv\Scripts\python.exe scripts\import_pppoe_items.py `
  --file C:\path\items_export.xlsx `
  --reseller-id 12 `
  --router-id 34 `
  --package-plan "1Mbps=556" `
  --package-plan "mnthly 70mbps=562" `
  --apply
```

## Passwords

Default behavior is passwordless import. Do not pass password flags when the router already has the live PPPoE secrets.

Only use these options if the source file really contains the correct passwords:

```powershell
--password-column Password
```

or if you explicitly want to set all rows to one known password:

```powershell
--default-password some-value
```

## Existing Customers

Matching is by `pppoe_username`.

If a username already belongs to another reseller/router, the import stops unless `--reassign-existing` is passed. Use that flag only when intentionally moving the customer row.

## Move Existing Customers Between Routers

Use this after a replacement router has already been provisioned into the app.
By default, apply mode first creates/updates active PPPoE secrets/profiles on
the target MikroTik, then changes `customers.router_id` for PPPoE customers and
moves related retry/FUP watcher state. It does not change customer status,
expiry, payments, plans, passwords, or account numbers.

Inactive and pending customers are moved in the DB but are not provisioned on
the target router. That preserves their inactive state; their future renewal
will provision them on the new router.

Preview:

```powershell
myEnv\Scripts\python.exe scripts\move_pppoe_customers.py `
  --source-router-id 12 `
  --target-router-id 34
```

Apply:

```powershell
myEnv\Scripts\python.exe scripts\move_pppoe_customers.py `
  --source-router-id 12 `
  --target-router-id 34 `
  --apply
```

Default behavior moves active, inactive, and pending PPPoE customers so future
renewals use the new router. Use `--active-only` only when intentionally leaving
expired/inactive customers on the old router.

Use DB-only mode only when the target router has already been prepared manually:

```powershell
myEnv\Scripts\python.exe scripts\move_pppoe_customers.py `
  --source-router-id 12 `
  --target-router-id 34 `
  --skip-target-provision `
  --apply
```

If any active customer fails to provision on the target router, the script does
not apply the DB move. Fix the target-router error and rerun.

The same flow is exposed to the admin frontend:

```http
POST /api/routers/{source_router_id}/pppoe-customers/transfer
```

Preview body:

```json
{
  "target_router_id": 34
}
```

Apply body:

```json
{
  "target_router_id": 34,
  "apply": true
}
```

Optional flags match the CLI: `active_only`, `skip_target_provision`, and
`sample_limit`.
