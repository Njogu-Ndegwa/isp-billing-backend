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
