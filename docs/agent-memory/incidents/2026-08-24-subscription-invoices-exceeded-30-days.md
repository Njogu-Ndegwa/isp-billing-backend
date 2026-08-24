# Subscription invoices exceeded the 30-day billing window

## What happened

Kennice Networks received invoice #497 for KES 2,613.80. The invoice said the
reseller had KES 72,960 in hotspot revenue, but the period ran from June 27 to
August 24: 57.38 days.

The reseller had paid every month. The problem was the period attached to each
payment:

| Payment date (EAT) | Amount | Period settled |
|---|---:|---|
| May 27-28 | KES 500.00 | April 27-May 23 |
| June 27 | KES 610.15 | May 23-June 24 |
| July 27 | KES 500.00 | June 24-June 27 |

Invoice #289 was created at 23:50:11 EAT on June 27, twenty seconds after the
previous invoice was paid. It covered only 3.6 days and remained pending until
July 27. Production does not record whether the user-facing Request Invoice
endpoint or an admin action created it, but it was not the scheduled 09:00 EAT
job and no other invoice was created at the same time.

While #289 was pending, the daily job skipped the reseller. Paying #289 on July
27 extended the subscription through August 28, even though #289 covered only
June 24-27. When the next scheduled invoice ran on August 24, it started at the
previous invoice's end date, June 27. That pulled 57 days of sales into one bill.

## Root cause

Three rules interacted badly:

1. Invoice generation used the previous invoice's `period_end` without a maximum
   age.
2. An existing pending invoice blocked creation of another invoice.
3. The self-service Request Invoice endpoint allowed an active reseller to create
   an invoice at any point in the subscription cycle.

The payment and usage periods could drift apart. A short invoice could remain
pending for a month, then a later invoice would collect every sale since that
short invoice ended.

## Scope and financial exposure

The production audit on August 24 found:

- 502 subscription invoices in total.
- 79 invoices across 51 resellers covered more than 30 days.
- 25 open invoices covered more than 30 days.
- Five open invoices exceeded a strict trailing-30-day price, by KES 1,086.54
  in total.
- Fourteen paid invoices across nine resellers were KES 1,715.46 above the same
  trailing-30-day calculation.

Kennice Networks accounted for KES 861.75 of the open difference before the
separate duplicate-payment-reference adjustment. Kennice had also paid an
estimated KES 8.85 extra on invoice #270. Central Kiddoh had already paid an
estimated KES 451.50 above the trailing-30-day calculation on invoice #377 and
had an additional KES 80.25 difference on pending invoice #489.

### Customers who had already paid an estimated excess

Status is the live subscription status checked on August 24, 2026. The estimate
keeps the PPPoE charge recorded on each original invoice and recalculates only
the hotspot revenue inside the strict trailing-30-day window.

| Customer | Email | Estimated excess | Current status |
|---|---|---:|---|
| Bitwave Soko Wifi | dennisndegwa001@gmail.com | KES 49.47 | Active |
| SIMNET | salomonkiptanui@gmail.com | KES 52.68 | Suspended |
| Kaloleni SkyNet Pro | festusyaa30@gmail.com | KES 123.90 | Active |
| Major1 net | abudojunior3@gmail.com | KES 145.17 | Active |
| Lightning Fast Hotspot | muchocyro@gmail.com | KES 118.50 | Active |
| Major1 Net | abudojunior5@gmail.com | KES 743.16 | Active |
| Kennice Networks | mikekariuki697@gmail.com | KES 8.85 | Active |
| Central Kiddoh | dennis1486@gmail.com | KES 451.50 | Active |
| YahWeh Tech | vincentmuchele5@gmail.com | KES 22.23 | Active |

Kennice Networks is the customer whose August invoice exposed the wider issue.

Historical paid amounts are an audit list, not an automatic refund instruction.
They need a separate decision on refund or account-credit handling.

## Fix

All invoice creation paths now set the start to the later of:

- the natural start (normally the previous invoice's end), and
- exactly 30 days before the invoice end.

The Request Invoice endpoint now rejects requests from active or trial resellers
until they are within five days of expiry. Expired and suspended resellers can
still request the invoice they need to renew.

PostgreSQL also has a `NOT VALID` check constraint that rejects new or updated
invoice periods over 30 days. Existing historical rows remain readable.

The one-off repair tool recalculates selected pending or overdue invoices. It is
dry-run by default and refuses to alter paid or waived invoices.

## Verification

The subscription tests cover:

- a 57-day requested period being reduced to 30 days;
- revenue before the cutoff being excluded;
- a recent previous-invoice end remaining unchanged;
- the pre-expiry job capping a stale prior period; and
- an invoice request immediately after renewal being rejected.

The fix was deployed on August 24, 2026. The repair was previewed first, then
applied to all 25 open invoices that exceeded 30 days. Five payable amounts were
reduced by KES 1,086.54 in total; the remaining 20 stayed at the same payable
amount, usually because the KES 500 minimum still applied.

Post-repair verification found no pending or overdue invoice longer than 30 days.
Kennice invoice #497 is now KES 1,752.05 for exactly 30 days, and Central Kiddoh
invoice #489 is now KES 2,203.50 for exactly 30 days. The database guard is also
present and rejects any new or updated invoice longer than 30 days.
