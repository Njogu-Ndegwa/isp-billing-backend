# Subscription invoices exceeded one calendar billing month

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

The initial production audit on August 24 found:

- 502 subscription invoices in total.
- 79 invoices across 51 resellers covered more than 30 days.
- 25 open invoices covered more than 30 days.

That first pass used a fixed 30-day comparison. The billing policy was then
clarified: renewal is from the same date in one month to the same date in the
next, so a legitimate billing month may contain 28, 29, 30, or 31 days. The
fixed-30-day comparison incorrectly treated ordinary 31-day cycles as excess.

Under the final calendar-month policy, two open invoices had a monetary excess:

- Kennice Networks invoice #497: KES 2,613.80 to KES 1,796.75, a KES 817.05
  reduction.
- FLUX NET invoice #186: KES 581.15 to KES 517.13, a KES 64.02 reduction.

The total correction on unpaid invoices is KES 881.07. Other open invoices may
need their displayed date boundary restored or capped to one calendar month,
but their payable value does not change.

### Customers who had already paid an estimated excess

Status is the live subscription status checked on August 24, 2026. The estimate
keeps the PPPoE charge recorded on each original invoice and recalculates only
the hotspot revenue inside the final one-calendar-month window.

| Customer | Email | Estimated excess | Current status |
|---|---|---:|---|
| Lightning Fast Hotspot | muchocyro@gmail.com | KES 60.90 | Active |
| Major1 Net | abudojunior5@gmail.com | KES 724.62 | Active |
| Kennice Networks | mikekariuki697@gmail.com | KES 3.45 | Active |
| Central Kiddoh | dennis1486@gmail.com | KES 451.50 | Active |

The four historical estimates total KES 1,240.47. They are not changed in the
system; refunds or credits will be handled separately.

Kennice Networks is the customer whose August invoice exposed the wider issue.

## Fix

All invoice creation paths now set the start to the later of:

- the natural start (normally the previous invoice's end), and
- the same date one calendar month before the invoice end.

This keeps normal cycles continuous while allowing February and 31-day months.
If the previous boundary is stale because of the historical bug, old backlog is
not pulled into the current invoice.

The Request Invoice endpoint now rejects requests from active or trial resellers
until they are within five days of expiry. Expired and suspended resellers can
still request the invoice they need to renew.

PostgreSQL also has a `NOT VALID` check constraint that rejects a new or updated
invoice starting earlier than one calendar month before its end. Existing
historical rows remain readable.

The one-off repair tool recalculates selected pending or overdue invoices. It is
dry-run by default and refuses to alter paid or waived invoices.

## Verification

The subscription tests cover:

- a 57-day requested period being reduced to one calendar month;
- revenue before the cutoff being excluded;
- a valid 31-day calendar month being retained without a gap;
- February producing the correct shorter calendar window;
- a recent previous-invoice end remaining unchanged;
- the pre-expiry job capping a stale prior period; and
- an invoice request immediately after renewal being rejected.

A temporary fixed-30-day guard was deployed first and repaired the 25 open
invoices. Before any of the materially affected invoices was paid, the policy
was clarified and the implementation was changed to calendar-month semantics.
The final repair restores the correct calendar boundary on open invoices only;
paid and waived invoices are never changed by the repair tool.
