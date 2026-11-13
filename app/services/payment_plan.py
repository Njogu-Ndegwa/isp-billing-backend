"""Which plan a customer payment paid for, as a SQL expression.

Plan reports used to join payments to ``Customer.plan_id``. That column is
overwritten on every purchase, so a customer who bought a daily plan ten times
and then one weekly plan had all eleven payments credited to the weekly plan.
``CustomerPayment.plan_id`` snapshots the plan at payment time; reports must
group by it.

The snapshot column went live on 2026-07-26 (first stamped row 03:29 UTC;
created_at is naive UTC).
Payments before that have no snapshot, so for them the customer's current plan
is the best guess left. After it, a NULL snapshot means the plan was deleted
(the FK is ON DELETE SET NULL), and falling back would hand that money to
whatever plan the customer is on now — so those stay unattributed.
"""
from datetime import datetime

from sqlalchemy import case

from app.db.models import Customer, CustomerPayment

PLAN_SNAPSHOT_SINCE = datetime(2026, 7, 26, 3, 29)


def payment_plan_id():
    """``CustomerPayment``'s plan id. The query must also (outer) join ``Customer``."""
    return case(
        (CustomerPayment.plan_id.isnot(None), CustomerPayment.plan_id),
        (CustomerPayment.created_at < PLAN_SNAPSHOT_SINCE, Customer.plan_id),
        else_=None,
    )
