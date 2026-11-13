"""Which customer owns the queue of an extra PPPoE session.

A username allowed several devices (profile ``only-one=no``, see
``mikrotik_api.multi_device_on_up_script``) gets one dynamic queue per
session. RouterOS names the extras ``<pppoe-alice-1>``, ``<pppoe-alice-2>``,
so the queue name alone matches no customer. Both usage paths (router push in
``usage_push`` and the polling snapshot in ``mikrotik_background``) resolve
those queues here, so they cannot drift apart.

Attribution bills a customer and can trip their data cap, so it is strict:

* When the router reported its ``/ppp active`` list, the session IP decides.
  An IP that belongs to another login is never credited to anyone else.
* Without that list, a numeric ``-N`` suffix is stripped, but only for a
  customer who is actually allowed more than one device. A leftover secret
  named ``john-2`` on a router therefore never bills single-device ``john``.
"""

import re
from typing import Callable, Optional

from app.db.models import Customer

EXTRA_SESSION_RE = re.compile(r"^(?P<base>.+)-(?P<n>\d{1,3})$")


def _allows_several_devices(customer: Customer) -> bool:
    from app.services.subscription_sharing import max_devices_for_customer

    return max_devices_for_customer(customer, customer.__dict__.get("plan")) > 1


def resolve_extra_session_customer(
    queue_user: str,
    target_ip: str,
    find_customer: Callable[[str], Optional[Customer]],
    session_users: Optional[dict[str, str]] = None,
) -> Optional[Customer]:
    """The customer whose extra session ``<pppoe-{queue_user}>`` is, or None.

    ``find_customer`` looks a PPPoE username up among this router's customers.
    Call only after the queue's own name matched no customer.
    """
    ip = str(target_ip or "").split(",", 1)[0].strip().split("/", 1)[0]
    if ip and session_users and ip in session_users:
        session_user = session_users[ip]
        if not session_user or session_user == queue_user:
            return None
        customer = find_customer(session_user)
        return customer if customer is not None and _allows_several_devices(customer) else None

    match = EXTRA_SESSION_RE.match(queue_user or "")
    if not match:
        return None
    customer = find_customer(match.group("base"))
    return customer if customer is not None and _allows_several_devices(customer) else None
