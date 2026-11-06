"""Check a newly provisioned router over its management tunnel and tell the reseller.

Why (Dennis, 2026-10-30: "check if it was correctly put and let the user
know"): the reseller pastes the setup command into the WinBox terminal and
then has no way to know whether it worked. Routers 673 (RB951Ui-2HnD, 7.12.1)
and 674 (hEX lite, 7.16.1) both logged "Provisioning complete! Rebooting in 5
seconds...", never rebooted, and kept the terminal's import as a stuck
/system script job; 673 sat at ~100% CPU for 35+ minutes and the reseller got
the "CPU above 90%, please restart" SMS instead of a "you're set up".

What happens now: /complete (the router registered) schedules
``verify_after_provisioning``. After a few minutes (the tunnel and the
post-registration installers go first) it logs in over the management tunnel
and runs a read-only checklist:

* hotspot enabled on the LAN bridge -- or, on a router set up for PPPoE
  (``dual_ports``/``pppoe_ports`` set, or a PPPoE server on the LAN bridge,
  e.g. router 674 converted on 2026-10-30), the PPPoE server, its profile and
  address pool, and the masquerade NAT instead;
* WAN: DHCP client on ether1 bound, or an active default route;
* DNS resolves (one plain-HTTP fetch by host name from the router);
* management tunnel reachable (the API login itself proves it);
* usage-push scheduler present (not expected on hAP lite/mini class boards);
* no stuck admin script jobs (seen twice, ~10 s apart, not ours);
* CPU not pegged (3 samples, all >= 90%).

Auto-fix, only when stuck jobs (and the CPU they burn) are the ONLY problem:
remove the stuck jobs, re-check, and if that did not clear it reboot the
router once (non-interactive, over the API) and re-check on the next attempt.
Nothing else on the router is ever changed here.

The result is stored on the provisioning token (``setup_check_*``, not the hot
routers row), and the reseller gets one inbox message + SMS (platform-paid,
like the overload alerts): "set up correctly", or a plain-language list of
what is wrong and what to do. Until the check passes, and for at most
``SETUP_GRACE`` after registration, CPU overload alerts are held back
(``in_setup_grace``), so a new reseller is not told to restart a router that is
still finishing setup.

DB discipline: every DB touch is its own short session; RouterOS I/O runs in a
thread with no session open.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timedelta
from typing import Callable, Optional

from sqlalchemy import or_, select, update

from app.config import settings
from app.db import database
from app.db.models import (
    MessagingSettings,
    ProvisioningToken,
    ResellerInboxMessage,
    Router,
    SmsMessage, SmsMessageKind, SmsMessageStatus,
    SubscriptionStatus,
    User,
)
from app.services.mikrotik_api import MikroTikAPI

logger = logging.getLogger(__name__)

# --- timing -------------------------------------------------------------------------

# /complete fires at the end of the import; the real-time push installer starts
# at +60 s and the standard runtime right away. Look after them, then retry.
# Attempts at ~4, 9, 19 and 34 minutes after registration.
FIRST_DELAY_SECONDS = 240
RETRY_DELAYS_SECONDS = (300, 600, 900)
# CPU overload alerts wait this long after registration unless the check passed.
SETUP_GRACE = timedelta(minutes=30)
# Startup catch-up: a deploy loses the in-memory task; re-queue recent ones.
CATCH_UP_WINDOW = timedelta(hours=2)
CATCH_UP_DELAY_SECONDS = 120

# --- checklist ----------------------------------------------------------------------

HOTSPOT_BRIDGE = "bridge"            # app.services.provisioning.HOTSPOT_BRIDGE
API_USERNAME = "bitwave-api"         # app.services.provisioning.API_USERNAME
WAN_INTERFACE = "ether1"
DNS_PROBE_URL = "http://isp.bitwavetechnologies.net/health"
CPU_PEGGED_PERCENT = 90
JOB_RESAMPLE_SECONDS = 10
JOB_REMOVE_SETTLE_SECONDS = 5

CHECK_HOTSPOT = "hotspot"
CHECK_PPPOE_SERVER = "pppoe_server"
CHECK_PPPOE_POOL = "pppoe_pool"
CHECK_NAT = "nat"
CHECK_WAN = "wan"
CHECK_DNS = "dns"
CHECK_TUNNEL = "mgmt_tunnel"
CHECK_PUSH = "usage_push"
CHECK_JOBS = "stuck_jobs"
CHECK_CPU = "cpu"
CHECK_ORDER = (CHECK_TUNNEL, CHECK_WAN, CHECK_DNS, CHECK_HOTSPOT, CHECK_PPPOE_SERVER, CHECK_PPPOE_POOL,
               CHECK_NAT, CHECK_JOBS, CHECK_CPU, CHECK_PUSH)
MODE_HOTSPOT = "hotspot"
MODE_PPPOE = "pppoe"

# Faults the reseller can see / act on. usage_push is ours: recorded, logged,
# never put in front of the reseller (customers work without it).
RESELLER_CHECKS = (CHECK_TUNNEL, CHECK_WAN, CHECK_DNS, CHECK_HOTSPOT, CHECK_PPPOE_SERVER,
                   CHECK_PPPOE_POOL, CHECK_NAT, CHECK_JOBS, CHECK_CPU)
# Faults that will not clear by waiting: two attempts in a row -> tell now.
STABLE_CHECKS = (CHECK_WAN, CHECK_DNS, CHECK_HOTSPOT, CHECK_PPPOE_SERVER, CHECK_PPPOE_POOL, CHECK_NAT)
# The only faults the auto-fix may act on.
AUTO_FIX_CHECKS = (CHECK_JOBS, CHECK_CPU)

STATUS_PENDING = "pending"
STATUS_PASSED = "passed"
STATUS_PASSED_WARN = "passed_with_warnings"
STATUS_FAILED = "failed"
STATUS_UNREACHABLE = "unreachable"
PASSED_STATUSES = (STATUS_PASSED, STATUS_PASSED_WARN)

SMS_CATEGORY = "router_setup_check"
_CUT_OFF_OWNER = (SubscriptionStatus.SUSPENDED, SubscriptionStatus.INACTIVE)
_SMALL_ARCHITECTURES = {"smips"}
_BITWAVE_SCRIPT_PREFIXES = ("bitwave", "bw-")


def _data(res) -> list:
    return (res or {}).get("data") or []


def _check(ok: Optional[bool], detail: str) -> dict:
    return {"ok": ok, "detail": detail}


def check_hotspot(hotspots: list) -> dict:
    on_bridge = [h for h in hotspots if h.get("interface") == HOTSPOT_BRIDGE]
    for h in on_bridge:
        if h.get("disabled") != "true" and h.get("invalid") != "true":
            return _check(True, f"hotspot {h.get('name') or ''} running on {HOTSPOT_BRIDGE}".replace("  ", " "))
    if on_bridge:
        return _check(False, f"hotspot on {HOTSPOT_BRIDGE} is disabled or invalid")
    others = sorted({h.get("interface") or "?" for h in hotspots})
    return _check(False, f"no hotspot on {HOTSPOT_BRIDGE}" + (f" (found on {', '.join(others)})" if others else ""))


def access_mode(router: dict, pppoe_servers: list) -> str:
    """PPPoE when the router was set up for it (DB ports) or serves PPPoE on the LAN bridge."""
    if router.get("dual_ports") or router.get("pppoe_ports"):
        return MODE_PPPOE
    if any(p.get("interface") == HOTSPOT_BRIDGE and p.get("disabled") != "true" for p in pppoe_servers):
        return MODE_PPPOE
    return MODE_HOTSPOT


def _enabled_pppoe_servers(pppoe_servers: list) -> list:
    return [p for p in pppoe_servers if p.get("disabled") != "true"]


def check_pppoe_server(pppoe_servers: list) -> dict:
    live = _enabled_pppoe_servers(pppoe_servers)
    if live:
        desc = ", ".join(f"{p.get('service-name') or '?'} on {p.get('interface') or '?'}" for p in live[:3])
        return _check(True, f"PPPoE server running: {desc}")
    if pppoe_servers:
        return _check(False, "PPPoE server is disabled")
    return _check(False, "no PPPoE server")


def check_pppoe_pool(pppoe_servers: list, profiles: list, pools: list) -> dict:
    """The server's default profile must exist with a local address and a remote pool/address."""
    live = _enabled_pppoe_servers(pppoe_servers)
    if not live:
        return _check(False, "no running PPPoE server to check the profile of")
    by_name = {p.get("name"): p for p in profiles}
    pool_names = {p.get("name") for p in pools}
    problems = []
    for server in live:
        name = server.get("default-profile") or "default"
        prof = by_name.get(name)
        if prof is None:
            problems.append(f"profile {name} missing")
            continue
        remote = prof.get("remote-address") or ""
        mine = []
        if not prof.get("local-address"):
            mine.append(f"profile {name} has no local address")
        if not remote:
            mine.append(f"profile {name} has no remote address/pool")
        elif remote[0].isalpha() and remote not in pool_names:
            mine.append(f"pool {remote} (profile {name}) missing")
        if not mine:
            return _check(True, f"profile {name}: local {prof.get('local-address')}, remote {remote}")
        problems.extend(mine)
    return _check(False, "; ".join(problems) or "PPPoE profile not usable")


def check_nat(nat_rules: list) -> dict:
    for r in nat_rules:
        if r.get("chain") == "srcnat" and r.get("action") == "masquerade" and r.get("disabled") != "true":
            return _check(True, f"masquerade on {r.get('out-interface') or r.get('src-address') or 'all'}")
    return _check(False, "no enabled masquerade NAT rule")


def check_wan(dhcp_clients: list, routes: list) -> dict:
    for c in dhcp_clients:
        if c.get("interface") == WAN_INTERFACE and c.get("disabled") != "true" and c.get("status") == "bound":
            return _check(True, f"DHCP client on {WAN_INTERFACE} bound ({c.get('address') or 'no address'})")
    for r in routes:
        if r.get("dst-address") == "0.0.0.0/0" and r.get("active") == "true":
            return _check(True, f"active default route via {r.get('gateway') or '?'}")
    status = next((c.get("status") for c in dhcp_clients if c.get("interface") == WAN_INTERFACE), None)
    return _check(False, f"no internet on {WAN_INTERFACE}: DHCP client "
                         f"{status or 'missing'}, no active default route")


def check_dns(fetch_result: dict) -> dict:
    """A fetch by host name: any HTTP answer, even an error status, proves DNS."""
    if fetch_result.get("success") or fetch_result.get("data"):
        return _check(True, "router resolved and reached the Bitwave server by name")
    err = str(fetch_result.get("error") or "")
    low = err.lower()
    if "resolv" in low or "dns" in low:
        return _check(False, f"DNS lookup failed ({err[:80]})")
    if "<" in err and any(f"<{d}" in err for d in "2345"):
        return _check(True, "router resolved the Bitwave server by name (HTTP answer)")
    if err:
        # Resolved, but the connection itself failed (blocked port, timeout).
        return _check(True, f"name resolved; fetch itself failed ({err[:80]})")
    return _check(None, "could not tell")


def check_usage_push(schedulers: list, arch: str) -> dict:
    from app.services.usage_push_script import SCHEDULER_NAME

    if not settings.REALTIME_PUSH_INSTALL_AT_SETUP:
        return _check(True, "not installed at setup (switched off)")
    if arch in _SMALL_ARCHITECTURES:
        return _check(True, f"not used on {arch} boards (server polling)")
    for s in schedulers:
        if s.get("name") == SCHEDULER_NAME:
            if s.get("disabled") == "true":
                return _check(False, f"{SCHEDULER_NAME} scheduler is disabled")
            return _check(True, f"{SCHEDULER_NAME} scheduler present")
    return _check(False, f"{SCHEDULER_NAME} scheduler missing")


def candidate_jobs(jobs: list) -> dict:
    """``.id -> job`` for script jobs that are not interactive logins and not ours."""
    out = {}
    for j in jobs:
        jtype = (j.get("type") or "").lower()
        if jtype == "login" or jtype.startswith("api"):
            continue
        if (j.get("owner") or "") == API_USERNAME:
            continue
        script = (j.get("script") or "").lower()
        if script.startswith(_BITWAVE_SCRIPT_PREFIXES):
            continue
        if j.get(".id"):
            out[j[".id"]] = j
    return out


def stuck_jobs(first: list, second: list) -> list:
    """Candidates present in both samples (~10 s apart)."""
    a, b = candidate_jobs(first), candidate_jobs(second)
    return [b[i] for i in b if i in a]


def check_jobs(stuck: list) -> dict:
    if not stuck:
        return _check(True, "no stuck script jobs")
    desc = ", ".join(f"{j.get('type') or '?'} by {j.get('owner') or '?'} since {j.get('started') or '?'}"
                     for j in stuck[:3])
    return _check(False, f"{len(stuck)} stuck script job(s): {desc}")


def check_cpu(samples: list) -> dict:
    if not samples:
        return _check(None, "CPU not read")
    if min(samples) >= CPU_PEGGED_PERCENT:
        return _check(False, f"CPU pegged: {samples}")
    return _check(True, f"CPU {samples}")


def _cpu_samples(api, n: int = 3, gap: float = 1.0, sleep: Callable = time.sleep) -> list:
    out = []
    for i in range(n):
        res = _data(api.send_command("/system/resource/print"))
        if res:
            try:
                out.append(int(res[0].get("cpu-load") or 0))
            except ValueError:
                pass
        if i < n - 1:
            sleep(gap)
    return out


def faults(checks: dict, keys=RESELLER_CHECKS) -> list:
    return [k for k in CHECK_ORDER if k in keys and (checks.get(k) or {}).get("ok") is False]


def check_router(router: dict, *, remediate: bool = False, allow_reboot: bool = False,
                 api_factory=MikroTikAPI, sleep: Callable = time.sleep) -> dict:
    """Run the checklist on one router. Blocking I/O; never raises.

    Read-only unless ``remediate``: then stuck jobs (when they and the CPU they
    burn are the only reseller-facing faults) are removed, and if that does not
    clear them and ``allow_reboot`` the router is rebooted once.
    """
    result: dict = {"checked_at": datetime.utcnow().isoformat(), "reachable": False,
                    "checks": {}, "fixes": [], "rebooted": False}
    api = api_factory(router["ip_address"], router["username"], router["password"],
                      router.get("port") or 8728, timeout=30)
    try:
        if not api.connect():
            result["checks"][CHECK_TUNNEL] = _check(False, "router did not answer over the management tunnel")
            return result
    except Exception as exc:  # noqa: BLE001
        result["checks"][CHECK_TUNNEL] = _check(False, f"connect failed: {str(exc)[:120]}")
        return result
    try:
        c = lambda p, a=None: api.send_command(p, a or {})  # noqa: E731
        result["reachable"] = True
        checks = result["checks"]
        checks[CHECK_TUNNEL] = _check(True, f"API answered at {router['ip_address']}")
        ident = (_data(c("/system/identity/print")) or [{}])[0].get("name")
        if router.get("identity") and ident != router.get("identity"):
            result["identity_mismatch"] = ident
            checks[CHECK_TUNNEL] = _check(False, f"another router answered at {router['ip_address']} ({ident})")
            return result
        res = (_data(c("/system/resource/print")) or [{}])[0]
        arch = res.get("architecture-name") or ""
        result.update(board=res.get("board-name"), ros=res.get("version"), arch=arch)

        jobs_first = _data(c("/system/script/job/print"))
        pppoe_servers = _data(c("/interface/pppoe-server/server/print"))
        result["mode"] = access_mode(router, pppoe_servers)
        if result["mode"] == MODE_PPPOE:
            checks[CHECK_PPPOE_SERVER] = check_pppoe_server(pppoe_servers)
            checks[CHECK_PPPOE_POOL] = check_pppoe_pool(pppoe_servers, _data(c("/ppp/profile/print")),
                                                        _data(c("/ip/pool/print")))
            checks[CHECK_NAT] = check_nat(_data(c("/ip/firewall/nat/print")))
        else:
            checks[CHECK_HOTSPOT] = check_hotspot(_data(c("/ip/hotspot/print")))
        checks[CHECK_WAN] = check_wan(_data(c("/ip/dhcp-client/print")), _data(c("/ip/route/print")))
        checks[CHECK_DNS] = check_dns(c("/tool/fetch", {"url": DNS_PROBE_URL, "output": "user",
                                                       "as-value": ""}))
        checks[CHECK_PUSH] = check_usage_push(_data(c("/system/scheduler/print")), arch)
        cpu = _cpu_samples(api, sleep=sleep)
        sleep(JOB_RESAMPLE_SECONDS)
        stuck = stuck_jobs(jobs_first, _data(c("/system/script/job/print")))
        checks[CHECK_JOBS] = check_jobs(stuck)
        checks[CHECK_CPU] = check_cpu(cpu + _cpu_samples(api, n=1, sleep=sleep))

        bad = faults(checks)
        if not (remediate and stuck and set(bad) <= set(AUTO_FIX_CHECKS)):
            return result

        # --- auto-fix: stuck jobs are the only problem --------------------------------
        for job in stuck:
            r = c("/system/script/job/remove", {".id": job[".id"]})
            result["fixes"].append({"action": "remove_job", "job": job.get(".id"),
                                    "type": job.get("type"), "owner": job.get("owner"),
                                    "ok": not r.get("error"), "error": str(r.get("error") or "")[:120] or None})
        sleep(JOB_REMOVE_SETTLE_SECONDS)
        left = [j for j in candidate_jobs(_data(c("/system/script/job/print"))).values()
                if j.get(".id") in {s.get(".id") for s in stuck}]
        checks[CHECK_JOBS] = check_jobs(left)
        checks[CHECK_CPU] = check_cpu(_cpu_samples(api, sleep=sleep))
        if left:
            checks[CHECK_JOBS]["detail"] += " (removal did not take)"
        elif checks[CHECK_JOBS]["ok"]:
            checks[CHECK_JOBS]["detail"] = f"{len(stuck)} stuck job(s) removed"
        if faults(checks) and allow_reboot:
            r = api.reboot_router()
            result["fixes"].append({"action": "reboot", "ok": bool(r.get("success")),
                                    "status": r.get("status") or r.get("error")})
            result["rebooted"] = bool(r.get("success"))
        return result
    except Exception as exc:  # noqa: BLE001 - never break the caller
        result["error"] = str(exc)[:200]
        return result
    finally:
        try:
            api.disconnect()
        except Exception:  # noqa: BLE001
            pass


def verdict(result: dict) -> str:
    checks = result.get("checks") or {}
    if not result.get("reachable"):
        return STATUS_UNREACHABLE
    if faults(checks):
        return STATUS_FAILED
    if faults(checks, keys=CHECK_ORDER):
        return STATUS_PASSED_WARN
    return STATUS_PASSED


# --- reseller copy --------------------------------------------------------------------

_ADVICE = {
    CHECK_TUNNEL: ("The router has not connected to Bitwave",
                   "check that the router is powered on and the internet cable from your modem "
                   "or ISP is in port 1 (ether1)"),
    CHECK_WAN: ("The router has no internet on port 1",
                "plug the cable from your modem or ISP into port 1 (ether1) and make sure that "
                "line has internet"),
    CHECK_DNS: ("The router cannot look up websites (DNS)",
                "check that your internet line works, then restart the router once"),
    CHECK_HOTSPOT: ("The hotspot is not running, so customers will not see the login page",
                    "paste the setup command into the WinBox terminal again"),
    CHECK_PPPOE_SERVER: ("The PPPoE server is not running, so PPPoE customers cannot connect",
                         "contact Bitwave support to re-run the PPPoE setup for this router"),
    CHECK_PPPOE_POOL: ("The PPPoE settings are incomplete (profile or address pool missing)",
                       "contact Bitwave support to re-run the PPPoE setup for this router"),
    CHECK_NAT: ("Customers will connect but get no internet (NAT rule missing)",
                "contact Bitwave support to re-run the setup for this router"),
    CHECK_JOBS: ("The setup command is still stuck in the WinBox terminal",
                 "close WinBox and restart the router once"),
    CHECK_CPU: ("The router is very busy (CPU above 90%)",
                "restart it once; if it stays busy, contact Bitwave support"),
}
_SMS_SHORT = {
    CHECK_TUNNEL: "not connected to Bitwave",
    CHECK_WAN: "no internet on port 1",
    CHECK_DNS: "cannot look up websites",
    CHECK_HOTSPOT: "hotspot not running",
    CHECK_PPPOE_SERVER: "PPPoE server not running",
    CHECK_PPPOE_POOL: "PPPoE settings incomplete",
    CHECK_NAT: "no internet for customers (NAT)",
    CHECK_JOBS: "setup stuck in WinBox",
    CHECK_CPU: "CPU too busy",
}


def render_message(name: str, status: str, result: dict) -> tuple[str, str, str]:
    """(subject, inbox body, sms body)."""
    if status in PASSED_STATUSES:
        access = "PPPoE" if result.get("mode") == MODE_PPPOE else "Hotspot"
        body = (f"Bitwave: your router '{name}' is set up correctly. {access}, internet and the "
                f"Bitwave connection all checked OK. Customers can now connect and pay.")
        return f"Router set up: {name}", body, body
    keys = faults(result.get("checks") or {}) or [CHECK_TUNNEL]
    lines = [f"{i}. {_ADVICE[k][0]}: {_ADVICE[k][1]}." for i, k in enumerate(keys, 1)]
    body = (f"Bitwave: we checked your new router '{name}' and found a problem:\n" + "\n".join(lines)
            + "\nWe will check again automatically after you fix it. Need help? Reply to this message.")
    sms = (f"Bitwave: your new router '{name}' needs attention: "
           + "; ".join(_SMS_SHORT[k] for k in keys[:3])
           + ". What to do is in your Bitwave inbox.")
    return f"Router setup needs attention: {name}", body, sms


# --- persistence ----------------------------------------------------------------------

def in_setup_grace(provisioned_at: Optional[datetime], check_status: Optional[str],
                   now: Optional[datetime] = None) -> bool:
    """True while a just-registered router is still being checked."""
    if provisioned_at is None or check_status in PASSED_STATUSES:
        return False
    now = now or datetime.utcnow()
    return timedelta(0) <= now - provisioned_at < SETUP_GRACE


async def setup_grace_active(db, router_id: int, now: Optional[datetime] = None) -> bool:
    """Read helper for alert paths (caller's session; one indexed read)."""
    row = (await db.execute(
        select(ProvisioningToken.provisioned_at, ProvisioningToken.setup_check_status)
        .where(ProvisioningToken.router_id == router_id)
        .order_by(ProvisioningToken.provisioned_at.desc().nullslast())
        .limit(1)
    )).first()
    return bool(row) and in_setup_grace(row[0], row[1], now)


def _open_status():
    return or_(ProvisioningToken.setup_check_status.is_(None),
               ProvisioningToken.setup_check_status == STATUS_PENDING)


async def _store_pending(router_id: int, result: dict) -> None:
    async with database.async_session() as db:
        await db.execute(
            update(ProvisioningToken)
            .where(ProvisioningToken.router_id == router_id, _open_status())
            .values(setup_check_status=STATUS_PENDING, setup_check_at=datetime.utcnow(),
                    setup_check_result=result)
            .execution_options(synchronize_session=False)
        )
        await db.commit()


async def _load_router(router_id: int) -> Optional[dict]:
    async with database.async_session() as db:
        r = await db.get(Router, router_id)
        info = None if r is None else {
            "id": r.id, "name": r.name, "identity": r.identity, "ip_address": r.ip_address,
            "username": r.username, "password": r.password, "port": r.port,
            "dual_ports": r.dual_ports or [], "pppoe_ports": r.pppoe_ports or [],
        }
        await db.commit()
    return info


async def finish(router_id: int, status: str, result: dict, *, notify: bool = True) -> bool:
    """Store the final verdict and, once, tell the reseller. Own session; never raises.

    The UPDATE only matches a token still open (NULL/pending), so a re-run after
    a restart cannot message the reseller twice. Returns True if a message was made.
    """
    from app.services.reseller_welcome import _resolve_sender_admin_id
    from app.services.messaging import count_segments
    from app.services.messaging import accounts as provider_accounts
    from app.services import router_overload_alerts as oa

    try:
        sms_id = sender_id = None
        async with database.async_session() as db:
            router = await db.get(Router, router_id)
            owner = await db.get(User, router.user_id) if router else None
            name = (router.name if router else None) or f"#{router_id}"
            subject, body, sms_body = render_message(name, status, result)
            told = bool(notify and owner is not None and owner.subscription_status not in _CUT_OFF_OWNER)
            admin_id = await _resolve_sender_admin_id(db, owner) if told else None
            told = told and admin_id is not None
            stored = {**result, "status": status, "notified": told}
            claim = await db.execute(
                update(ProvisioningToken)
                .where(ProvisioningToken.router_id == router_id, _open_status())
                .values(setup_check_status=status, setup_check_at=datetime.utcnow(),
                        setup_check_result=stored)
                .execution_options(synchronize_session=False)
            )
            if claim.rowcount < 1 or not told:
                await db.commit()
                return False
            phone = (owner.support_phone or "").strip()
            settings_row = await db.get(MessagingSettings, 1)
            messaging_on = settings_row is None or bool(settings_row.enabled)
            if settings.SMS_DISPATCH_ENABLED and messaging_on and phone and router.status_alerts_enabled:
                row = SmsMessage(
                    user_id=owner.id, recipient_phone=phone, body=sms_body,
                    segments=count_segments(sms_body), credits_charged=0,
                    kind=SmsMessageKind.ADMIN_TO_RESELLER, category=SMS_CATEGORY,
                    status=SmsMessageStatus.QUEUED,
                )
                db.add(row)
                await db.flush()
                sms_id = row.id
                sender_id = await provider_accounts.resolve_sender_id_for(
                    db, None, settings_row.sender_id if settings_row else None)
            db.add(ResellerInboxMessage(recipient_user_id=owner.id, sender_user_id=admin_id,
                                        subject=subject, body=body, sent_sms=sms_id is not None))
            await db.commit()
        if sms_id is not None:
            oa._spawn_sms(sms_id, sender_id)
        logger.info("[SETUP-CHECK] router %s: %s, reseller told (sms=%s)", router_id, status, sms_id is not None)
        return True
    except Exception:
        logger.exception("[SETUP-CHECK] could not store/notify result for router %s", router_id)
        return False


# --- orchestration --------------------------------------------------------------------

def _summary(result: dict) -> dict:
    return {k: (v or {}).get("ok") for k, v in (result.get("checks") or {}).items()}


async def verify_after_provisioning(router_id: int, *, first_delay: float = FIRST_DELAY_SECONDS,
                                    sleep=asyncio.sleep, check=check_router) -> dict:
    """Check a freshly registered router until it passes or we give up, then tell the reseller.

    Never raises. Returns the last result with ``status``.
    """
    if not settings.PROVISION_VERIFY_ENABLED:
        return {"id": router_id, "status": "disabled"}
    history: list = []
    result: dict = {"id": router_id, "status": STATUS_PENDING}
    try:
        await _store_pending(router_id, {"attempts": []})
        if first_delay:
            await sleep(first_delay)
        rebooted = False
        prev_stable: Optional[list] = None
        delays = (0,) + RETRY_DELAYS_SECONDS
        for i, delay in enumerate(delays):
            if delay:
                await sleep(delay)
            info = await _load_router(router_id)          # short session, released
            if info is None:
                return {"id": router_id, "status": "no_router"}
            res = await asyncio.to_thread(check, info, remediate=settings.PROVISION_VERIFY_AUTO_FIX,
                                          allow_reboot=not rebooted)
            status = verdict(res)
            history.append({"at": res.get("checked_at"), "status": status, "checks": _summary(res),
                            "fixes": res.get("fixes") or []})
            result = {**res, "id": router_id, "status": status, "attempts": history}
            if res.get("rebooted"):
                rebooted = True
                await _record_reboot(router_id)
            last = i == len(delays) - 1
            stable = [k for k in faults(res.get("checks") or {}) if k in STABLE_CHECKS]
            if status in PASSED_STATUSES:
                await finish(router_id, status, result)
                break
            if last or (stable and stable == prev_stable and not res.get("rebooted")):
                await finish(router_id, status, result)
                break
            prev_stable = stable
            await _store_pending(router_id, result)
        logger.info("[SETUP-CHECK] router %s: %s after %s attempt(s) %s", router_id, result.get("status"),
                    len(history), _summary(result))
    except Exception:  # noqa: BLE001
        logger.exception("[SETUP-CHECK] verification for router %s crashed", router_id)
    return result


async def _record_reboot(router_id: int) -> None:
    """A reboot we sent takes the router down on purpose (see router_operations)."""
    try:
        from app.services.router_availability import record_router_availability
        await record_router_availability(None, router_id, False, "setup_check_reboot", confirm_offline=True)
    except Exception:  # noqa: BLE001
        logger.exception("[SETUP-CHECK] could not record the reboot of router %s", router_id)


_tasks: set = set()


def schedule_verify_after_provisioning(router_id: int, *, first_delay: float = FIRST_DELAY_SECONDS) -> None:
    """Fire-and-forget from the /complete callback. Never raises."""
    try:
        task = asyncio.get_running_loop().create_task(
            verify_after_provisioning(router_id, first_delay=first_delay))
        _tasks.add(task)
        task.add_done_callback(_tasks.discard)
    except Exception:  # noqa: BLE001
        logger.exception("[SETUP-CHECK] could not schedule verification for router %s", router_id)


async def routers_to_resume(now: Optional[datetime] = None) -> list[int]:
    """Recently registered routers whose check never finished (lost to a deploy)."""
    now = now or datetime.utcnow()
    async with database.async_session() as db:
        rows = (await db.execute(
            select(ProvisioningToken.router_id)
            .where(ProvisioningToken.router_id.isnot(None),
                   ProvisioningToken.provisioned_at >= now - CATCH_UP_WINDOW,
                   _open_status())
        )).scalars().all()
        await db.commit()
    return sorted({r for r in rows if r})


async def catch_up_after_restart(*, sleep=asyncio.sleep, schedule=schedule_verify_after_provisioning) -> list[int]:
    if not settings.PROVISION_VERIFY_ENABLED:
        return []
    try:
        await sleep(CATCH_UP_DELAY_SECONDS)
        ids = await routers_to_resume()
        for router_id in ids:
            schedule(router_id, first_delay=0)
        if ids:
            logger.info("[SETUP-CHECK] startup catch-up: verification re-queued for routers %s", ids)
        return ids
    except Exception:  # noqa: BLE001
        logger.exception("[SETUP-CHECK] startup catch-up failed")
        return []


def schedule_catch_up_after_restart() -> None:
    try:
        task = asyncio.get_running_loop().create_task(catch_up_after_restart())
        _tasks.add(task)
        task.add_done_callback(_tasks.discard)
    except Exception:  # noqa: BLE001
        logger.exception("[SETUP-CHECK] could not schedule the startup catch-up")
