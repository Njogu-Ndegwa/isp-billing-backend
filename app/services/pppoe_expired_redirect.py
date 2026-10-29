"""PPPoE expired redirect: a captive portal for expired PPPoE customers.

Per-router opt-in (``routers.pppoe_expired_redirect``). With it on, an expired
PPPoE customer is not removed from the router. Their secret is kept and moved
to the walled ``bw-pppoe-expired`` profile, and the session is kicked so the
CPE redials into it:

* the walled profile hands out addresses from its own pool (a /22 that does
  not overlap anything on the router) and puts the session in the
  ``BW_PPPOE_EXPIRED`` address list;
* DNS is allowed, and so are the portal and API hosts (``BW_PPPOE_EXPIRED_ALLOW``
  plus the anti-tunnel ``isp_portal_allow`` list when the router has it);
* plain HTTP (tcp/80) to anywhere else is redirected to the router's own web
  proxy, whose access list answers every request with a redirect to the
  portal's expired page (router id, and the username when the profile's on-up
  script could add a per-session rule). The OS captive-portal probes are plain
  HTTP, so phones and laptops behind the customer's CPE show "Sign in to
  network";
* everything else (HTTPS included) is rejected at once, tcp-reset for TCP, so
  browsers and apps fail fast instead of hanging. HTTPS cannot be redirected
  without a certificate warning; it can only be refused.

Paying (portal STK, paybill C2B, reseller Activate) runs the normal PPPoE
provisioning, which sets the secret back to the plan profile and kicks the
session, so the customer is restored with no extra step.

Everything this module puts on a router carries a comment starting
``ISP_BILLING_PPPOE_EXPIRED`` (pool and profile are named ``bw-pppoe-expired``),
and every apply is idempotent: a router already in the right state gets no
writes. Nothing here touches the hotspot's dynamic rules, the anti-tunnel
output rule, load-balancing mangle/routes, or plain/PPPoE port setup: the rules
match only the walled pool's address list.

Functions taking ``api`` are synchronous RouterOS work for a thread; the
caller owns the connection and must not hold a DB session meanwhile.
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from app.config import settings

logger = logging.getLogger("pppoe_expired_redirect")

EXPIRED_PROFILE = "bw-pppoe-expired"
EXPIRED_POOL = "bw-pppoe-expired"
EXPIRED_LIST = "BW_PPPOE_EXPIRED"
ALLOW_LIST = "BW_PPPOE_EXPIRED_ALLOW"
PORTAL_ALLOW_LIST = "isp_portal_allow"  # the hotspot anti-tunnel allow-list

COMMENT_PREFIX = "ISP_BILLING_PPPOE_EXPIRED"
COMMENT_POOL = f"{COMMENT_PREFIX}_POOL"
COMMENT_ALLOW = f"{COMMENT_PREFIX}_ALLOW"
COMMENT_REDIRECT = f"{COMMENT_PREFIX}_REDIRECT"
COMMENT_USER = f"{COMMENT_PREFIX}_USER"

# /22s (1,021 walled sessions). 10.255.0.0/16 is avoided on purpose: it is what
# One ISP's routers used for the same job, and second-hand routers keep it.
EXPIRED_CIDR_CANDIDATES = (
    "10.254.252.0/22",
    "10.253.252.0/22",
    "172.31.252.0/22",
    "192.168.252.0/22",
)

SYNTAX_REDIRECT_TO = "redirect-to"   # action=deny redirect-to=URL (RouterOS 6, most 7)
SYNTAX_ACTION_DATA = "action-data"   # action=redirect action-data=URL (fallback)


class RedirectError(Exception):
    pass


# ---------------------------------------------------------------------------
# small RouterOS helpers
# ---------------------------------------------------------------------------


def _rows(api, menu: str) -> List[Dict[str, Any]]:
    result = api.send_command(f"{menu}/print")
    if not result.get("success"):
        raise RedirectError(f"could not read {menu}: {result.get('error')}")
    return list(result.get("data") or [])


def _write(api, command: str, args: Dict[str, Any]) -> Dict[str, Any]:
    result = api.send_command(command, args)
    if result.get("error"):
        raise RedirectError(f"{command}: {result['error']}")
    return result


def _truthy(value: Any) -> bool:
    return str(value).strip().lower() in ("true", "yes")


def _norm(value: Any) -> str:
    """Compare script bodies the way RouterOS may re-print them (CRLF, trailing space)."""
    return " ".join(str(value or "").split())


def _ours(row: Dict[str, Any]) -> bool:
    return str(row.get("comment") or "").startswith(COMMENT_PREFIX)


def _csv(value: str) -> List[str]:
    return [part.strip() for part in str(value or "").split(",") if part.strip()]


def layout_for(cidr: str) -> Dict[str, str]:
    net = ipaddress.ip_network(cidr)
    return {
        "cidr": str(net),
        "local_address": str(net.network_address + 1),
        "pool_range": f"{net.network_address + 2}-{net.broadcast_address - 1}",
    }


def portal_url(router_id: int) -> str:
    base = settings.PPPOE_EXPIRED_PORTAL_URL
    sep = "&" if "?" in base else "?"
    return f"{base}{sep}r={int(router_id)}"


def allow_addresses() -> List[str]:
    """What a walled customer may still reach, besides DNS."""
    out: List[str] = []
    for value in (
        _csv(settings.PPPOE_EXPIRED_ALLOW_HOSTS)
        + _csv(settings.PPPOE_EXPIRED_ALLOW_CIDRS)
        + [settings.INSURANCE_SERVER_PUBLIC_IP, settings.SERVER_PUBLIC_IP]
    ):
        value = (value or "").strip()
        if value and value not in out:
            out.append(value)
    return out


# ---------------------------------------------------------------------------
# choosing the walled pool
# ---------------------------------------------------------------------------


def _networks_in_use(api, own_cidr: Optional[str]) -> List[Any]:
    own = ipaddress.ip_network(own_cidr) if own_cidr else None

    def _inside_own(net) -> bool:
        return bool(own and net.version == 4 and net.subnet_of(own))

    nets = []
    for row in _rows(api, "/ip/address"):
        for value in (row.get("address"), row.get("network")):
            try:
                net = ipaddress.ip_network(str(value or "").strip(), strict=False)
            except ValueError:
                continue
            if not _inside_own(net):
                nets.append(net)
    for pool in _rows(api, "/ip/pool"):
        if pool.get("name") == EXPIRED_POOL:
            continue
        for part in str(pool.get("ranges") or "").split(","):
            part = part.strip()
            try:
                if "-" in part:
                    lo, hi = (p.strip() for p in part.split("-", 1))
                    nets.extend(ipaddress.summarize_address_range(
                        ipaddress.ip_address(lo), ipaddress.ip_address(hi)))
                elif part:
                    nets.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                continue
    for route in _rows(api, "/ip/route"):
        try:
            net = ipaddress.ip_network(str(route.get("dst-address") or "").strip(), strict=False)
        except ValueError:
            continue
        if net.prefixlen == 0 or _inside_own(net):
            continue
        nets.append(net)
    return nets


def choose_expired_cidr(api, current: Optional[str] = None) -> str:
    """Keep the walled pool where it is unless it now overlaps something."""
    in_use = _networks_in_use(api, current)
    candidates = ([current] if current else []) + [
        c for c in EXPIRED_CIDR_CANDIDATES if c != current
    ]
    for cidr in candidates:
        net = ipaddress.ip_network(cidr)
        if not any(net.overlaps(other) for other in in_use if other.version == 4):
            return cidr
    raise RedirectError(
        "No free subnet for the expired-customer pool: every candidate "
        f"({', '.join(EXPIRED_CIDR_CANDIDATES)}) overlaps an address, pool or "
        "route on this router"
    )


def _current_cidr(api, config: Dict[str, Any]) -> Optional[str]:
    if config.get("cidr"):
        return config["cidr"]
    for pool in _rows(api, "/ip/pool"):
        if pool.get("name") != EXPIRED_POOL:
            continue
        first = str(pool.get("ranges") or "").split(",")[0].split("-")[0].strip()
        for cidr in EXPIRED_CIDR_CANDIDATES:
            try:
                if ipaddress.ip_address(first) in ipaddress.ip_network(cidr):
                    return cidr
            except ValueError:
                return None
    return None


# ---------------------------------------------------------------------------
# rendered router objects
# ---------------------------------------------------------------------------


def _access_action(syntax: str, url: str) -> Dict[str, str]:
    if syntax == SYNTAX_ACTION_DATA:
        return {"action": "redirect", "action-data": url}
    return {"action": "deny", "redirect-to": url}


def render_on_up(router_id: int, port: int, syntax: str) -> str:
    """PPP on-up for the walled profile: a per-session proxy rule that sends
    this session's browser to the expired page WITH its username.

    The catch-all rule (router id only) still answers if this ever fails.
    Usernames outside [A-Za-z0-9._@-] are left out of the URL rather than
    URL-encoded in RouterOS script; the page then asks for the account.
    """
    url = portal_url(router_id)
    if syntax == SYNTAX_ACTION_DATA:
        action = 'action=redirect action-data=$url'
    else:
        action = 'action=deny redirect-to=$url'
    return (
        f':local u $user\n'
        f':local a $"remote-address"\n'
        f':local c ("{COMMENT_USER} " . $a . " " . $u)\n'
        f':local url "{url}"\n'
        f':if ($u ~ "^[A-Za-z0-9._@-]+\\$") do={{ :set url ($url . "&u=" . $u) }}\n'
        f':do {{ /ip proxy access remove [find where comment~("^{COMMENT_USER} " . $a . " ")] }} on-error={{}}\n'
        f':local f [/ip proxy access find]\n'
        f':do {{\n'
        f'  :if ([:len $f] > 0) do={{\n'
        f'    /ip proxy access add src-address=$a local-port={int(port)} {action} comment=$c place-before=[:pick $f 0]\n'
        f'  }} else={{\n'
        f'    /ip proxy access add src-address=$a local-port={int(port)} {action} comment=$c\n'
        f'  }}\n'
        f'}} on-error={{ :log warning ("bw-pppoe-expired: no redirect rule for " . $u) }}\n'
    )


def render_on_down() -> str:
    return (
        ':local c ("' + COMMENT_USER + ' " . $"remote-address" . " " . $user)\n'
        ':do { /ip proxy access remove [find where comment=$c] } on-error={}\n'
    )


def desired_filter_rules(cidr: str, port: int, guard_proxy: bool) -> List[Dict[str, str]]:
    src = {"src-address-list": EXPIRED_LIST}
    rules = [
        {"chain": "forward", **src, "protocol": "udp", "dst-port": "53", "action": "accept",
         "comment": f"{COMMENT_PREFIX}_DNS_UDP"},
        {"chain": "forward", **src, "protocol": "tcp", "dst-port": "53", "action": "accept",
         "comment": f"{COMMENT_PREFIX}_DNS_TCP"},
        {"chain": "forward", **src, "dst-address-list": ALLOW_LIST, "action": "accept",
         "comment": f"{COMMENT_PREFIX}_ALLOW_HOSTS"},
        {"chain": "forward", **src, "dst-address-list": PORTAL_ALLOW_LIST, "action": "accept",
         "comment": f"{COMMENT_PREFIX}_ALLOW_PORTAL"},
        # Fast refusal: HTTPS and apps get a TCP reset, not a timeout.
        {"chain": "forward", **src, "protocol": "tcp", "action": "reject",
         "reject-with": "tcp-reset", "comment": f"{COMMENT_PREFIX}_REJECT_TCP"},
        {"chain": "forward", **src, "action": "reject",
         "reject-with": "icmp-admin-prohibited", "comment": f"{COMMENT_PREFIX}_REJECT"},
        # The redirected HTTP lands on the router's proxy (input chain); a
        # defconf "drop all not coming from LAN" would otherwise eat it.
        {"chain": "input", **src, "protocol": "tcp", "dst-port": str(int(port)), "action": "accept",
         "comment": f"{COMMENT_PREFIX}_INPUT_PROXY"},
        {"chain": "input", **src, "protocol": "udp", "dst-port": "53", "action": "accept",
         "comment": f"{COMMENT_PREFIX}_INPUT_DNS_UDP"},
        {"chain": "input", **src, "protocol": "tcp", "dst-port": "53", "action": "accept",
         "comment": f"{COMMENT_PREFIX}_INPUT_DNS_TCP"},
    ]
    if guard_proxy:
        # We switched the web proxy on: nobody else (WAN!) may use it.
        rules.append({"chain": "input", "protocol": "tcp", "dst-port": str(int(port)),
                      "action": "drop", "comment": f"{COMMENT_PREFIX}_PROXY_GUARD"})
    return rules


def desired_nat_rules(cidr: str, port: int) -> List[Dict[str, str]]:
    return [
        {"chain": "dstnat", "src-address-list": EXPIRED_LIST, "protocol": "tcp", "dst-port": "80",
         "dst-address-list": f"!{ALLOW_LIST}", "action": "redirect", "to-ports": str(int(port)),
         "comment": COMMENT_REDIRECT},
        {"chain": "srcnat", "src-address": cidr, "action": "masquerade",
         "comment": f"{COMMENT_PREFIX}_NAT"},
    ]


# ---------------------------------------------------------------------------
# idempotent reconcilers
# ---------------------------------------------------------------------------


def _row_matches(row: Dict[str, Any], want: Dict[str, Any]) -> bool:
    if _truthy(row.get("disabled")):
        return False
    return all(str(row.get(k, "")) == str(v) for k, v in want.items())


def _reconcile_chain_rules(api, menu: str, desired: List[Dict[str, str]]) -> int:
    """Our rules, in order, ahead of every other static rule of their chain.

    Returns the number of writes (0 when the router already matches). Dynamic
    rules (hotspot, PPP) are never touched or counted.
    """
    rows = [r for r in _rows(api, menu) if not _truthy(r.get("dynamic"))]
    wanted_chains = {d["chain"] for d in desired}
    ok = not any(_ours(r) and r.get("chain") not in wanted_chains for r in rows)
    for chain in wanted_chains:
        if not ok:
            break
        chain_rows = [r for r in rows if r.get("chain") == chain]
        lead = []
        for r in chain_rows:
            if not _ours(r):
                break
            lead.append(r)
        ours = [r for r in chain_rows if _ours(r)]
        want = [d for d in desired if d["chain"] == chain]
        if len(lead) != len(ours) or len(ours) != len(want):
            ok = False
        elif not all(_row_matches(r, d) for r, d in zip(ours, want)):
            ok = False
    if ok:
        return 0

    writes = 0
    for r in rows:
        if _ours(r) and r.get(".id"):
            _write(api, f"{menu}/remove", {"numbers": r[".id"]})
            writes += 1
    rows = [r for r in _rows(api, menu) if not _truthy(r.get("dynamic"))]
    for d in desired:
        anchor = next(
            (r.get(".id") for r in rows if r.get("chain") == d["chain"] and not _ours(r) and r.get(".id")),
            None,
        )
        args = dict(d)
        if anchor:
            args["place-before"] = anchor
        _write(api, f"{menu}/add", args)
        writes += 1
    return writes


def _reconcile_address_list(api, list_name: str, comment: str, addresses: Iterable[str]) -> int:
    wanted = list(dict.fromkeys(addresses))
    rows = [
        r for r in _rows(api, "/ip/firewall/address-list")
        if r.get("list") == list_name and not _truthy(r.get("dynamic")) and r.get("comment") == comment
    ]
    writes = 0
    have = set()
    for r in rows:
        addr = str(r.get("address") or "")
        if addr in wanted and addr not in have and not _truthy(r.get("disabled")):
            have.add(addr)
            continue
        if r.get(".id"):
            _write(api, "/ip/firewall/address-list/remove", {"numbers": r[".id"]})
            writes += 1
    for addr in wanted:
        if addr not in have:
            _write(api, "/ip/firewall/address-list/add",
                   {"list": list_name, "address": addr, "comment": comment})
            writes += 1
    return writes


def _ensure_pool(api, layout: Dict[str, str]) -> int:
    for pool in _rows(api, "/ip/pool"):
        if pool.get("name") == EXPIRED_POOL:
            if str(pool.get("ranges") or "") == layout["pool_range"]:
                return 0
            _write(api, "/ip/pool/set", {"numbers": pool[".id"], "ranges": layout["pool_range"]})
            return 1
    _write(api, "/ip/pool/add", {"name": EXPIRED_POOL, "ranges": layout["pool_range"]})
    return 1


def _base_dns(api) -> str:
    try:
        base = api.get_active_pppoe_profile()
        if base.get("found"):
            dns = (base.get("data") or {}).get("dns_server") or ""
            if dns:
                return dns
    except Exception as exc:  # a lookup, never fatal
        logger.debug("expired redirect: base PPPoE profile lookup failed: %s", exc)
    return settings.PPPOE_EXPIRED_DNS


def _ensure_profile(api, *, router_id: int, layout: Dict[str, str], port: int,
                    syntax: str, with_address_list: bool) -> tuple[int, bool]:
    want = {
        "local-address": layout["local_address"],
        "remote-address": EXPIRED_POOL,
        "rate-limit": settings.PPPOE_EXPIRED_RATE_LIMIT,
        "dns-server": _base_dns(api),
        "only-one": "no",
        "change-tcp-mss": "yes",
        "on-up": render_on_up(router_id, port, syntax),
        "on-down": render_on_down(),
    }
    if with_address_list:
        want["address-list"] = EXPIRED_LIST
    existing = next((p for p in _rows(api, "/ppp/profile") if p.get("name") == EXPIRED_PROFILE), None)
    if existing and all(_norm(existing.get(k, "")) == _norm(v) for k, v in want.items()):
        return 0, with_address_list
    if existing:
        command, args = "/ppp/profile/set", {"numbers": existing[".id"], **want}
    else:
        command, args = "/ppp/profile/add", {"name": EXPIRED_PROFILE, **want}
    result = api.send_command(command, args)
    if result.get("error") and with_address_list and "address" in str(result["error"]).lower():
        # A RouterOS build without PPP profile address-list: the static pool
        # entry in BW_PPPOE_EXPIRED still matches every walled session.
        args.pop("address-list", None)
        result = api.send_command(command, args)
        with_address_list = False
    if result.get("error"):
        raise RedirectError(f"{command}: {result['error']}")
    return 1, with_address_list


def _ensure_proxy(api, config: Dict[str, Any]) -> tuple[int, bool, int]:
    """(port, enabled_by_us, writes). An already-enabled proxy is reused."""
    rows = _rows(api, "/ip/proxy")
    proxy = rows[0] if rows else {}
    if _truthy(proxy.get("enabled")):
        try:
            port = int(str(proxy.get("port") or "").split(",")[0])
        except ValueError:
            port = int(settings.PPPOE_EXPIRED_PROXY_PORT)
        by_us = bool(config.get("proxy_enabled_by_us")) and port == config.get("proxy_port")
        return port, by_us, 0
    port = int(settings.PPPOE_EXPIRED_PROXY_PORT)
    _write(api, "/ip/proxy/set", {"enabled": "yes", "port": str(port)})
    return port, True, 1


def _ensure_proxy_access(api, *, router_id: int, cidr: str, port: int,
                         syntax_hint: Optional[str], cidr_changed: bool) -> tuple[str, int]:
    """The catch-all redirect for the walled pool, ahead of foreign rules.

    Returns (syntax this RouterOS accepted, writes).
    """
    url = portal_url(router_id)
    rows = _rows(api, "/ip/proxy/access")
    writes = 0
    if cidr_changed:
        for r in rows:
            if str(r.get("comment") or "").startswith(COMMENT_USER) and r.get(".id"):
                _write(api, "/ip/proxy/access/remove", {"numbers": r[".id"]})
                writes += 1
        rows = _rows(api, "/ip/proxy/access")

    catch = [r for r in rows if r.get("comment") == COMMENT_REDIRECT]
    syntax = syntax_hint
    if catch:
        syntax = SYNTAX_ACTION_DATA if "action-data" in catch[0] and catch[0].get("action-data") else SYNTAX_REDIRECT_TO
    first_foreign = next((i for i, r in enumerate(rows) if not _ours(r)), len(rows))
    if len(catch) == 1:
        idx = rows.index(catch[0])
        want = {"src-address": cidr, "local-port": str(port), **_access_action(syntax, url)}
        if idx < first_foreign and _row_matches(catch[0], want):
            return syntax, writes
    for r in catch:
        if r.get(".id"):
            _write(api, "/ip/proxy/access/remove", {"numbers": r[".id"]})
            writes += 1
    rows = _rows(api, "/ip/proxy/access")
    anchor = next((r.get(".id") for r in rows if not _ours(r) and r.get(".id")), None)
    base = {"src-address": cidr, "local-port": str(port), "comment": COMMENT_REDIRECT}
    if anchor:
        base["place-before"] = anchor
    # Try the syntax this router used before first, then the other one.
    order = [SYNTAX_REDIRECT_TO, SYNTAX_ACTION_DATA]
    if syntax == SYNTAX_ACTION_DATA:
        order.reverse()
    last_error = None
    for candidate in order:
        result = api.send_command("/ip/proxy/access/add", {**base, **_access_action(candidate, url)})
        if not result.get("error"):
            return candidate, writes + 1
        last_error = result["error"]
    raise RedirectError(f"/ip/proxy/access/add: {last_error}")


# ---------------------------------------------------------------------------
# apply / remove / wall
# ---------------------------------------------------------------------------


def ensure_expired_infra(api, *, router_id: int, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Create or repair everything the walled state needs. Idempotent.

    Returns {"success": True, "config": {...}, "writes": n} or {"error": ...}.
    """
    config = dict(config or {})
    try:
        current = _current_cidr(api, config)
        cidr = choose_expired_cidr(api, current)
        layout = layout_for(cidr)
        writes = 0

        port, by_us, w = _ensure_proxy(api, config)
        writes += w
        writes += _ensure_pool(api, layout)
        syntax, w = _ensure_proxy_access(
            api, router_id=router_id, cidr=cidr, port=port,
            syntax_hint=config.get("access_syntax"),
            cidr_changed=bool(current and current != cidr),
        )
        writes += w
        w, with_list = _ensure_profile(
            api, router_id=router_id, layout=layout, port=port, syntax=syntax,
            with_address_list=config.get("profile_address_list", True),
        )
        writes += w
        writes += _reconcile_address_list(api, EXPIRED_LIST, COMMENT_POOL, [cidr])
        writes += _reconcile_address_list(api, ALLOW_LIST, COMMENT_ALLOW, allow_addresses())
        writes += _reconcile_chain_rules(api, "/ip/firewall/filter", desired_filter_rules(cidr, port, by_us))
        writes += _reconcile_chain_rules(api, "/ip/firewall/nat", desired_nat_rules(cidr, port))

        new_config = {
            "cidr": cidr,
            "proxy_port": port,
            "proxy_enabled_by_us": by_us,
            "access_syntax": syntax,
            "profile_address_list": with_list,
            "portal_url": portal_url(router_id),
        }
        if current and current != cidr:
            new_config["moved_from"] = current
        if writes:
            logger.info("expired redirect: router %s repaired with %d write(s)", router_id, writes)
        return {"success": True, "config": new_config, "writes": writes}
    except RedirectError as exc:
        logger.warning("expired redirect: router %s apply failed: %s", router_id, exc)
        return {"error": str(exc)}
    except Exception as exc:  # never let a parse surprise escape a background job
        logger.exception("expired redirect: router %s apply crashed", router_id)
        return {"error": f"{type(exc).__name__}: {exc}"}


def _active_sessions_by_name(api) -> Dict[str, List[str]]:
    sessions: Dict[str, List[str]] = {}
    for row in _rows(api, "/ppp/active"):
        if row.get("name") and row.get(".id"):
            sessions.setdefault(row["name"], []).append(row[".id"])
    return sessions


def teardown_expired_infra(api, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Turn the feature off on the router: walled customers lose their secret
    (the old expiry behaviour) and every walled-state object is removed."""
    config = dict(config or {})
    try:
        removed_secrets = []
        walled = [s for s in _rows(api, "/ppp/secret") if s.get("profile") == EXPIRED_PROFILE]
        # Secret first, then the session (the 2026-10-02 redial race).
        for secret in walled:
            if secret.get(".id"):
                _write(api, "/ppp/secret/remove", {"numbers": secret[".id"]})
                removed_secrets.append(secret.get("name"))
        if removed_secrets:
            sessions = _active_sessions_by_name(api)
            for name in removed_secrets:
                for sid in sessions.get(name, []):
                    api.send_command("/ppp/active/remove", {"numbers": sid})

        removed = 0
        for menu in ("/ip/firewall/filter", "/ip/firewall/nat", "/ip/proxy/access", "/ip/firewall/address-list"):
            for row in _rows(api, menu):
                if _ours(row) and not _truthy(row.get("dynamic")) and row.get(".id"):
                    _write(api, f"{menu}/remove", {"numbers": row[".id"]})
                    removed += 1
        for menu, name in (("/ppp/profile", EXPIRED_PROFILE), ("/ip/pool", EXPIRED_POOL)):
            for row in _rows(api, menu):
                if row.get("name") == name and row.get(".id"):
                    _write(api, f"{menu}/remove", {"numbers": row[".id"]})
                    removed += 1
        if config.get("proxy_enabled_by_us"):
            others = [r for r in _rows(api, "/ip/proxy/access") if not _ours(r)]
            if not others:
                _write(api, "/ip/proxy/set", {"enabled": "no"})
        return {"success": True, "secrets_removed": removed_secrets, "objects_removed": removed}
    except RedirectError as exc:
        return {"error": str(exc)}
    except Exception as exc:
        logger.exception("expired redirect: teardown crashed")
        return {"error": f"{type(exc).__name__}: {exc}"}


def wall_pppoe_users(api, customers: List[Dict[str, Any]], *, create_missing: bool = True) -> Dict[str, Dict[str, Any]]:
    """Move each customer's secret to the walled profile and kick the session.

    ``customers``: [{"id", "pppoe_username", "pppoe_password"?, "comment"?}].
    Profile first, kick second: the redial then lands in the walled profile.
    A missing secret is re-created on the walled profile when the password is
    known and ``create_missing``; otherwise there is nothing to wall (no access).
    Returns {customer_id: {"ok": bool, "action": ..., "error"?: ...}}.
    """
    out: Dict[str, Dict[str, Any]] = {}
    secrets = {s.get("name"): s for s in _rows(api, "/ppp/secret") if s.get("name")}
    changed = []
    for cust in customers:
        username = cust["pppoe_username"]
        secret = secrets.get(username)
        try:
            if secret is not None:
                if secret.get("profile") != EXPIRED_PROFILE:
                    _write(api, "/ppp/secret/set", {"numbers": secret.get(".id") or username,
                                                    "profile": EXPIRED_PROFILE})
                    action = "walled"
                else:
                    action = "already_walled"
            elif create_missing and cust.get("pppoe_password"):
                args = {"name": username, "password": cust["pppoe_password"],
                        "service": "pppoe", "profile": EXPIRED_PROFILE}
                if cust.get("comment"):
                    args["comment"] = cust["comment"]
                _write(api, "/ppp/secret/add", args)
                action = "created_walled"
            else:
                action = "absent"
            out[cust["id"]] = {"ok": True, "action": action}
            changed.append(username)
        except RedirectError as exc:
            out[cust["id"]] = {"ok": False, "error": str(exc)}

    if changed:
        try:
            sessions = _active_sessions_by_name(api)
        except RedirectError as exc:
            for cust in customers:
                if out.get(cust["id"], {}).get("ok"):
                    out[cust["id"]] = {"ok": False, "error": f"session list failed: {exc}"}
            return out
        for cust in customers:
            result = out.get(cust["id"])
            if not result or not result.get("ok"):
                continue
            kicked = 0
            for sid in sessions.get(cust["pppoe_username"], []):
                r = api.send_command("/ppp/active/remove", {"numbers": sid})
                if r.get("error"):
                    out[cust["id"]] = {"ok": False, "error": f"session disconnect failed: {r['error']}"}
                    break
                kicked += 1
            else:
                result["disconnected"] = kicked
    return out


def config_changed(old: Optional[Dict[str, Any]], new: Optional[Dict[str, Any]]) -> bool:
    keys = ("cidr", "proxy_port", "proxy_enabled_by_us", "access_syntax", "profile_address_list", "portal_url")
    old = old or {}
    new = new or {}
    return any(old.get(k) != new.get(k) for k in keys)


async def persist_router_config(router_id: int, config: Dict[str, Any], *, error: Optional[str] = None) -> None:
    """Store what was applied, in its own short session. Never fatal."""
    from app.db import database as db_module
    from app.db.models import Router

    try:
        async with db_module.async_session() as db:
            router = await db.get(Router, router_id)
            if router is not None:
                merged = dict(router.pppoe_expired_redirect_config or {})
                merged.update(config or {})
                merged["checked_at"] = datetime.utcnow().isoformat()
                if error is None:
                    merged.pop("last_error", None)
                else:
                    merged["last_error"] = error[:255]
                router.pppoe_expired_redirect_config = merged
            await db.commit()
    except Exception as exc:
        logger.warning("expired redirect: could not store config for router %s: %s", router_id, exc)
