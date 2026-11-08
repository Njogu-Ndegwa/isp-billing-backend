"""Remote control of a customer's own router / CPE that reaches the reseller's
MikroTik over PPPoE (WAN = PPPoE).

Unlike the hotspot-LAN access-point path (:mod:`app.services.ap_control`), the
device here is a full router in the customer's home. It dials the reseller's
PPPoE server with the customer's PPPoE account and sits on the reseller's PPPoE
pool; it is NOT on a MikroTik port directly. To reach it we:

* find the customer's **active PPPoE session** on the MikroTik by PPPoE
  username (``/ppp active``); its ``address`` is the device's WAN IP inside the
  reseller's PPPoE pool; then
* ``/tool fetch`` from the MikroTik to ``http://<that IP>:<port>/...`` -- the
  same transport and per-model adapters as the AP path
  (:mod:`app.services.ap_fetch`, :mod:`app.services.ap_adapters`).

Safety rules specific to PPPoE:

* **the IP is never the identity.** It is resolved live from ``/ppp active``
  every single time, keyed by the customer's PPPoE username. A stored address
  is never trusted, and only the address of *this* customer's *active* session
  on *this* router is ever contacted.
* **no session => offline.** If the customer has no active PPPoE session we
  return a clear "customer is offline" message and touch nothing.
* the Tenda only answers on its WAN when "Remote Web Management" is enabled,
  usually on a port like 8080/8888, and its allowed management source must
  include the MikroTik's PPPoE local-address (the source of the fetch). The web
  port is configurable per device.

Everything here is synchronous and runs in a worker thread via
``run_with_guard`` with no DB session held, exactly like the AP path.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict, Optional

from app.services import ap_adapters
from app.services.ap_adapters import (
    DEFAULT_LAN_WEB_PORT, DEFAULT_WAN_REMOTE_MGMT_PORT, detect_model_key, get_adapter,
)
from app.services.ap_control import (
    ApCredential, LoginResult, _login, _read_status_body, _rows, _with_api,
)
from app.services.ap_fetch import RouterFetchHttpClient, reply_ok

logger = logging.getLogger(__name__)

ACTION_STATUS = "status"
ACTION_REBOOT = "reboot"
ACTION_DISCONNECT = "disconnect"

# Re-exported so callers (routes, tests) have one import for both.
DEFAULT_LAN_PORT = DEFAULT_LAN_WEB_PORT
DEFAULT_WAN_PORT = DEFAULT_WAN_REMOTE_MGMT_PORT


# ---------------------------------------------------------------------------
# Resolve the device's live WAN IP from the customer's PPPoE session
# ---------------------------------------------------------------------------

def resolve_pppoe_session(api, username: str) -> Optional[Dict[str, Any]]:
    """The customer's active PPPoE session on this router, found by username.

    Returns ``{"address", "uptime", "caller_id", "session_id"}`` for the active
    session, or ``None`` when the customer has no session up right now. Reads
    ``/ppp active`` only; never writes.
    """
    want = str(username or "").strip()
    if not want:
        return None
    for row in _rows(api.send_command("/ppp/active/print")):
        if str(row.get("name", "")).strip() != want:
            continue
        address = str(row.get("address", "")).strip()
        if not address:
            continue
        try:
            ipaddress.ip_address(address)
        except ValueError:
            continue
        return {
            "address": address,
            "uptime": row.get("uptime"),
            "caller_id": row.get("caller-id"),
            "session_id": row.get(".id"),
        }
    return None


_OFFLINE = {
    "error": "offline",
    "offline": True,
    "message": "The customer is offline: no active PPPoE session on this router right now, "
               "so the router (CPE) can't be reached. Ask them to check power and the "
               "WAN/fibre, then try again once the line is back up.",
}


def _locate_cpe(api, cred: ApCredential, username: str):
    """Resolve the device IP from the live session, or refuse as offline.

    Sets ``cred.ap_ip`` to the session address on success. Returns
    ``(session, None)`` or ``(None, refusal)``.
    """
    session = resolve_pppoe_session(api, username)
    if not session:
        return None, dict(_OFFLINE)
    cred.ap_ip = session["address"]
    return session, None


def _cpe_login_refusal(login: LoginResult, port: int) -> Dict[str, Any]:
    """Turn a failed login into a CPE-specific, actionable error.

    Distinguishes "did not answer" (remote management off / wrong port / source
    not allowed) from "answered but rejected the password".
    """
    if login.unreachable:
        detail = f" ({login.error})" if login.error else ""
        return {
            "error": "cpe_unreachable",
            "message": f"The router (CPE) did not answer on port {port}. Likely causes: remote "
                       f"web management is off on the Tenda, the port is wrong, or its allowed "
                       f"management source does not include the MikroTik's PPPoE address.{detail}",
        }
    if login.locked:
        return {
            "error": "login_locked", "locked": True, "login_ok": False,
            "message": login.error or "Locked after too many wrong passwords; save the password again.",
        }
    # The device answered on the port but no usable session opened. With
    # /tool fetch the only success signal is a readable status page, so this is
    # either a wrong password or a model/firmware whose status page we don't
    # recognise -- name both so the operator can check the password and model.
    return {
        "error": "login_failed", "locked": False, "login_ok": False,
        "message": "The router (CPE) answered but no session opened: the saved admin password "
                   "was rejected, or this model/firmware is not supported. Check the password "
                   "and the selected model.",
    }


def _client(api, cred: ApCredential, port: int) -> RouterFetchHttpClient:
    return RouterFetchHttpClient(api, cred.ap_ip, port=port)


# ---------------------------------------------------------------------------
# Public sync actions (run in a worker thread; no DB session held)
# ---------------------------------------------------------------------------

def read_cpe_status_sync(router_info: Dict[str, Any], cred: ApCredential, username: str,
                         port: int, *, api_factory=None) -> Dict[str, Any]:
    adapter = get_adapter(cred.model, cred.vendor)

    def run(api):
        session, refused = _locate_cpe(api, cred, username)
        if refused:
            return refused
        client = _client(api, cred, port)
        login = _login(client, adapter, cred)
        if not login.ok:
            return _cpe_login_refusal(login, port)
        _resp, status = _read_status_body(client, adapter)
        if status is None:
            return {
                "error": "cpe_unsupported", "login_ok": True, "login_method": login.method,
                "message": "The router (CPE) accepted the login but its status page was not "
                           "recognised. The selected model may be wrong, or this firmware is "
                           "not supported yet.",
            }
        if not status.ip:
            status.ip = cred.ap_ip
        public = status.public()
        public["session_address"] = session["address"]
        public["session_uptime"] = session.get("uptime")
        detected = detect_model_key(status.model)
        if detected:
            public["detected_model"] = detected
        return {"success": True, "login_ok": True, "login_method": login.method,
                "status": public, "session": session}

    return _with_api(router_info, api_factory, run)


def reboot_cpe_sync(router_info: Dict[str, Any], cred: ApCredential, username: str,
                    port: int, *, api_factory=None) -> Dict[str, Any]:
    adapter = get_adapter(cred.model, cred.vendor)

    def run(api):
        session, refused = _locate_cpe(api, cred, username)
        if refused:
            return refused
        client = _client(api, cred, port)
        login = _login(client, adapter, cred)
        if not login.ok:
            return _cpe_login_refusal(login, port)
        resp = client.request(adapter.reboot_request())
        if not resp.ok or not (resp.redirected or reply_ok(resp.body)):
            return {"error": "cpe_reboot_failed", "login_ok": True, "login_method": login.method,
                    "message": resp.error or "The router (CPE) did not accept the reboot."}
        return {"success": True, "login_ok": True, "login_method": login.method,
                "action": ACTION_REBOOT, "session": session,
                "message": "Reboot sent. The router drops for about a minute and the PPPoE line "
                           "reconnects once it is back up."}

    return _with_api(router_info, api_factory, run)


def disconnect_cpe_session_sync(router_info: Dict[str, Any], username: str,
                                *, api_factory=None) -> Dict[str, Any]:
    """Cheap, always-works fallback: drop the PPPoE session so the device redials.

    This does NOT reboot the device -- it only reconnects the line. Reuses the
    router API's ``disconnect_pppoe_session`` (the same code the dashboard's
    "reset session" already uses).
    """

    def run(api):
        result = api.disconnect_pppoe_session(username)
        if result.get("error"):
            return {"error": "disconnect_failed", "message": result["error"],
                    "disconnected": int(result.get("disconnected") or 0)}
        disconnected = int(result.get("disconnected") or 0)
        return {"success": True, "action": ACTION_DISCONNECT, "disconnected": disconnected,
                "message": ("Line disconnected; the router will redial within a few seconds. "
                            "This reconnects the line -- it does not reboot the device.")
                           if disconnected else
                           ("The customer had no active session to disconnect; nothing to redial.")}

    return _with_api(router_info, api_factory, run)
