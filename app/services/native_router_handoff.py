"""Authenticated, bounded transfer of an existing native reporter guard."""

import re
import time

GUARD_COMMENT = "Bitwave native API fallback v1"
CLAIM_COMMENT = "Bitwave native API handover claim v1"


def guard_marker(comment):
    match = re.fullmatch(
        re.escape(GUARD_COMMENT) + r":(?:(handoff):)?([0-9]+):([a-f0-9]{32})",
        comment or "",
    )
    if not match:
        return None
    return {"handoff": bool(match[1]), "created": int(match[2]), "owner": match[3]}


def validate_handoff(guard, timer, cfg, leases, *, expected_comment=None):
    marker = guard_marker(guard.get("comment"))
    upgrade_list = "bw-native-upgrade-" + cfg["name"].removeprefix("bw-native-api-fallback-")
    wrapper = (':if ([:len [/ip firewall address-list find where list="'
               + upgrade_list + '"]] = 0) do={ /system script run bitwave-usage-push }')
    if (
        not marker or not marker["handoff"]
        or not 0 <= time.time() - marker["created"] <= 120
        or guard.get("name") != cfg["name"]
        or guard.get("disabled") != "false"
        or guard.get("on-event") != cfg["guard"]
        or timer.get("disabled") != "true"
        or timer.get("on-event") not in (
            "bitwave-usage-push", "/system script run bitwave-usage-push", wrapper,
        )
        or (expected_comment is not None and guard.get("comment") != expected_comment)
    ):
        raise RuntimeError("Native handover is not available")
    expected = "Bitwave native API RAM lease:" + marker["owner"]
    if not leases or any(
        row.get("list") != cfg["list"]
        or row.get("dynamic") != "true"
        or row.get("comment") != expected
        for row in leases
    ):
        raise RuntimeError("Native handover lease is not owned")
    return marker


async def acquire_claim(api, router_id, owner):
    """A uniquely named empty script serializes simultaneous adopters.

    RouterOS enforces script-name uniqueness. The script is never executed.
    A failed claimant leaves a recognizable lock that can be retired only after
    the old guard's fallback window has elapsed.
    """
    name = "bw-native-api-claim-" + str(router_id)
    rows = (await api.rpc(
        "/system/script/print", {".proplist": ".id,name,source,comment"},
        query=("?name=" + name,),
    ))["rows"]
    if len(rows) > 1:
        raise RuntimeError("Native handover claim is not unique")
    for row in rows:
        marker = re.fullmatch(
            re.escape(CLAIM_COMMENT) + r":([0-9]+):[a-f0-9]{32}", row.get("comment", "")
        )
        if (row.get("name") != name or row.get("source", "") != ""
                or not marker or time.time() - int(marker[1]) < 240):
            raise RuntimeError("Another native handover claimant exists")
        await api.rpc("/system/script/remove", {".id": row[".id"]})
    comment = CLAIM_COMMENT + ":" + str(int(time.time())) + ":" + owner
    reply = await api.rpc("/system/script/add", {
        "name": name, "source": "", "policy": "read", "comment": comment,
    })
    identifier = reply.get("done", {}).get("ret")
    if not identifier:
        raise RuntimeError("Native handover claim was not created")
    return {".id": identifier, "name": name, "comment": comment}


async def release_claim(api, claim):
    rows = (await api.rpc(
        "/system/script/print", {".proplist": ".id,name,source,comment"},
        query=("?name=" + claim["name"],),
    ))["rows"]
    if len(rows) != 1 or any(
        rows[0].get(key) != claim[key] for key in (".id", "name", "comment")
    ) or rows[0].get("source", "") != "":
        raise RuntimeError("Native handover claim changed owner")
    await api.rpc("/system/script/remove", {".id": claim[".id"]})
