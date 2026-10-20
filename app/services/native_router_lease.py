"""RAM heartbeat and constant-size fallback for one selected reporter timer."""

import re


def lease_sources(router_id, original_interval, *, seconds=180):
    if type(router_id) is not int or router_id <= 0:
        raise ValueError("Invalid lease router")
    if not re.fullmatch(r"[0-9wdhms:.]+", original_interval):
        raise ValueError("Invalid original interval")
    if type(seconds) is not int or not 10 <= seconds <= 180:
        raise ValueError("Invalid lease duration")
    name = "bw-native-api-fallback-" + str(router_id)
    list_name = "bw-native-api-lease-" + str(router_id)
    guard = (
        ':if ([:len [/ip firewall address-list find where list="'
        + list_name
        + '"]] = 0) do={ '
        ':local s [/system scheduler find where name="bitwave-usage-push"]; '
        ":if ([:len $s] = 1) do={ :if ([/system scheduler get $s disabled]) do={ "
        "/system scheduler set $s disabled=no interval=" + original_interval + " } }; "
        '/system scheduler set [find where name="' + name + '"] disabled=yes; '
        ':log warning "Bitwave native API lease expired; original reporter restored" }'
    )
    return {"name": name, "list": list_name, "seconds": seconds, "guard": guard}


async def touch_lease(api, cfg):
    """Add a new RAM-only entry before removing its predecessor."""
    rows = (
        await api.rpc(
            "/ip/firewall/address-list/print",
            {".proplist": ".id,list,address,dynamic,comment"},
            query=("?list=" + cfg["list"],),
        )
    )["rows"]
    own = [r for r in rows if r.get("list") == cfg["list"]]
    comment = "Bitwave native API RAM lease" + (
        ":" + cfg["owner"] if cfg.get("owner") else ""
    )
    if any(r.get("dynamic") != "true" for r in own):
        raise RuntimeError("Unexpected persistent lease entry")
    if any(r.get("comment") != comment for r in own):
        raise RuntimeError("Another native owner has a RAM lease")
    used = {r["address"] for r in own}
    address = next(
        "127.255.0." + str(i)
        for i in range(1, 255)
        if "127.255.0." + str(i) not in used
    )
    await api.rpc(
        "/ip/firewall/address-list/add",
        {
            "list": cfg["list"],
            "address": address,
            "timeout": str(cfg["seconds"]) + "s",
            "comment": comment,
        },
    )
    for row in own:
        await api.rpc("/ip/firewall/address-list/remove", {".id": row[".id"]})
