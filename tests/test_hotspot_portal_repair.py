"""Dual-mode captive-portal repair must never leave the hotspot without a login page.

Router 182 (2026-09-29): a dual save switched hsprof1 to another html-directory,
the refresh then failed, and the hotspot was left serving a folder with no
login.html.
"""
from app.services.mikrotik_api import MikroTikAPI

SUPPORT = ["alogin.html", "errors.txt", "redirect.html", "md5.js"]
URL = "http://isp.example.net/api/provision/tok/login-page"


def _api(html_dir, files, fetch_error=None, https_ok=False):
    api = MikroTikAPI("10.0.0.1", "u", "p", 8728)
    api.connected = True
    state = {
        "dir": html_dir,
        "files": {f"{html_dir}/{name}": size for name, size in files.items()},
        "resets": 0,
        "dir_sets": [],
    }

    def send_command(command, args=None):
        args = args or {}
        if command == "/ip/hotspot/print":
            return {"success": True, "data": [{".id": "*1", "name": "hotspot1", "interface": "bridge", "profile": "hsprof1"}]}
        if command == "/ip/hotspot/profile/print":
            return {"success": True, "data": [{".id": "*P", "name": "hsprof1", "html-directory": state["dir"]}]}
        if command == "/ip/hotspot/profile/set":
            if "html-directory" in args:
                state["dir_sets"].append(args["html-directory"])
                state["dir"] = args["html-directory"]
            return {"success": True}
        if command == "/file/print":
            return {"success": True, "data": [{"name": n, "size": str(s)} for n, s in state["files"].items()]}
        if command == "/tool/fetch":
            state.setdefault("fetch_modes", []).append(args.get("mode"))
            if fetch_error and not (https_ok and args.get("mode") == "https"):
                return {"error": fetch_error}
            state["files"][args["dst-path"]] = 2894
            return {"success": True}
        return {"success": True}

    api.send_command = send_command
    api.ensure_hotspot_server_profile = lambda **kw: {"success": True, "html_directory": kw.get("html_directory")}

    def reset(_profile):
        state["resets"] += 1
        for name in SUPPORT + ["login.html"]:
            state["files"][f"{state['dir']}/{name}"] = 100
        return {"success": True}

    api.reset_hotspot_profile_html_directory = reset
    return api, state


def test_failed_refresh_keeps_the_working_login_page():
    files = {name: 100 for name in SUPPORT} | {"login.html": 3398}
    api, state = _api("flash/hotspot", files, fetch_error="failure: connection timeout")

    result = api.ensure_existing_hotspot_captive_portal(login_page_url=URL)

    assert result["success"] is True
    assert any("kept the existing one" in w for w in result["warnings"])
    assert state["dir"] == "flash/hotspot" and state["dir_sets"] == []
    assert state["resets"] == 0  # a reset would have overwritten the custom login.html
    assert state["files"]["flash/hotspot/login.html"] == 3398


def test_refresh_goes_into_the_directory_already_in_use():
    files = {name: 100 for name in SUPPORT} | {"login.html": 3398}
    api, state = _api("flash/hotspot", files)

    result = api.ensure_existing_hotspot_captive_portal(login_page_url=URL)

    assert result["success"] is True
    assert result["login_path"] == "flash/hotspot/login.html"
    assert state["files"]["flash/hotspot/login.html"] == 2894
    assert state["dir_sets"] == []


def test_missing_support_files_are_restored_before_fetch():
    api, state = _api("hotspot", {"login.html": 3398})

    result = api.ensure_existing_hotspot_captive_portal(login_page_url=URL)

    assert result["success"] is True
    assert state["resets"] == 1
    assert state["files"]["hotspot/login.html"] == 2894


def test_no_login_page_at_all_is_still_an_error():
    api, _ = _api("hotspot", {name: 100 for name in SUPPORT}, fetch_error="failure: connection timeout")

    result = api.ensure_existing_hotspot_captive_portal(login_page_url=URL)

    assert "Could not fetch hotspot login page" in result["error"]


def test_http_blocked_by_relay_rule_falls_back_to_https():
    api, state = _api("hotspot", {name: 100 for name in SUPPORT},
                      fetch_error="failure: closing connection: <connection failed> 172.67.173.124:80", https_ok=True)

    result = api.ensure_existing_hotspot_captive_portal(login_page_url=URL)

    assert result["success"] is True
    assert state["fetch_modes"] == ["http", "https"]
    assert state["files"]["hotspot/login.html"] == 2894
