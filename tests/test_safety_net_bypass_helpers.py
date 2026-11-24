from unittest.mock import patch

from app.services.mikrotik_background import (
    _find_router_binding_cleanup_candidates_sync,
    _remove_router_bindings_sync,
)


ROUTER_INFO = {
    "ip": "10.0.100.25",
    "username": "bitwave-api",
    "password": "secret",
    "port": 8728,
    "name": "fastnet #8",
}


def test_find_binding_cleanup_candidates_returns_set_on_connect_failure():
    with patch("app.services.mikrotik_background.MikroTikAPI") as api_cls:
        api_cls.return_value.connect.return_value = False

        result = _find_router_binding_cleanup_candidates_sync(ROUTER_INFO, set())

    assert result == set()


def test_find_binding_cleanup_candidates_returns_set_on_print_failure():
    with patch("app.services.mikrotik_background.MikroTikAPI") as api_cls:
        api = api_cls.return_value
        api.connect.return_value = True
        api.send_command.return_value = {"error": "router command failed"}

        result = _find_router_binding_cleanup_candidates_sync(ROUTER_INFO, set())

    assert result == set()
    api.disconnect.assert_called_once()


def test_remove_router_bindings_returns_int_on_connect_failure():
    with patch("app.services.mikrotik_background.MikroTikAPI") as api_cls:
        api_cls.return_value.connect.return_value = False

        result = _remove_router_bindings_sync(ROUTER_INFO, {"AA:BB:CC:DD:EE:FF"})

    assert result == 0


def test_remove_router_bindings_uses_binding_id():
    with patch("app.services.mikrotik_background.MikroTikAPI") as api_cls:
        api = api_cls.return_value
        api.connect.return_value = True
        api.send_command.side_effect = [
            {
                "success": True,
                "data": [
                    {
                        ".id": "*1",
                        "mac-address": "AA:BB:CC:DD:EE:FF",
                        "type": "bypassed",
                        "comment": "USER:0712000000|EXPIRES:DB_MANAGED|EXP:1795000000",
                    }
                ],
            },
            {"success": True},
        ]

        result = _remove_router_bindings_sync(ROUTER_INFO, {"AA:BB:CC:DD:EE:FF"})

    assert result == 1
    api.send_command.assert_any_call(
        "/ip/hotspot/ip-binding/remove",
        {"numbers": "*1"},
    )


def test_hand_added_bypass_is_never_removed():
    """A reseller's own bypass (AP in router mode, CCTV) carries none of our
    comments; removing it cuts everything behind it."""
    rows = [
        {".id": "*1", "mac-address": "AA:BB:CC:DD:EE:01", "type": "bypassed", "comment": "CCTV gate"},
        {".id": "*2", "mac-address": "AA:BB:CC:DD:EE:02", "type": "bypassed"},
        {".id": "*3", "mac-address": "AA:BB:CC:DD:EE:03", "type": "bypassed",
         "comment": "USER:0712000000|EXPIRES:DB_MANAGED"},
    ]
    with patch("app.services.mikrotik_background.MikroTikAPI") as api_cls:
        api = api_cls.return_value
        api.connect.return_value = True
        api.send_command.return_value = {"success": True, "data": rows}
        found = _find_router_binding_cleanup_candidates_sync(ROUTER_INFO, set())
    assert found == {"AA:BB:CC:DD:EE:03"}
