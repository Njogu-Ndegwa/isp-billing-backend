"""Port-mode saves never cut a router off its internet or drop ports they did not name.

The assistant's "make ether4 PPPoE too" used to send ports=["ether4"], which replaces
the whole set and puts ether2's PPPoE customers back on hotspot; and nothing on the
server stopped a load-balancing WAN port from being made an access port.
"""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.api.router_operations import (
    SetDualPortsRequest, SetPPPoEPortsRequest, SetPlainPortsRequest, refuse_wan_ports, resolve_port_set,
)


def test_add_keeps_the_ports_already_on_the_mode():
    assert resolve_port_set(None, ["ether4"], None, ["ether2"]) == ["ether2", "ether4"]


def test_remove_takes_only_that_port_off():
    assert resolve_port_set(None, None, ["ether2"], ["ether2", "ether4"]) == ["ether4"]


def test_add_twice_is_once():
    assert resolve_port_set(None, ["ether2"], None, ["ether2"]) == ["ether2"]


def test_the_whole_set_still_replaces_as_the_classic_page_sends_it():
    assert resolve_port_set(["ether3"], None, None, ["ether2"]) == ["ether3"]
    assert resolve_port_set([], None, None, ["ether2"]) == []   # clear the mode


def test_nothing_named_is_refused():
    with pytest.raises(HTTPException) as exc:
        resolve_port_set(None, None, None, ["ether2"])
    assert exc.value.status_code == 400


def _router(lb_enabled=True, wan=("ether1", "ether2")):
    return SimpleNamespace(lb_enabled=lb_enabled, lb_config={"wan_ports": list(wan)})


@pytest.mark.parametrize("mode", ["PPPoE", "plain mode", "dual mode"])
def test_load_balancing_wan_port_is_refused(mode):
    with pytest.raises(HTTPException) as exc:
        refuse_wan_ports(_router(), ["ether3", "ether2"], mode)
    assert exc.value.status_code == 400
    assert "ether2" in exc.value.detail and "load balancing" in exc.value.detail


def test_ether1_is_refused_without_load_balancing():
    with pytest.raises(HTTPException):
        refuse_wan_ports(_router(lb_enabled=False, wan=()), ["ether1"], "PPPoE")


def test_a_former_wan_port_is_free_once_load_balancing_is_off():
    refuse_wan_ports(_router(lb_enabled=False), ["ether2"], "PPPoE")


@pytest.mark.parametrize("model", [SetPPPoEPortsRequest, SetPlainPortsRequest, SetDualPortsRequest])
def test_requests_take_a_change_or_the_whole_set(model):
    assert model(add=["ether4"]).ports is None
    assert model(ports=["ether3"]).ports == ["ether3"]
    schema = model.model_json_schema()["properties"]
    assert {"ports", "add", "remove"} <= set(schema)
    assert "add/remove" in schema["ports"]["description"]
