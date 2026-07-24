"""Unit tests for the pure downstream-device classifier.

No DB, no RouterOS — classification is fully computed from caller-supplied
signals (MAC OUI, hostnames, hotspot source address + inferred subnets).
"""

from app.services.device_classifier import (
    classify_device,
    infer_hotspot_subnets,
    is_foreign_gateway_claim,
    normalize_oui,
    subnet_24,
    vendor_from_hostname,
    vendor_from_mac,
)


# ---------------------------------------------------------------------------
# OUI matching
# ---------------------------------------------------------------------------

def test_oui_match_uppercase_colons():
    assert vendor_from_mac("B4:0F:3B:AA:BB:CC") == "Tenda"


def test_oui_match_lowercase_dashes():
    assert vendor_from_mac("d8-07-b6-01-02-03") == "TP-Link"


def test_oui_match_colonless_lowercase():
    assert vendor_from_mac("488f5a010203") == "MikroTik"


def test_oui_match_ubiquiti_and_mercusys():
    assert vendor_from_mac("24:A4:3C:00:00:01") == "Ubiquiti"
    assert vendor_from_mac("b8:3a:34:00:00:01") == "Mercusys"


def test_oui_unknown_returns_none():
    assert vendor_from_mac("AA:BB:CC:DD:EE:FF") is None


def test_normalize_oui_garbage_and_short_input():
    assert normalize_oui(None) == ""
    assert normalize_oui("") == ""
    assert normalize_oui("zz:zz") == ""
    assert normalize_oui("B4:0F") == ""  # fewer than 6 hex digits
    assert normalize_oui("b4:0f:3b:aa:bb:cc") == "B40F3B"


# ---------------------------------------------------------------------------
# Hostname matching
# ---------------------------------------------------------------------------

def test_hostname_vendor_prefixes():
    assert vendor_from_hostname("Tenda_AC10") == "Tenda"
    assert vendor_from_hostname("tp-link_5G_ext") == "TP-Link"
    assert vendor_from_hostname("TPLINK-Router") == "TP-Link"
    assert vendor_from_hostname("CUDY-wr1300") == "Cudy"
    assert vendor_from_hostname("totolink n300") == "TOTOLINK"
    assert vendor_from_hostname("MikroTik") == "MikroTik"


def test_hostname_non_vendor_returns_none():
    assert vendor_from_hostname("Dennis-iPhone") is None
    assert vendor_from_hostname("Galaxy-A14") is None
    assert vendor_from_hostname("") is None
    assert vendor_from_hostname(None) is None
    # vendor name must be a prefix, not a substring
    assert vendor_from_hostname("my-tenda-box") is None


# ---------------------------------------------------------------------------
# Hotspot subnet inference + gateway-claim detection
# ---------------------------------------------------------------------------

def test_infer_hotspot_subnets_majority():
    subnets = infer_hotspot_subnets(
        ["192.168.88.10", "192.168.88.11", "192.168.0.1"]
    )
    assert subnets == {"192.168.88"}


def test_infer_hotspot_subnets_needs_min_hosts():
    # a single address (or the same address repeated) infers nothing
    assert infer_hotspot_subnets(["192.168.88.10"]) == set()
    assert infer_hotspot_subnets(["192.168.88.10", "192.168.88.10"]) == set()


def test_infer_hotspot_subnets_ignores_invalid():
    assert infer_hotspot_subnets([None, "", "not-an-ip", "300.1.2.3"]) == set()


def test_subnet_24():
    assert subnet_24("192.168.88.10") == "192.168.88"
    assert subnet_24("10.0.0.5") == "10.0.0"
    assert subnet_24("bogus") is None
    assert subnet_24(None) is None


def test_gateway_claim_foreign_subnet_flags():
    assert is_foreign_gateway_claim("192.168.0.1", {"192.168.88"}) is True


def test_gateway_claim_same_subnet_not_flagged():
    assert is_foreign_gateway_claim("192.168.88.1", {"192.168.88"}) is False


def test_gateway_claim_requires_known_subnets():
    assert is_foreign_gateway_claim("192.168.0.1", set()) is False
    assert is_foreign_gateway_claim("192.168.0.1", None) is False


def test_gateway_claim_only_192_168_dot_1_addresses():
    assert is_foreign_gateway_claim("192.168.0.5", {"192.168.88"}) is False
    assert is_foreign_gateway_claim("10.0.0.1", {"192.168.88"}) is False
    assert is_foreign_gateway_claim("", {"192.168.88"}) is False


# ---------------------------------------------------------------------------
# classify_device end-to-end
# ---------------------------------------------------------------------------

def test_classify_default_is_customer():
    result = classify_device()
    assert result == {
        "device_class": "customer",
        "vendor": None,
        "router_mode_suspect": False,
    }


def test_classify_by_oui_is_infrastructure():
    result = classify_device(mac_address="c8:3a:35:12:34:56")
    assert result["device_class"] == "infrastructure"
    assert result["vendor"] == "Tenda"
    assert result["router_mode_suspect"] is False


def test_classify_by_hostname_when_oui_unknown():
    result = classify_device(
        mac_address="AA:BB:CC:00:00:01",
        hostnames=(None, "TP-Link_ExtenderA0"),
    )
    assert result["device_class"] == "infrastructure"
    assert result["vendor"] == "TP-Link"


def test_classify_oui_takes_precedence_over_hostname():
    result = classify_device(
        mac_address="B4:0F:3B:00:00:01",
        hostnames=("TP-Link_Whatever",),
    )
    assert result["vendor"] == "Tenda"


def test_classify_gateway_claim_sets_suspect_and_infrastructure():
    result = classify_device(
        mac_address="AA:BB:CC:00:00:02",
        hostnames=(),
        source_ip="192.168.0.1",
        hotspot_subnets={"192.168.88"},
    )
    assert result["device_class"] == "infrastructure"
    assert result["vendor"] is None
    assert result["router_mode_suspect"] is True


def test_classify_ordinary_hotspot_client_stays_customer():
    result = classify_device(
        mac_address="AA:BB:CC:00:00:03",
        hostnames=("Galaxy-A14",),
        source_ip="192.168.88.23",
        hotspot_subnets={"192.168.88"},
    )
    assert result == {
        "device_class": "customer",
        "vendor": None,
        "router_mode_suspect": False,
    }
