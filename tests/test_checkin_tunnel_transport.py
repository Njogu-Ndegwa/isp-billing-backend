import pytest

from app.services.checkin_applier_script import render_checkin_applier_source
from app.services.checkin_tunnel_transport import (
    BEGIN,
    END,
    FETCH,
    prefer_tunnel_transport,
)

TUNNEL = "http://10.251.0.1:8088/api/router/checkin"


def source(**kwargs):
    return render_checkin_applier_source(
        identity="Router-1426",
        endpoint_url="https://isp.example.net/api/router/checkin",
        **kwargs
    )


def test_tunnel_only_replaces_transport_and_preserves_entire_frame_validator():
    original = source()
    fetch = FETCH.search(original)
    changed = prefer_tunnel_transport(original, TUNNEL)
    assert (
        changed[: changed.index(BEGIN)].rstrip() == original[: fetch.start()].rstrip()
    )
    assert changed[changed.index(END) + len(END) :] == original[fetch.end() :]
    assert fetch["fetch"] in changed
    assert "idle-timeout=3s duration=5s" in changed
    assert changed.index('url="' + TUNNEL + '"') < changed.index(":if (!$bwcTunnelOk)")
    assert changed.index(":if (!$bwcTunnelOk)") < changed.index(
        ":set res " + fetch["fetch"]
    )
    assert prefer_tunnel_transport(changed, TUNNEL) == changed


@pytest.mark.parametrize("certificate", ["no", "yes", "yes-without-crl"])
def test_public_fallback_keeps_certificate_policy(certificate):
    changed = source(check_certificate=certificate, tunnel_endpoint_url=TUNNEL)
    public = next(
        line
        for line in changed.splitlines()
        if ":set res [/tool fetch url=$url " in line
    )
    tunnel = next(
        line
        for line in changed.splitlines()
        if ':set res [/tool fetch url="http:' in line
    )
    assert "check-certificate=" + certificate + " " in public
    assert "check-certificate=" not in tunnel


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://10.251.0.1:8088/api/router/checkin",
        "http://example.net:8088/api/router/checkin",
        "http://8.8.8.8:8088/api/router/checkin",
        "http://10.251.0.1:8000/api/router/checkin",
        "http://10.251.0.1:8088/other",
        TUNNEL + "?x=1",
        TUNNEL + "#x",
        "http://user@10.251.0.1:8088/api/router/checkin",
        TUNNEL + '"; reboot',
        "http://10.999.0.1:8088/api/router/checkin",
        "http://[bad",
        "",
    ],
)
def test_tunnel_token_cannot_be_sent_to_an_arbitrary_plaintext_endpoint(endpoint):
    with pytest.raises(ValueError):
        prefer_tunnel_transport(source(), endpoint)


def test_unexpected_or_duplicate_fetch_shape_is_refused():
    original = source()
    for invalid in (
        original.replace(":local res [", ":local other ["),
        original + original,
    ):
        with pytest.raises(ValueError):
            prefer_tunnel_transport(invalid, TUNNEL)


def test_default_transport_remains_public_and_opt_in_source_is_balanced():
    assert BEGIN not in source()
    changed = source(tunnel_endpoint_url=TUNNEL)
    for left, right in (("{", "}"), ("[", "]"), ("(", ")")):
        assert changed.count(left) == changed.count(right)
    assert changed.count('"') % 2 == 0
    assert ":global" not in changed and ":return" not in changed
