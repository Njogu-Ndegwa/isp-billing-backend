from app.services.usage_push_script import render_realtime_push_script
URL='https://isp.bitwavetechnologies.net/api/router/usage-push'

def test_opt_in_preserves_legacy_default_and_v3_counter_contract():
    legacy=render_realtime_push_script(identity='Router-0001',endpoint_url=URL)
    native=render_realtime_push_script(identity='Router-0001',endpoint_url=URL,native_ports=True)
    assert 'bw-native-ports-json' not in legacy and ':serialize to=json' not in legacy
    assert '[/ip hotspot host get $h bytes-in]' in legacy
    assert ':local hrow [/ip hotspot host get $h]' in native
    assert '($hrow->"bytes-in")' in native and '($hrow->"bytes-out")' in native
    assert '($qrow->"bytes")' in native
    assert r'\"v\":3' in native and 'bwv4' not in native
    assert ':if (([:len $hm] > 0)' in native
    assert ':typeof $hbi' in native and ':typeof $hbo' in native
    assert r'",\"ports\":[]"' in native
    assert '"last_link_up"=("" . $ilu)' in native
    assert ':if ([:typeof $ire] != "num") do={ :set ire 0 }' in native

def test_native_encoder_keeps_the_existing_per_router_token_and_transport():
    kwargs={'identity':'Router-0001','endpoint_url':URL,'wan_interface':'ether1','interval_seconds':60}
    legacy=render_realtime_push_script(**kwargs)
    native=render_realtime_push_script(**kwargs,native_ports=True)
    for prefix in ['    :local tok ', '    :local url ', '    :local ident ']:
        assert next(s for s in legacy.splitlines() if s.startswith(prefix)) == next(s for s in native.splitlines() if s.startswith(prefix))
    assert native.startswith('# Bitwave usage push')
    assert '# bw-gate v1' in native
    assert 'interval=60s' in native
