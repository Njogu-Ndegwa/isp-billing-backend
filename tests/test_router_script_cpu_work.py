"""Bound control-plane work without weakening delivery or disconnect proof.

RouterOS executes these templates, so hardware benchmarks remain necessary.
These guards catch a return to a table search for every customer.
"""
from app.services.checkin_applier_script import render_checkin_applier_source
from app.services.expiry_reaper_script import render_expiry_reaper_script, script_source
from app.services.router_expiry import MAX_ITEMS_PER_CALL, parse_request


def test_checkin_collects_queue_names_once_and_uses_exact_keys():
    source = render_checkin_applier_source(identity="Bench", endpoint_url="http://example.com/checkin")
    collect = source[source.index(':local macs ""'):source.index(':local post (')]
    assert collect.count("/queue simple find") == 1
    assert '/queue simple find where name=("plan_" . $rf)' not in collect
    assert ':set ($queueNames->$qn) true' in collect
    assert '($queueNames->("plan_" . $rf))' in collect
    # Semicolons or substrings in someone else's queue name cannot mask a
    # missing exact plan queue, as a concatenated string index would allow.
    assert ':find $queueNames' not in collect
    # Snapshot order can change, and API-run print can return no map. Neither
    # is permission to advertise a partial inventory as a complete report.
    for variable, item in (("brow", "b"), ("urow", "u"), ("qrow", "q")):
        assert f'(${variable}->".id") = ${item}' in collect
    assert ':set readOk false' in collect
    assert ':set qOk false' in collect


def test_expiry_batches_searches_and_verifies_live_tables_before_acknowledging():
    source = script_source(render_expiry_reaper_script(
        identity="Bench", tunnel_url="http://example.com/expiry", public_url="https://example.com/expiry"))
    build = source[source.index(':local macPattern'):source.index(':set macPattern ($macPattern . ")\\$")')]
    assert "/ip hotspot" not in build and "/queue simple" not in build
    assert f'($batchSeen < {MAX_ITEMS_PER_CALL})' in build
    assert '$m ~ "^[0-9A-Fa-f:]+\\$"' in build  # no regex metacharacters from the reply
    remove = source[source.index(':if ($batchCount > 0) do={', source.index(':set queuePattern ($queuePattern . ")\\$")')):]
    disable = remove.index('/ip hotspot user set $users disabled=yes')
    kick = remove.index('/ip hotspot active remove $sessions')
    delete = remove.index('/ip hotspot user remove $users')
    unbind = remove.index('/ip hotspot ip-binding remove $bindings')
    ack = remove.index(':set bwExpDone ($bwExpDone . $m . "@"')
    assert disable < kick < delete < unbind < ack
    proof = remove[unbind:ack]
    for predicate in (
        '/ip hotspot user find where name~$userPattern',
        '/ip hotspot ip-binding find where mac-address~$macPattern',
        '/ip hotspot active find where mac-address~$macPattern',
        '/ip hotspot host find where mac-address~$macPattern and authorized',
        '/ip hotspot host find where mac-address~$macPattern and bypassed',
    ):
        assert predicate in proof
    # Bulk cached IDs are write targets, never evidence of successful deletion.
    assert ':if ([:len $users] > 0)' in remove
    assert ':if ([:len $bindings] > 0)' in remove


def test_full_expiry_batch_acknowledgement_fits_and_is_accepted():
    macs = [f"02:BB:56:30:00:{i:02X}" for i in range(MAX_ITEMS_PER_CALL)]
    done = ''.join(f'{mac}@1792425600,' for mac in macs)
    assert 700 < len(done) < 2048
    request = parse_request(f'ident=Bench&v=4&now=1792425600&due=&done={done}')
    assert len(request.done) == MAX_ITEMS_PER_CALL
    assert {mac for mac, _ in request.done} == set(macs)


def test_outage_acknowledgements_are_sent_in_server_sized_chunks():
    source = script_source(render_expiry_reaper_script(
        identity="Bench", tunnel_url="http://example.com/expiry", public_url="https://example.com/expiry"))
    assert f'($doneCount < {MAX_ITEMS_PER_CALL})' in source
    assert '"&done=" . $doneSend' in source
    assert ':local doneRest $bwExpDone' in source
    accepted = source.index(':if ($ok && ([:pick $rd 0 3] = "BW1"))')
    advance = source.index(':set bwExpDone $doneRest')
    assert accepted < advance
    assert ':set bwExpDone ""' not in source[accepted:]
