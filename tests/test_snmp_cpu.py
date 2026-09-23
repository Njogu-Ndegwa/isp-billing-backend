"""Minimal SNMP v2c CPU reader (app/services/snmp_cpu.py), against a fake local agent."""

import asyncio

import pytest

from app.services import snmp_cpu as s

OID = s.HR_PROCESSOR_LOAD


def _response(request: bytes, oid, value, *, tag=0x02, rid_override=None):
    """Build a Response PDU echoing the request id, using the module's own encoder."""
    _, msg, _ = s._read_tlv(request, 0)
    _, _v, pos = s._read_tlv(msg, 0)
    _, community, pos = s._read_tlv(msg, pos)
    _, pdu, _ = s._read_tlv(msg, pos)
    _, rid_raw, _ = s._read_tlv(pdu, 0)
    rid = int.from_bytes(rid_raw, "big", signed=True) if rid_override is None else rid_override
    if tag == 0x02:
        val = s._int(value)
    else:
        val = s._tlv(tag, b"")
    varbind = s._tlv(0x30, s._oid(oid) + val)
    body = s._int(rid) + s._int(0) + s._int(0) + s._tlv(0x30, varbind)
    return s._tlv(0x30, s._int(1) + s._tlv(0x04, community) + s._tlv(0xA2, body))


def _requested_oid(request: bytes):
    _, msg, _ = s._read_tlv(request, 0)
    _, _v, pos = s._read_tlv(msg, 0)
    _, _c, pos = s._read_tlv(msg, pos)
    _, pdu, _ = s._read_tlv(msg, pos)
    pos = 0
    for _ in range(3):
        _, _x, pos = s._read_tlv(pdu, pos)
    _, vbs, _ = s._read_tlv(pdu, pos)
    _, vb, _ = s._read_tlv(vbs, 0)
    _, raw, _ = s._read_tlv(vb, 0)
    return s._decode_oid(raw)


class _Agent(asyncio.DatagramProtocol):
    """Serves a table {oid: value}; GetNext returns the next row, then endOfMibView."""

    def __init__(self, table, community="bw-ro", silent=False):
        self.table = sorted(table.items())
        self.community = community
        self.silent = silent
        self.requests = 0

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.requests += 1
        if self.silent:
            return
        asked = _requested_oid(data)
        nxt = next(((o, v) for o, v in self.table if o > asked), None)
        if nxt is None:
            self.transport.sendto(_response(data, asked, None, tag=0x82), addr)
        else:
            self.transport.sendto(_response(data, nxt[0], nxt[1]), addr)


async def _serve(table, **kw):
    loop = asyncio.get_running_loop()
    proto = _Agent(table, **kw)
    transport, _ = await loop.create_datagram_endpoint(lambda: proto, local_addr=("127.0.0.1", 0))
    return transport, proto, transport.get_extra_info("sockname")[1]


def test_oid_roundtrip_and_multibyte_arcs():
    for oid in [OID, (1, 3, 6, 1, 4, 1, 14988, 1, 1, 3, 10, 0), (1, 3, 6, 1, 2, 1, 25, 3, 3, 1, 2, 200000)]:
        tag, raw, _ = s._read_tlv(s._oid(oid), 0)
        assert tag == 0x06 and s._decode_oid(raw) == oid


def test_long_length_form():
    blob = b"x" * 300
    tag, value, end = s._read_tlv(s._tlv(0x04, blob), 0)
    assert value == blob and end == len(s._tlv(0x04, blob))


def test_malformed_packets_raise_snmp_error():
    with pytest.raises(s.SnmpError):
        s.decode_response(b"\x30\x05\x02")
    with pytest.raises(s.SnmpError):
        s.decode_response(b"")


async def test_reads_single_core_hap_lite():
    transport, proto, port = await _serve({OID + (1,): 100, (1, 3, 6, 1, 2, 1, 25, 3, 4, 1): 7})
    try:
        assert await s.read_cpu_load("127.0.0.1", "bw-ro", port=port, timeout=1) == 100
        assert proto.requests == 2          # core 1, then walked past the column
    finally:
        transport.close()


async def test_averages_multiple_cores():
    transport, _, port = await _serve({OID + (1,): 90, OID + (2,): 70, OID + (3,): 80, OID + (4,): 60})
    try:
        assert await s.read_cpu_load("127.0.0.1", "bw-ro", port=port, timeout=1) == 75
    finally:
        transport.close()


async def test_end_of_mib_and_empty_table_give_none():
    transport, _, port = await _serve({})
    try:
        assert await s.read_cpu_load("127.0.0.1", "bw-ro", port=port, timeout=1) is None
    finally:
        transport.close()


async def test_silent_router_times_out_to_none_without_raising():
    transport, proto, port = await _serve({OID + (1,): 50}, silent=True)
    try:
        started = asyncio.get_running_loop().time()
        assert await s.read_cpu_load("127.0.0.1", "bw-ro", port=port, timeout=0.2, retries=1) is None
        assert asyncio.get_running_loop().time() - started < 2
        assert proto.requests == 2          # first try + one retry, then give up
    finally:
        transport.close()


async def test_many_reads_run_concurrently_on_the_event_loop():
    transport, _, port = await _serve({OID + (1,): 42})
    try:
        results = await asyncio.gather(*[
            s.read_cpu_load("127.0.0.1", "bw-ro", port=port, timeout=1) for _ in range(25)])
        assert results == [42] * 25
    finally:
        transport.close()


def test_module_uses_no_threads():
    import inspect
    src = inspect.getsource(s)
    assert "to_thread" not in src and "run_in_executor" not in src and "ThreadPool" not in src
