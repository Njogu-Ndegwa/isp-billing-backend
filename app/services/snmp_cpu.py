"""Minimal, dependency-free SNMP v2c reader for router CPU load.

Why hand-rolled: we need exactly one thing (HOST-RESOURCES-MIB hrProcessorLoad)
and the dependency tree is unpinned (see docs/agent-memory: unpinned deps drift
into prod on every deploy), so a small BER codec is safer than a new library.

Why asyncio UDP and not a thread: the app runs on a 2-vCPU box whose default
executor has only 6 workers, shared with PPPoE provisioning, expiry cleanup and
other jobs. SNMP is one small UDP datagram per request; running it on the event
loop means a slow or dead router can never occupy a worker thread that a
payment is waiting for. Every request is bounded by ``timeout`` x ``retries``.

It never uses the RouterOS API, the per-router locks, or the circuit breaker.
"""

from __future__ import annotations

import asyncio
import itertools
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# HOST-RESOURCES-MIB::hrProcessorLoad — one row per CPU core, integer 0-100.
HR_PROCESSOR_LOAD = (1, 3, 6, 1, 2, 1, 25, 3, 3, 1, 2)
SNMP_PORT = 161
MAX_CORES = 16

_SEQUENCE = 0x30
_INTEGER = 0x02
_OCTET_STRING = 0x04
_NULL = 0x05
_OID = 0x06
_GET_NEXT = 0xA1
_RESPONSE = 0xA2
_GAUGE32 = 0x42
_COUNTER32 = 0x41
_UNSIGNED_TYPES = (_INTEGER, _GAUGE32, _COUNTER32, 0x43)  # 0x43 = TimeTicks
_NO_SUCH_OBJECT, _NO_SUCH_INSTANCE, _END_OF_MIB = 0x80, 0x81, 0x82

_request_ids = itertools.count(1)


class SnmpError(Exception):
    pass


# --- BER encoding ---------------------------------------------------------------

def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _len(len(value)) + value


def _int(value: int) -> bytes:
    length = max(1, (value.bit_length() + 8) // 8)
    return _tlv(_INTEGER, value.to_bytes(length, "big", signed=True))


def _oid(oid: tuple[int, ...]) -> bytes:
    if len(oid) < 2:
        raise ValueError("OID needs at least two arcs")
    out = bytearray([40 * oid[0] + oid[1]])
    for arc in oid[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        out.extend(reversed(chunk))
    return _tlv(_OID, bytes(out))


def encode_get_next(community: str, oid: tuple[int, ...], request_id: int) -> bytes:
    varbind = _tlv(_SEQUENCE, _oid(oid) + _tlv(_NULL, b""))
    pdu = _tlv(_GET_NEXT, _int(request_id) + _int(0) + _int(0) + _tlv(_SEQUENCE, varbind))
    return _tlv(_SEQUENCE, _int(1) + _tlv(_OCTET_STRING, community.encode()) + pdu)


# --- BER decoding ---------------------------------------------------------------

def _read_tlv(data: bytes, pos: int) -> tuple[int, bytes, int]:
    if pos + 2 > len(data):
        raise SnmpError("truncated TLV")
    tag = data[pos]
    first = data[pos + 1]
    pos += 2
    if first & 0x80:
        n = first & 0x7F
        if n == 0 or n > 4 or pos + n > len(data):
            raise SnmpError("bad length")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    else:
        length = first
    end = pos + length
    if end > len(data):
        raise SnmpError("truncated value")
    return tag, data[pos:end], end


def _decode_oid(raw: bytes) -> tuple[int, ...]:
    if not raw:
        raise SnmpError("empty OID")
    arcs = [raw[0] // 40, raw[0] % 40]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(value)
            value = 0
    return tuple(arcs)


def decode_response(data: bytes) -> tuple[int, int, tuple[int, ...], Optional[int]]:
    """Return (request_id, error_status, oid, int_value_or_None)."""
    tag, msg, _ = _read_tlv(data, 0)
    if tag != _SEQUENCE:
        raise SnmpError("not a SEQUENCE")
    _, _version, pos = _read_tlv(msg, 0)
    _, _community, pos = _read_tlv(msg, pos)
    tag, pdu, _ = _read_tlv(msg, pos)
    if tag != _RESPONSE:
        raise SnmpError(f"unexpected PDU 0x{tag:02x}")
    _, rid, pos = _read_tlv(pdu, 0)
    _, err, pos = _read_tlv(pdu, pos)
    _, _err_index, pos = _read_tlv(pdu, pos)
    _, varbinds, _ = _read_tlv(pdu, pos)
    _, varbind, _ = _read_tlv(varbinds, 0)
    tag, raw_oid, vpos = _read_tlv(varbind, 0)
    if tag != _OID:
        raise SnmpError("varbind without OID")
    vtag, vraw, _ = _read_tlv(varbind, vpos)
    value: Optional[int]
    if vtag in _UNSIGNED_TYPES:
        value = int.from_bytes(vraw, "big", signed=(vtag == _INTEGER)) if vraw else 0
    else:
        value = None  # noSuchObject / endOfMibView / non-integer
    return (int.from_bytes(rid, "big", signed=True), int.from_bytes(err, "big"),
            _decode_oid(raw_oid), value)


# --- asyncio UDP transport ------------------------------------------------------

class _OneShot(asyncio.DatagramProtocol):
    def __init__(self, future: asyncio.Future):
        self.future = future

    def datagram_received(self, data, addr):
        if not self.future.done():
            self.future.set_result(data)

    def error_received(self, exc):
        if not self.future.done():
            self.future.set_exception(exc)


async def _request(host: str, payload: bytes, *, port: int, timeout: float) -> bytes:
    loop = asyncio.get_running_loop()
    future: asyncio.Future = loop.create_future()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: _OneShot(future), remote_addr=(host, port))
    try:
        transport.sendto(payload)
        return await asyncio.wait_for(future, timeout)
    finally:
        transport.close()


async def get_next(host: str, community: str, oid: tuple[int, ...], *,
                   port: int = SNMP_PORT, timeout: float = 2.0, retries: int = 1):
    """One GetNext. Returns (next_oid, int_value_or_None). Raises on timeout/error."""
    last_exc: Exception = SnmpError("no attempt")
    for _ in range(retries + 1):
        rid = next(_request_ids) & 0x7FFFFFFF
        try:
            data = await _request(host, encode_get_next(community, oid, rid),
                                  port=port, timeout=timeout)
            got_rid, err, next_oid, value = decode_response(data)
            if got_rid != rid:
                raise SnmpError("request id mismatch")
            if err:
                raise SnmpError(f"error-status {err}")
            return next_oid, value
        except (asyncio.TimeoutError, OSError, SnmpError) as exc:
            last_exc = exc
    raise last_exc


async def read_cpu_load(host: str, community: str, *, port: int = SNMP_PORT,
                        timeout: float = 2.0, retries: int = 1) -> Optional[int]:
    """Average hrProcessorLoad across cores, or None when unreadable.

    Never raises: an unreachable or non-SNMP router simply yields None.
    """
    loads: list[int] = []
    oid = HR_PROCESSOR_LOAD
    try:
        for _ in range(MAX_CORES):
            oid, value = await get_next(host, community, oid, port=port,
                                        timeout=timeout, retries=retries)
            if oid[:len(HR_PROCESSOR_LOAD)] != HR_PROCESSOR_LOAD or value is None:
                break
            loads.append(max(0, min(100, int(value))))
    except Exception as exc:  # noqa: BLE001 - telemetry must never raise
        logger.debug("SNMP CPU read failed for %s: %s", host, exc)
        return None
    if not loads:
        return None
    return round(sum(loads) / len(loads))
