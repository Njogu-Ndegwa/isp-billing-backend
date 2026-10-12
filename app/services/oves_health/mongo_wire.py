"""Unauthenticated MongoDB ``hello`` over the wire protocol (OP_MSG), with a
tiny BSON codec, so the billing image needs no Mongo driver.

``hello`` needs no authentication and tells us, per member: is it the
writable primary, which member it believes is primary, the replica-set name,
and its last write time (so a lagging secondary is visible without the
clusterMonitor role nobody has the password for).
"""

from __future__ import annotations

import asyncio
import struct
import time
from datetime import datetime, timezone
from typing import Any

OP_MSG = 2013


def _cstring(s: str) -> bytes:
    return s.encode() + b"\x00"


def encode_doc(doc: dict) -> bytes:
    body = b""
    for k, v in doc.items():
        if isinstance(v, bool):
            body += b"\x08" + _cstring(k) + (b"\x01" if v else b"\x00")
        elif isinstance(v, int):
            body += b"\x10" + _cstring(k) + struct.pack("<i", v)
        elif isinstance(v, str):
            raw = v.encode()
            body += b"\x02" + _cstring(k) + struct.pack("<i", len(raw) + 1) + raw + b"\x00"
        else:
            raise TypeError(f"unsupported BSON value for {k}")
    return struct.pack("<i", len(body) + 5) + body + b"\x00"


def decode_doc(buf: bytes, pos: int = 0) -> tuple[dict, int]:
    (length,) = struct.unpack_from("<i", buf, pos)
    end = pos + length - 1
    pos += 4
    out: dict[str, Any] = {}
    while pos < end:
        t = buf[pos]
        pos += 1
        z = buf.index(b"\x00", pos)
        key = buf[pos:z].decode("utf-8", "replace")
        pos = z + 1
        if t == 0x01:
            (out[key],) = struct.unpack_from("<d", buf, pos); pos += 8
        elif t in (0x02, 0x0D, 0x0E):
            (n,) = struct.unpack_from("<i", buf, pos)
            out[key] = buf[pos + 4:pos + 4 + n - 1].decode("utf-8", "replace"); pos += 4 + n
        elif t in (0x03, 0x04):
            sub, pos = decode_doc(buf, pos)
            out[key] = list(sub.values()) if t == 0x04 else sub
        elif t == 0x05:
            (n,) = struct.unpack_from("<i", buf, pos); pos += 5 + n; out[key] = None
        elif t == 0x07:
            out[key] = buf[pos:pos + 12].hex(); pos += 12
        elif t == 0x08:
            out[key] = buf[pos] == 1; pos += 1
        elif t == 0x09:
            (ms,) = struct.unpack_from("<q", buf, pos); pos += 8
            out[key] = datetime.fromtimestamp(ms / 1000, tz=timezone.utc).replace(tzinfo=None)
        elif t in (0x0A, 0x06, 0xFF, 0x7F):
            out[key] = None
        elif t == 0x10:
            (out[key],) = struct.unpack_from("<i", buf, pos); pos += 4
        elif t in (0x11, 0x12):
            (out[key],) = struct.unpack_from("<q", buf, pos); pos += 8
        elif t == 0x13:
            out[key] = None; pos += 16
        else:
            raise ValueError(f"unsupported BSON type 0x{t:02x}")
    return out, end + 1


def build_hello(request_id: int = 1) -> bytes:
    section = b"\x00" + encode_doc({"hello": 1, "$db": "admin"})
    body = struct.pack("<I", 0) + section
    return struct.pack("<iiii", 16 + len(body), request_id, 0, OP_MSG) + body


def parse_reply(buf: bytes) -> dict:
    _len, _rid, _to, opcode = struct.unpack_from("<iiii", buf, 0)
    if opcode != OP_MSG:
        raise ValueError(f"unexpected opcode {opcode}")
    pos = 16 + 4
    if buf[pos] != 0:
        raise ValueError("unexpected section kind")
    doc, _ = decode_doc(buf, pos + 1)
    return doc


async def hello(host: str, port: int, timeout: float = 5.0) -> dict:
    """Return {ok, latency_ms, primary, writable, set, me, last_write} or raise."""
    start = time.perf_counter()
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    try:
        writer.write(build_hello())
        await writer.drain()
        head = await asyncio.wait_for(reader.readexactly(4), timeout)
        (length,) = struct.unpack("<i", head)
        if not 16 <= length <= 1_000_000:
            raise ValueError("bad reply length")
        rest = await asyncio.wait_for(reader.readexactly(length - 4), timeout)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
    doc = parse_reply(head + rest)
    last_write = (doc.get("lastWrite") or {}).get("lastWriteDate")
    return {
        "latency_ms": round((time.perf_counter() - start) * 1000, 1),
        "writable": bool(doc.get("isWritablePrimary") or doc.get("ismaster")),
        "secondary": bool(doc.get("secondary")),
        "set": doc.get("setName"),
        "primary": doc.get("primary"),
        "me": doc.get("me"),
        "last_write": last_write.isoformat() + "Z" if isinstance(last_write, datetime) else None,
    }


def summarize_members(members: list[dict]) -> tuple[str, str]:
    """(status, detail) for a replica set from per-member hello results."""
    reachable = [m for m in members if "error" not in m]
    primaries = [m for m in reachable if m.get("writable")]
    if not reachable:
        return "down", "no member reachable"
    if len(primaries) == 0:
        return "down", "no PRIMARY (election in progress or quorum lost)"
    if len(primaries) > 1:
        return "down", "more than one member claims PRIMARY (split brain)"
    detail = f"primary {primaries[0].get('me') or primaries[0]['host']}"
    if len(reachable) < len(members):
        return "slow", detail + f"; {len(members) - len(reachable)} member(s) unreachable"
    writes = [m.get("last_write") for m in reachable if m.get("last_write")]
    if len(writes) >= 2:
        newest = max(datetime.fromisoformat(w[:-1]) for w in writes)
        oldest = min(datetime.fromisoformat(w[:-1]) for w in writes)
        lag = (newest - oldest).total_seconds()
        if lag > 60:
            return "slow", detail + f"; a member is {int(lag)} s behind"
    return "up", detail
