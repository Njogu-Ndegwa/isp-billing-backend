"""RADIUS CoA disconnect: packet-level client behavior and the DB-session
handling of the service-layer path that mixes the CoA boundary with RADIUS
table writes.

Two layers under test, both with the RADIUS/router boundary faked:

* RadiusCoA.disconnect_user (app/services/radius_service.py) — a raw UDP
  Disconnect-Request client. Faked at the socket, so the packet format
  (code 40, MD5 authenticator over the shared secret, User-Name attribute)
  and the ACK/NAK/timeout verdicts are pinned without a router.

* RadiusProvisioning.remove_user (app/services/radius_provisioning.py) —
  the deprovisioning flow: CoA disconnect (best-effort) then DELETE from the
  radius_* tables and COMMIT. DB-session expectations: the deletion is
  committed (visible from a different session); a failed disconnect must NOT
  abort the deprovisioning; a raised boundary error is contained and leaves
  the session usable (no wedged transaction).
"""

import hashlib
import socket as socket_module

import pytest
from sqlalchemy import text

from app.services import radius_provisioning as rp_module
from app.services import radius_service as rs_module
from app.services.radius_provisioning import RadiusProvisioning
from app.services.radius_service import RadiusCoA

pytestmark = pytest.mark.asyncio

SECRET = "shared-secret"
DISCONNECT_REQUEST = 40
DISCONNECT_ACK = 41
DISCONNECT_NAK = 42


# ---------------------------------------------------------------------------
# Fake UDP socket
# ---------------------------------------------------------------------------

class FakeUdpSocket:
    def __init__(self, response: bytes | None = None, raise_timeout: bool = False):
        self.response = response
        self.raise_timeout = raise_timeout
        self.sent: list[tuple[bytes, tuple]] = []
        self.closed = False
        self.timeout = None

    def settimeout(self, value):
        self.timeout = value

    def sendto(self, packet, addr):
        self.sent.append((packet, addr))

    def recvfrom(self, bufsize):
        if self.raise_timeout:
            raise socket_module.timeout()
        return self.response, ("10.0.0.2", 3799)

    def close(self):
        self.closed = True


def _patch_socket(monkeypatch, fake: FakeUdpSocket):
    monkeypatch.setattr(
        rs_module.socket, "socket", lambda *args, **kwargs: fake
    )


# ---------------------------------------------------------------------------
# RadiusCoA.disconnect_user — packet + verdict behavior
# ---------------------------------------------------------------------------

async def test_disconnect_ack_happy_path_sends_valid_packet(monkeypatch):
    fake = FakeUdpSocket(response=bytes([DISCONNECT_ACK]) + b"\x00" * 19)
    _patch_socket(monkeypatch, fake)

    coa = RadiusCoA("10.0.0.2", SECRET)
    success, message = coa.disconnect_user(username="AABBCCDDEEFF")

    assert success is True
    assert message == "User disconnected successfully"
    assert fake.closed is True

    (packet, addr), = fake.sent
    assert addr == ("10.0.0.2", 3799)
    # RADIUS header: code 40 (Disconnect-Request), length == packet size
    assert packet[0] == DISCONNECT_REQUEST
    assert int.from_bytes(packet[2:4], "big") == len(packet)
    # User-Name attribute (type 1) carrying the MAC-derived username
    attrs = packet[20:]
    assert attrs[0] == 1
    assert attrs[2:2 + attrs[1] - 2] == b"AABBCCDDEEFF"
    # Request Authenticator = MD5(header + 16 zero bytes + attrs + secret)
    expected_auth = hashlib.md5(
        packet[:4] + b"\x00" * 16 + attrs + SECRET.encode()
    ).digest()
    assert packet[4:20] == expected_auth


async def test_disconnect_nak_reports_rejection(monkeypatch):
    fake = FakeUdpSocket(response=bytes([DISCONNECT_NAK]) + b"\x00" * 19)
    _patch_socket(monkeypatch, fake)

    success, message = RadiusCoA("10.0.0.2", SECRET).disconnect_user(
        username="AABBCCDDEEFF"
    )

    assert success is False
    assert message == "Disconnect rejected by NAS"


async def test_disconnect_timeout_fails_and_closes_socket(monkeypatch):
    fake = FakeUdpSocket(raise_timeout=True)
    _patch_socket(monkeypatch, fake)

    success, message = RadiusCoA("10.0.0.2", SECRET).disconnect_user(
        username="AABBCCDDEEFF"
    )

    assert success is False
    assert message == "Timeout waiting for NAS response"
    assert fake.closed is True  # finally-block cleanup even on timeout


async def test_disconnect_requires_an_identifier(monkeypatch):
    def _explode(*args, **kwargs):  # pragma: no cover - guard
        raise AssertionError("no socket may be opened without an identifier")

    monkeypatch.setattr(rs_module.socket, "socket", _explode)

    success, message = RadiusCoA("10.0.0.2", SECRET).disconnect_user()

    assert success is False
    assert "identifier" in message


# ---------------------------------------------------------------------------
# RadiusProvisioning.remove_user — DB session handling around the boundary
# ---------------------------------------------------------------------------

USERNAME = "AABBCCDDEEFF"


async def _seed_radius_tables(db):
    """Minimal radius_* tables (raw-SQL only in prod, no ORM models)."""
    for ddl in (
        "CREATE TABLE IF NOT EXISTS radius_check (username TEXT, attribute TEXT)",
        "CREATE TABLE IF NOT EXISTS radius_reply (username TEXT, attribute TEXT)",
        "CREATE TABLE IF NOT EXISTS radius_usergroup (username TEXT, groupname TEXT)",
    ):
        await db.execute(text(ddl))
    await db.execute(
        text("INSERT INTO radius_check (username, attribute) VALUES (:u, 'Cleartext-Password')"),
        {"u": USERNAME},
    )
    await db.execute(
        text("INSERT INTO radius_reply (username, attribute) VALUES (:u, 'Mikrotik-Rate-Limit')"),
        {"u": USERNAME},
    )
    await db.commit()


class FakeCoA:
    """Fake RadiusCoA boundary: records construction and returns a verdict."""
    instances: list["FakeCoA"] = []

    verdict = (True, "User disconnected successfully")
    raise_error: Exception | None = None

    def __init__(self, nas_ip, secret, coa_port=3799):
        self.nas_ip = nas_ip
        self.secret = secret
        self.calls = []
        FakeCoA.instances.append(self)

    def disconnect_user(self, **kwargs):
        if FakeCoA.raise_error is not None:
            raise FakeCoA.raise_error
        self.calls.append(kwargs)
        return FakeCoA.verdict


@pytest.fixture
def fake_coa(monkeypatch):
    FakeCoA.instances = []
    FakeCoA.verdict = (True, "User disconnected successfully")
    FakeCoA.raise_error = None
    monkeypatch.setattr(rp_module, "RadiusCoA", FakeCoA)
    return FakeCoA


async def _radius_row_count(session, table):
    return (
        await session.execute(
            text(f"SELECT COUNT(*) FROM {table} WHERE username = :u"), {"u": USERNAME}
        )
    ).scalar()


async def test_remove_user_disconnects_deletes_and_commits(db, session_factory, fake_coa):
    await _seed_radius_tables(db)

    result = await RadiusProvisioning(db).remove_user(
        customer_id=1,
        mac_address="AA:BB:CC:DD:EE:FF",
        router_ip="10.0.0.2",
        radius_secret=SECRET,
    )

    assert result["success"] is True
    assert result["deleted_from_radius"] is True
    assert result["disconnect_result"] == {
        "success": True, "message": "User disconnected successfully",
    }
    # CoA targeted the right NAS with the MAC-derived username
    (coa,) = fake_coa.instances
    assert (coa.nas_ip, coa.secret) == ("10.0.0.2", SECRET)
    assert coa.calls == [{"username": USERNAME}]

    # The deletion was COMMITTED, not just flushed: rolling back the caller's
    # session must NOT resurrect the rows (StaticPool shares one connection,
    # so a would-be-uncommitted delete would be undone right here).
    await db.rollback()
    assert await _radius_row_count(db, "radius_check") == 0
    assert await _radius_row_count(db, "radius_reply") == 0
    async with session_factory() as other:
        assert await _radius_row_count(other, "radius_check") == 0


async def test_remove_user_proceeds_when_disconnect_fails(db, session_factory, fake_coa):
    """A NAK/timeout from the router must not leave the expired user
    provisioned in RADIUS — deprovisioning continues and commits."""
    await _seed_radius_tables(db)
    fake_coa.verdict = (False, "Timeout waiting for NAS response")

    result = await RadiusProvisioning(db).remove_user(
        customer_id=1,
        mac_address="AA:BB:CC:DD:EE:FF",
        router_ip="10.0.0.2",
        radius_secret=SECRET,
    )

    assert result["success"] is True
    assert result["deleted_from_radius"] is True
    assert result["disconnect_result"]["success"] is False

    async with session_factory() as other:
        assert await _radius_row_count(other, "radius_check") == 0


async def test_remove_user_contains_boundary_crash_and_session_stays_usable(
    db, fake_coa
):
    """If the CoA boundary raises, remove_user reports failure instead of
    propagating, and the caller's session is NOT left in a wedged state."""
    await _seed_radius_tables(db)
    fake_coa.raise_error = OSError("network unreachable")

    result = await RadiusProvisioning(db).remove_user(
        customer_id=1,
        mac_address="AA:BB:CC:DD:EE:FF",
        router_ip="10.0.0.2",
        radius_secret=SECRET,
    )

    assert result["success"] is False
    assert "network unreachable" in result["error"]

    # Session still usable for further work (no dangling failed transaction),
    # and nothing was deleted before the crash.
    assert await _radius_row_count(db, "radius_check") == 1
    assert await _radius_row_count(db, "radius_reply") == 1


async def test_remove_user_skips_disconnect_without_router_info(db, fake_coa):
    """No router_ip/secret -> no CoA attempt at all, deletion still commits."""
    await _seed_radius_tables(db)

    result = await RadiusProvisioning(db).remove_user(
        customer_id=1, mac_address="AA:BB:CC:DD:EE:FF",
    )

    assert result["success"] is True
    assert result["disconnect_result"] is None
    assert fake_coa.instances == []
    assert await _radius_row_count(db, "radius_check") == 0
