"""Registry discovery, credential handling, and per-tenant provider resolution."""

import httpx
import pytest

from app.config import settings
from app.db.models import MessagingProviderAccount, User
from app.services.messaging import accounts, registry
from app.services.messaging.base import (
    MessagingProvider,
    ProviderField,
    ProviderSpec,
    SendResult,
)
from app.services.messaging.hostpinnacle import HostPinnacleProvider


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def test_registry_discovers_every_installed_provider():
    names = registry.provider_names()
    assert {"africastalking", "talksasa", "hostpinnacle"} <= set(names)


def test_registry_rejects_unknown_provider():
    with pytest.raises(ValueError):
        registry.get_spec("does-not-exist")


def test_describe_exposes_fields_but_never_values():
    catalogue = {p["name"]: p for p in registry.describe()}
    hp = catalogue["hostpinnacle"]
    fields = {f["key"]: f for f in hp["fields"]}
    assert fields["password"]["secret"] is True
    assert fields["userid"]["secret"] is False
    assert fields["base_url"]["default"] == "https://smsportal.hostpinnacle.co.ke"
    # The catalogue is a schema, not a config dump.
    assert all("value" not in f for f in hp["fields"])


def test_spec_validate_names_missing_required_fields():
    spec = registry.get_spec("hostpinnacle")
    problems = spec.validate({"userid": "dukestop"})
    assert problems == ["Portal password is required"]
    assert spec.validate({"userid": "dukestop", "password": "pw"}) == []


def test_spec_build_applies_defaults_and_drops_unknown_keys():
    spec = registry.get_spec("hostpinnacle")
    provider = spec.build(
        {"userid": "dukestop", "password": "pw", "nonsense": "ignored"}
    )
    assert isinstance(provider, HostPinnacleProvider)
    assert provider.base_url == "https://smsportal.hostpinnacle.co.ke"
    assert provider.send_path == "/SMSApi/send"


def test_a_new_provider_module_needs_no_factory_edit(monkeypatch):
    """The whole installation step for a provider is: define a SPEC."""

    class _Bespoke(MessagingProvider):
        name = "bespoke"

        def __init__(self, token: str):
            self.token = token

        async def send_bulk(self, recipients, body, sender_id):
            return []

    spec = ProviderSpec(
        name="bespoke",
        label="Bespoke Gateway",
        factory=_Bespoke,
        fields=[ProviderField("token", "Token", secret=True)],
    )
    monkeypatch.setitem(registry.all_specs(), "bespoke", spec)

    built = registry.build("bespoke", {"token": "abc"})
    assert isinstance(built, _Bespoke)
    assert built.token == "abc"


# ---------------------------------------------------------------------------
# Credential storage
# ---------------------------------------------------------------------------

def test_secrets_are_encrypted_at_rest_and_masked_on_read():
    spec = registry.get_spec("hostpinnacle")
    stored = accounts.encrypt_config(
        spec, {"userid": "dukestop", "password": "d0vEaW5n"}
    )
    assert stored["password"] != "d0vEaW5n"
    assert "d0vEaW5n" not in str(stored)
    assert stored["userid"] == "dukestop"  # not marked secret

    assert accounts.decrypt_config(spec, stored)["password"] == "d0vEaW5n"

    masked = accounts.masked_config(spec, stored)
    assert masked["password"].endswith("aW5n")
    assert "d0vEaW5n" not in masked["password"]
    assert masked["userid"] == "dukestop"


def test_update_without_resending_a_secret_keeps_it():
    spec = registry.get_spec("hostpinnacle")
    stored = accounts.encrypt_config(
        spec, {"userid": "dukestop", "password": "d0vEaW5n"}
    )
    masked = accounts.masked_config(spec, stored)

    # A UI PUTs back the form it rendered: the mask, not the real secret.
    merged = accounts.merge_config(
        spec, stored, {"userid": "newuser", "password": masked["password"]}
    )
    plain = accounts.decrypt_config(spec, merged)
    assert plain["password"] == "d0vEaW5n"
    assert plain["userid"] == "newuser"

    # An omitted secret is also left alone; a real one replaces it.
    merged = accounts.merge_config(spec, stored, {"password": "rotated"})
    assert accounts.decrypt_config(spec, merged)["password"] == "rotated"


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------

async def _make_reseller(db, email: str | None = None) -> User:
    from tests.factories import make_reseller

    return await make_reseller(db, **({"email": email} if email else {}))


def _hostpinnacle_account(user_id, **kwargs) -> MessagingProviderAccount:
    spec = registry.get_spec("hostpinnacle")
    defaults = dict(
        user_id=user_id,
        provider="hostpinnacle",
        label="Client gateway",
        sender_id="DUKESTOP",
        credentials=accounts.encrypt_config(
            spec, {"userid": "dukestop", "password": "d0vEaW5n"}
        ),
        is_default=True,
        is_active=True,
    )
    defaults.update(kwargs)
    return MessagingProviderAccount(**defaults)


@pytest.mark.asyncio
async def test_resolution_falls_back_to_env_when_nothing_configured(db, monkeypatch):
    """A deployment with no accounts behaves exactly as it did before."""
    monkeypatch.setattr(settings, "SMS_PROVIDER", "talksasa")
    monkeypatch.setattr(settings, "TALKSASA_API_TOKEN", "token")
    monkeypatch.setattr(settings, "SMS_SENDER_ID", "PLATFORM")

    user = await _make_reseller(db)
    resolved = await accounts.resolve(db, user.id)
    assert resolved.source == "env"
    assert resolved.provider.name == "talksasa"
    assert resolved.sender_id == "PLATFORM"
    assert resolved.account_id is None


@pytest.mark.asyncio
async def test_reseller_account_wins_over_platform_and_env(db, monkeypatch):
    monkeypatch.setattr(settings, "SMS_PROVIDER", "talksasa")
    monkeypatch.setattr(settings, "TALKSASA_API_TOKEN", "token")
    monkeypatch.setattr(settings, "SMS_SENDER_ID", "PLATFORM")

    user = await _make_reseller(db)
    db.add(MessagingProviderAccount(
        user_id=None, provider="talksasa", label="Platform",
        sender_id="PLATFORMSMS",
        credentials=accounts.encrypt_config(
            registry.get_spec("talksasa"), {"api_token": "platform-token"}
        ),
        is_default=True, is_active=True,
    ))
    db.add(_hostpinnacle_account(user.id))
    await db.flush()

    resolved = await accounts.resolve(db, user.id)
    assert resolved.source == "reseller"
    assert resolved.provider.name == "hostpinnacle"
    assert resolved.provider.userid == "dukestop"
    assert resolved.provider.password == "d0vEaW5n"
    # The reseller's own approved sender ID, NOT the SMS_SENDER_ID override.
    assert resolved.sender_id == "DUKESTOP"


@pytest.mark.asyncio
async def test_reseller_without_account_uses_the_platform_account(db, monkeypatch):
    monkeypatch.setattr(settings, "SMS_SENDER_ID", "")
    user = await _make_reseller(db)
    db.add(MessagingProviderAccount(
        user_id=None, provider="talksasa", label="Platform",
        sender_id="PLATFORMSMS",
        credentials=accounts.encrypt_config(
            registry.get_spec("talksasa"), {"api_token": "platform-token"}
        ),
        is_default=True, is_active=True,
    ))
    await db.flush()

    resolved = await accounts.resolve(db, user.id)
    assert resolved.source == "platform"
    assert resolved.sender_id == "PLATFORMSMS"


@pytest.mark.asyncio
async def test_inactive_reseller_account_is_skipped(db, monkeypatch):
    monkeypatch.setattr(settings, "SMS_SENDER_ID", "")
    user = await _make_reseller(db)
    db.add(_hostpinnacle_account(user.id, is_active=False))
    db.add(MessagingProviderAccount(
        user_id=None, provider="talksasa", label="Platform",
        sender_id="PLATFORMSMS",
        credentials=accounts.encrypt_config(
            registry.get_spec("talksasa"), {"api_token": "t"}
        ),
        is_default=True, is_active=True,
    ))
    await db.flush()

    resolved = await accounts.resolve(db, user.id)
    assert resolved.source == "platform"


@pytest.mark.asyncio
async def test_unusable_reseller_account_falls_through_rather_than_failing(db, monkeypatch):
    """A reseller row naming an uninstalled provider must not black-hole their SMS."""
    monkeypatch.setattr(settings, "SMS_SENDER_ID", "")
    user = await _make_reseller(db)
    db.add(MessagingProviderAccount(
        user_id=user.id, provider="uninstalled-vendor", label="Broken",
        sender_id="BROKEN", credentials={}, is_default=True, is_active=True,
    ))
    db.add(MessagingProviderAccount(
        user_id=None, provider="talksasa", label="Platform",
        sender_id="PLATFORMSMS",
        credentials=accounts.encrypt_config(
            registry.get_spec("talksasa"), {"api_token": "t"}
        ),
        is_default=True, is_active=True,
    ))
    await db.flush()

    resolved = await accounts.resolve(db, user.id)
    assert resolved.source == "platform"


@pytest.mark.asyncio
async def test_queue_time_sender_id_matches_the_gateway_that_will_send(db, monkeypatch):
    """The stamped sender ID must be the reseller's, not the platform override."""
    monkeypatch.setattr(settings, "SMS_SENDER_ID", "PLATFORM")
    user = await _make_reseller(db)
    db.add(_hostpinnacle_account(user.id))
    await db.flush()

    assert await accounts.resolve_sender_id_for(db, user.id, "DBBRAND") == "DUKESTOP"
    # With no reseller account, the operational override still applies.
    other = await _make_reseller(db)
    assert await accounts.resolve_sender_id_for(db, other.id, "DBBRAND") == "PLATFORM"


# ---------------------------------------------------------------------------
# HostPinnacle transport
# ---------------------------------------------------------------------------

def _fake_client(captured, payload, status_code=200):
    class _FakeResponse:
        def __init__(self):
            self.status_code = status_code
            self.text = str(payload)

        def json(self):
            return payload

    class _FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, data=None, headers=None):
            captured["url"] = url
            captured["data"] = data
            captured["headers"] = headers
            return _FakeResponse()

    return _FakeClient


@pytest.mark.asyncio
async def test_hostpinnacle_posts_form_credentials_and_normalizes_numbers(monkeypatch):
    captured = {}
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client(captured, {
        "status": "success",
        "mobile": "254712345678,254700000000",
        "invalidMobile": "",
        "transactionId": "txn-1",
        "statusCode": "900",
        "reason": "success",
    }))
    provider = HostPinnacleProvider(userid="dukestop", password="d0vEaW5n")
    results = await provider.send_bulk(["0712345678", "+254700000000"], "Hi", "DUKESTOP")

    assert captured["url"] == "https://smsportal.hostpinnacle.co.ke/SMSApi/send"
    assert captured["data"]["userid"] == "dukestop"
    assert captured["data"]["password"] == "d0vEaW5n"
    assert captured["data"]["senderid"] == "DUKESTOP"
    assert captured["data"]["mobile"] == "254712345678,254700000000"
    assert captured["data"]["sendMethod"] == "quick"
    assert captured["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
    assert "apikey" not in captured["headers"]

    # Results come back keyed by the caller's original strings.
    assert [r.recipient for r in results] == ["0712345678", "+254700000000"]
    assert all(r.success for r in results)
    assert {r.provider_message_id for r in results} == {"txn-1"}


@pytest.mark.asyncio
async def test_hostpinnacle_marks_only_the_numbers_the_gateway_rejected(monkeypatch):
    captured = {}
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client(captured, {
        "status": "success",
        "mobile": "254712345678",
        "invalidMobile": "254700000000",
        "transactionId": "txn-2",
        "statusCode": "200",
    }))
    provider = HostPinnacleProvider(userid="u", password="p")
    results = await provider.send_bulk(
        ["254712345678", "254700000000"], "Hi", "BRAND"
    )
    by_phone = {r.recipient: r for r in results}
    assert by_phone["254712345678"].success is True
    assert by_phone["254700000000"].success is False
    assert by_phone["254700000000"].error == "invalid_recipient"


@pytest.mark.asyncio
async def test_hostpinnacle_error_payload_fails_every_recipient(monkeypatch):
    captured = {}
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client(captured, {
        "status": "error",
        "statusCode": "401",
        "reason": "Invalid username or password",
    }))
    provider = HostPinnacleProvider(userid="u", password="wrong")
    results = await provider.send_bulk(["254712345678"], "Hi", "BRAND")
    assert results[0].success is False
    assert results[0].error == "Invalid username or password"


@pytest.mark.asyncio
async def test_hostpinnacle_sends_api_key_header_when_configured(monkeypatch):
    captured = {}
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client(
        captured, {"status": "success", "statusCode": "900", "transactionId": "t"}
    ))
    provider = HostPinnacleProvider(userid="u", password="p", api_key="secret-key")
    await provider.send_bulk(["254712345678"], "Hi", "BRAND")
    assert captured["headers"]["apikey"] == "secret-key"


@pytest.mark.asyncio
async def test_hostpinnacle_alternate_deployment_paths_are_config_not_code(monkeypatch):
    captured = {}
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client(
        captured, {"status": "success", "statusCode": "900", "transactionId": "t"}
    ))
    provider = HostPinnacleProvider(
        userid="u", password="p",
        base_url="https://other.example/", send_path="SMSApi/rest/send",
        send_method="simpleMsg",
    )
    await provider.send_bulk(["254712345678"], "Hi", "BRAND")
    assert captured["url"] == "https://other.example/SMSApi/rest/send"
    assert captured["data"]["sendMethod"] == "simpleMsg"


@pytest.mark.asyncio
async def test_hostpinnacle_missing_credentials_makes_no_request(monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("must not open an HTTP client without credentials")

    monkeypatch.setattr(httpx, "AsyncClient", _boom)
    provider = HostPinnacleProvider(userid="", password="p")
    results = await provider.send_bulk(["254712345678"], "Hi", "BRAND")
    assert results[0].success is False
    assert results[0].error == "missing_userid"


@pytest.mark.asyncio
async def test_hostpinnacle_network_error_fails_cleanly(monkeypatch):
    class _Boom:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, *a, **k):
            raise httpx.ConnectError("dns failure")

    monkeypatch.setattr(httpx, "AsyncClient", _Boom)
    provider = HostPinnacleProvider(userid="u", password="p")
    results = await provider.send_bulk(["254712345678"], "Hi", "BRAND")
    assert results[0].success is False
    assert results[0].status == "network_error"


@pytest.mark.asyncio
async def test_every_provider_returns_one_result_per_recipient():
    """The contract dispatch and credit refunds rely on, checked for all."""
    for name in registry.provider_names():
        spec = registry.get_spec(name)
        provider = spec.build({f.key: "x" for f in spec.fields})
        assert await provider.send_bulk([], "Hi", "BRAND") == []
        assert isinstance(provider, MessagingProvider)
        assert provider.name == name
        assert isinstance(SendResult(recipient="x", success=True), SendResult)
