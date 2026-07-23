"""Email service transport selection: SMTP-first, Resend fallback, safe no-op."""

import pytest

from app.config import settings
from app.services import email_service


@pytest.mark.asyncio
async def test_disabled_when_nothing_configured(monkeypatch):
    monkeypatch.setattr(settings, "SMTP_HOST", "")
    monkeypatch.setattr(settings, "RESEND_API_KEY", "")
    assert not email_service.email_enabled()
    assert await email_service.send_email("a@b.com", "s", "<p>hi</p>") is False


@pytest.mark.asyncio
async def test_smtp_preferred_when_host_set(monkeypatch):
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.gmail.com")
    monkeypatch.setattr(settings, "RESEND_API_KEY", "resend-key-should-be-ignored")
    sent = []
    monkeypatch.setattr(
        email_service, "_send_via_smtp_sync",
        lambda to, subject, html: sent.append((to, subject)),
    )

    async def _boom(*a):
        raise AssertionError("Resend must not be used when SMTP_HOST is set")
    monkeypatch.setattr(email_service, "_send_via_resend", _boom)

    assert await email_service.send_email("a@b.com", "Reset", "<p>hi</p>") is True
    assert sent == [("a@b.com", "Reset")]


@pytest.mark.asyncio
async def test_smtp_failure_returns_false(monkeypatch):
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.gmail.com")

    def _fail(to, subject, html):
        raise OSError("connection refused")
    monkeypatch.setattr(email_service, "_send_via_smtp_sync", _fail)

    assert await email_service.send_email("a@b.com", "Reset", "<p>hi</p>") is False


@pytest.mark.asyncio
async def test_reset_email_contains_link(monkeypatch):
    captured = {}

    async def _capture(to, subject, html):
        captured.update(to=to, subject=subject, html=html)
        return True
    monkeypatch.setattr(email_service, "send_email", _capture)

    url = "https://bitwavetechnologies.com/reset-password?token=abc123"
    assert await email_service.send_password_reset_email("a@b.com", url) is True
    assert captured["to"] == "a@b.com"
    assert url in captured["html"]
