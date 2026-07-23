"""Transactional email via the Resend HTTP API.

Used for password reset links. Deliberately minimal: one provider, one
httpx call, no DB access — callers must follow Database Session Discipline
and invoke this only after their session is committed/closed (it is slow
external I/O).

With RESEND_API_KEY unset the send is skipped and logged so local/dev and
a not-yet-configured production degrade gracefully.
"""

import logging

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

SEND_TIMEOUT_SECONDS = 15


def email_enabled() -> bool:
    return bool(settings.RESEND_API_KEY)


async def send_email(to: str, subject: str, html: str) -> bool:
    """Send one email. Returns True on acceptance by the provider."""
    if not email_enabled():
        logger.warning(
            "Email sending disabled (RESEND_API_KEY unset); dropped '%s' to %s",
            subject, to,
        )
        return False
    try:
        async with httpx.AsyncClient(timeout=SEND_TIMEOUT_SECONDS) as client:
            resp = await client.post(
                f"{settings.RESEND_BASE_URL}/emails",
                headers={"Authorization": f"Bearer {settings.RESEND_API_KEY}"},
                json={
                    "from": settings.EMAIL_FROM,
                    "to": [to],
                    "subject": subject,
                    "html": html,
                },
            )
        if resp.status_code in (200, 201):
            return True
        logger.error(
            "Email send failed (%s) to %s: %s",
            resp.status_code, to, resp.text[:300],
        )
        return False
    except Exception as exc:
        logger.error("Email send error to %s: %s", to, exc)
        return False


async def send_password_reset_email(to: str, reset_url: str) -> bool:
    ttl_minutes = settings.PASSWORD_RESET_TOKEN_TTL_MINUTES
    subject = "Reset your Bitwave password"
    html = f"""\
<div style="font-family: Arial, Helvetica, sans-serif; max-width: 480px; margin: 0 auto; padding: 24px; color: #1a1a1a;">
  <h2 style="margin: 0 0 8px;">Reset your password</h2>
  <p style="margin: 0 0 16px; line-height: 1.5;">
    We received a request to reset the password for your Bitwave
    ISP Billing account ({to}).
  </p>
  <p style="margin: 0 0 24px;">
    <a href="{reset_url}"
       style="display: inline-block; background: #f59e0b; color: #ffffff; text-decoration: none; padding: 12px 24px; border-radius: 8px; font-weight: bold;">
      Choose a new password
    </a>
  </p>
  <p style="margin: 0 0 8px; line-height: 1.5; color: #555555; font-size: 14px;">
    This link expires in {ttl_minutes} minutes and can be used once.
    If the button doesn't work, copy this URL into your browser:
  </p>
  <p style="margin: 0 0 16px; word-break: break-all; font-size: 13px;">
    <a href="{reset_url}">{reset_url}</a>
  </p>
  <p style="margin: 0; line-height: 1.5; color: #555555; font-size: 14px;">
    If you didn't request this, you can safely ignore this email —
    your password will not change.
  </p>
  <p style="margin: 24px 0 0; color: #999999; font-size: 12px;">
    Bitwave Technologies · ISP Billing &amp; Network Management
  </p>
</div>
"""
    return await send_email(to, subject, html)
