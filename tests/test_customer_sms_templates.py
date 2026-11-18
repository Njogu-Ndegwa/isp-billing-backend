from datetime import datetime

import pytest

from app.services import customer_sms_templates


def test_template_validation_names_the_bad_placeholder():
    error = customer_sms_templates.validate_template("expiry", "Hi {name}, paid {amount}")
    assert error is not None and "{amount}" in error
    assert customer_sms_templates.validate_template("payment_receipt", "Paid {amount}") is None
    assert customer_sms_templates.validate_template("welcome", "   ") is not None
    assert customer_sms_templates.validate_template("welcome", "x" * 481) is not None


def test_receipt_without_reference_drops_the_ref_clause_and_plan_speed():
    context = customer_sms_templates.build_context(
        reseller=type("R", (), {"business_name": None, "organization_name": "ISP"})(),
        tz_name="Africa/Nairobi",
        plan_name="25MBPS@3500",
        expiry=datetime(2030, 1, 1, 9, 30),
        amount="KES 50",
    )
    assert customer_sms_templates.render("payment_receipt", context) == (
        "Payment of KES 50 received. Your internet is active until 01 Jan, 12:30. - ISP"
    )


@pytest.mark.parametrize(
    "raw,expected",
    [("Jane Wanjiku", "Jane"), ("254712345678", "Customer"),
     ("AA:BB:CC:DD:EE:FF", "Customer"), (None, "Customer"),
     ("Guest 5364", "Customer"), ("Device 4A:3F:F1", "Customer")],
)
def test_friendly_name(raw, expected):
    assert customer_sms_templates.friendly_name(raw) == expected


def test_default_welcome_fits_one_sms_for_a_typical_reseller():
    context = customer_sms_templates.build_context(
        reseller=type("R", (), {"business_name": "Mwal-Networks Technology", "organization_name": ""})(),
        tz_name="Africa/Nairobi",
        account_number="44353225",
        paybill="4159825",
        username="pppoe_254712345678",
        password="yr5bhDxjcclK",
    )
    assert len(customer_sms_templates.render("welcome", context)) <= 160


_RESELLER = type("R", (), {"business_name": "Elgy Link Connect", "organization_name": ""})()


def _context(**overrides):
    return customer_sms_templates.build_context(
        reseller=_RESELLER, tz_name="Africa/Nairobi", **overrides
    )


def _saved_default(event):
    return {event: customer_sms_templates.DEFAULT_TEMPLATE_TEXT[event]}


def test_custom_reminder_with_paybill_renders_every_field():
    text = customer_sms_templates.render(
        "reminder",
        _context(paybill="4159825", account_number="70985932"),
        _saved_default("reminder"),
    )
    assert text == (
        "Reminder: Your internet expires soon. Pay via M-Pesa Paybill 4159825, "
        "Account 70985932 to avoid disconnection. - Elgy Link Connect"
    )


def test_custom_reminder_without_paybill_drops_the_payment_sentence():
    """Reseller 638 (direct settlement, no C2B) got "Paybill , Account ..." (18 Nov)."""
    context = _context(paybill=None, account_number="70985932")
    custom = customer_sms_templates.render("reminder", context, _saved_default("reminder"))
    assert custom == (
        "Reminder: Your internet expires soon. Please renew to avoid "
        "disconnection. - Elgy Link Connect"
    )
    assert "Paybill" not in custom


def test_custom_expiry_and_welcome_without_paybill_drop_the_payment_sentence():
    context = _context(
        paybill=None, account_number="70985932", username="jane", password="pw1",
    )
    assert customer_sms_templates.render("expiry", context, _saved_default("expiry")) == (
        "Your internet has expired. Please renew to restore service. - Elgy Link Connect"
    )
    assert customer_sms_templates.render("welcome", context, _saved_default("welcome")) == (
        "Welcome to Elgy Link Connect! Username: jane Password: pw1."
    )


def test_custom_receipt_without_reference_drops_the_ref_sentence():
    context = _context(amount="KES 50", expiry=datetime(2030, 1, 1, 9, 30))
    assert customer_sms_templates.render(
        "payment_receipt", context, _saved_default("payment_receipt")
    ) == "Payment of KES 50 received. Your internet is active until 01 Jan, 12:30. - Elgy Link Connect"


def test_custom_template_keeps_reseller_wording_and_line_breaks():
    body = "Hi {name}!\nPay to Paybill {paybill} acc {account}.\nCall {support_phone}"
    context = _context(customer_name="Jane", account_number="1", support_phone="0712")
    assert customer_sms_templates.render("welcome", context, {"welcome": body}) == (
        "Hi Jane!\nCall 0712"
    )
    assert customer_sms_templates.render("expiry", context, {"expiry": body}) == (
        "Hi Jane!\nPlease renew to restore service.\nCall 0712"
    )


def test_custom_template_with_only_missing_fields_falls_back_to_default():
    context = _context(amount="KES 50")
    text = customer_sms_templates.render(
        "payment_receipt", context, {"payment_receipt": "Ref {reference}"}
    )
    assert text == customer_sms_templates.default_receipt(context)
