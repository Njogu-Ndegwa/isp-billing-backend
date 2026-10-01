from datetime import datetime

import pytest

from app.services import customer_sms_templates


def test_template_validation_names_the_bad_placeholder():
    error = customer_sms_templates.validate_template("expiry", "Hi {name}, paid {amount}")
    assert error is not None and "{amount}" in error
    assert customer_sms_templates.validate_template("payment_receipt", "Paid {amount}") is None
    assert customer_sms_templates.validate_template("welcome", "   ") is not None
    assert customer_sms_templates.validate_template("welcome", "x" * 481) is not None


def test_receipt_without_reference_drops_the_ref_clause():
    context = customer_sms_templates.build_context(
        reseller=type("R", (), {"business_name": None, "organization_name": "ISP"})(),
        tz_name="Africa/Nairobi",
        plan_name="Daily",
        expiry=datetime(2030, 1, 1, 9, 30),
        amount="KES 50",
    )
    assert customer_sms_templates.render("payment_receipt", context) == (
        "Payment of KES 50 received. Your Daily is active until 01 Jan, 12:30. - ISP"
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
