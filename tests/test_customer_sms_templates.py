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
     ("AA:BB:CC:DD:EE:FF", "Customer"), (None, "Customer")],
)
def test_friendly_name(raw, expected):
    assert customer_sms_templates.friendly_name(raw) == expected
