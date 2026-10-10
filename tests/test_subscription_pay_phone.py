import pytest

from app.api.subscription_routes import normalize_kenyan_msisdn


@pytest.mark.parametrize("raw", [
    "+2540746545223", "2540746545223",  # country code AND leading 0 (2026-10-10, reseller 567)
    "0746545223", "746545223", "+254746545223", "254746545223", "0746 545 223", "0746-545-223",
])
def test_normalizes_to_daraja_format(raw):
    assert normalize_kenyan_msisdn(raw) == "254746545223"


def test_accepts_01_prefix_numbers():
    assert normalize_kenyan_msisdn("0110123456") == "254110123456"


@pytest.mark.parametrize("raw", ["25746545223", "12345", "abc", "", None, "0746545", "+1 555 123 4567"])
def test_rejects_numbers_mpesa_cannot_take(raw):
    assert normalize_kenyan_msisdn(raw) is None
