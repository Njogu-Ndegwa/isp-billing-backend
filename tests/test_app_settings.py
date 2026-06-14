"""Tests for the app-settings KV store and compensation-limit DB override.

TDD order:
  1. get_int_setting returns default when key unset
  2. get_int_setting returns stored int after set_setting
  3. get_int_setting returns default when stored value is non-numeric
  4. get_compensation_daily_limit returns config default when unset
  5. get_compensation_daily_limit returns DB override after set_setting
  6. DB override is honoured by generate_vouchers (limit=2, third rejected)
"""

import pytest

from app.config import settings
from tests.factories import make_plan, make_reseller

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# get_int_setting helpers
# ---------------------------------------------------------------------------

async def test_get_int_setting_returns_default_when_key_unset(db):
    from app.services.app_settings import get_int_setting

    result = await get_int_setting(db, "nonexistent_key", 42)
    assert result == 42


async def test_get_int_setting_returns_stored_int_after_set_setting(db):
    from app.services.app_settings import get_int_setting, set_setting

    await set_setting(db, "test_numeric_key", 7)
    result = await get_int_setting(db, "test_numeric_key", 99)
    assert result == 7


async def test_get_int_setting_returns_default_for_non_numeric_value(db):
    from app.services.app_settings import get_int_setting, set_setting

    await set_setting(db, "bad_value_key", "not-a-number")
    result = await get_int_setting(db, "bad_value_key", 55)
    assert result == 55


# ---------------------------------------------------------------------------
# get_compensation_daily_limit
# ---------------------------------------------------------------------------

async def test_get_compensation_daily_limit_returns_config_default_when_unset(db):
    from app.services.voucher_service import (
        COMPENSATION_DAILY_LIMIT_KEY,
        get_compensation_daily_limit,
    )
    from app.services.app_settings import get_setting

    # Confirm no DB row exists for this key
    raw = await get_setting(db, COMPENSATION_DAILY_LIMIT_KEY)
    assert raw is None

    limit = await get_compensation_daily_limit(db)
    assert limit == settings.COMPENSATION_DAILY_LIMIT


async def test_get_compensation_daily_limit_returns_db_override(db):
    from app.services.app_settings import set_setting
    from app.services.voucher_service import (
        COMPENSATION_DAILY_LIMIT_KEY,
        get_compensation_daily_limit,
    )

    await set_setting(db, COMPENSATION_DAILY_LIMIT_KEY, 3)
    limit = await get_compensation_daily_limit(db)
    assert limit == 3


# ---------------------------------------------------------------------------
# DB override honoured by generate_vouchers
# ---------------------------------------------------------------------------

async def test_db_override_is_honoured_by_generate_vouchers(db):
    """After setting the DB limit to 2, 2 comp vouchers succeed but a 3rd is rejected."""
    from app.db.models import VoucherType
    from app.services.app_settings import set_setting
    from app.services.voucher_service import (
        COMPENSATION_DAILY_LIMIT_KEY,
        generate_vouchers,
    )

    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)

    # Override daily limit to 2 in DB
    await set_setting(db, COMPENSATION_DAILY_LIMIT_KEY, 2)

    # First 2 should succeed
    first = await generate_vouchers(
        db=db,
        plan_id=plan.id,
        user_id=reseller.id,
        quantity=2,
        voucher_type=VoucherType.COMPENSATION,
    )
    assert "error" not in first
    assert first["quantity"] == 2

    # Third should be rejected
    third = await generate_vouchers(
        db=db,
        plan_id=plan.id,
        user_id=reseller.id,
        quantity=1,
        voucher_type=VoucherType.COMPENSATION,
    )
    assert "error" in third
    assert "compensation" in third["error"].lower()
