"""
Live smoke-test against the MTN MoMo sandbox.

Uses the service functions directly (no database, no FastAPI) so we can be sure
the HTTP wire-level calls are correct before wiring anything up end-to-end.

Run:
    python scripts/test_mtn_momo_live.py
"""

from __future__ import annotations

import asyncio
import sys
import os
import uuid
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.mtn_momo import (
    get_access_token,
    initiate_request_to_pay,
    check_request_to_pay_status,
    _format_amount,
    normalize_msisdn,
)

# Credentials provided by the user for the sandbox.
API_USER = "64f8c775-6dff-45c0-93e0-39a9cd78df8b"
API_KEY = "3eccb4f68c3241caad25b59823b7ac86"
PRIMARY_KEY = "af8ced583a5849f5bcb7aa39f008ce4e"
BASE_URL = "https://sandbox.momodeveloper.mtn.com"
TARGET_ENV = "sandbox"
CURRENCY = "EUR"


async def run_scenario(msisdn: str, expected_final: str) -> bool:
    """Initiate a RequestToPay against ``msisdn`` and poll until final."""
    print(f"\n--- Scenario: MSISDN={msisdn} (expect {expected_final}) ---")

    reference_id = str(uuid.uuid4())
    external_id = f"SMOKE-{int(time.time())}"
    try:
        await initiate_request_to_pay(
            reference_id=reference_id,
            amount=1000,
            currency=CURRENCY,
            phone=msisdn,
            external_id=external_id,
            payer_message="Smoke test payment",
            payee_note="Smoke test",
            target_environment=TARGET_ENV,
            base_url=BASE_URL,
            api_user=API_USER,
            api_key=API_KEY,
            subscription_key=PRIMARY_KEY,
            callback_url=None,
        )
        print(f"  RequestToPay accepted, reference_id={reference_id}")
    except Exception as exc:
        print(f"  ! RequestToPay failed: {exc!r}")
        return False

    # Sandbox takes up to ~60s to auto-advance test MSISDNs.
    for attempt in range(1, 41):
        try:
            data = await check_request_to_pay_status(
                reference_id,
                target_environment=TARGET_ENV,
                base_url=BASE_URL,
                api_user=API_USER,
                api_key=API_KEY,
                subscription_key=PRIMARY_KEY,
            )
        except Exception as exc:
            print(f"  ! Status call failed on attempt {attempt}: {exc!r}")
            return False
        status = data.get("status")
        if status in ("SUCCESSFUL", "FAILED"):
            print(f"  attempt {attempt}: status={status} (raw={data})")
            return status == expected_final
        if attempt == 1 or attempt % 5 == 0:
            print(f"  attempt {attempt}: status={status}")
        await asyncio.sleep(3)

    print("  ! Never reached a final state within the timeout")
    return False


async def main() -> int:
    print("=== Helpers ===")
    assert _format_amount(1000) == "1000"
    assert _format_amount(1000.0) == "1000"
    assert _format_amount(1000.5) == "1000.50"
    assert normalize_msisdn("+46733123454") == "46733123454"
    print("  OK")

    print("\n=== Token ===")
    token = await get_access_token(
        api_user=API_USER,
        api_key=API_KEY,
        subscription_key=PRIMARY_KEY,
        base_url=BASE_URL,
    )
    print(f"  acquired (prefix={token[:16]}..., len={len(token)})")
    token2 = await get_access_token(
        api_user=API_USER,
        api_key=API_KEY,
        subscription_key=PRIMARY_KEY,
        base_url=BASE_URL,
    )
    assert token2 == token, "cached token should be reused"
    print("  cache reuse OK")

    # Run scenarios sequentially so sandbox rate-limits aren't hit.
    success_ok = await run_scenario("46733123454", "SUCCESSFUL")
    failed_ok = await run_scenario("46733123453", "FAILED")

    print("\n=== Summary ===")
    print(f"  SUCCESSFUL scenario: {'PASS' if success_ok else 'FAIL'}")
    print(f"  FAILED scenario:     {'PASS' if failed_ok else 'FAIL'}")
    return 0 if (success_ok and failed_ok) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
