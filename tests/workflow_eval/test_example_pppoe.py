"""Example scenario (the one that started this): registering a PPPoE customer.

Copy this shape for new scenarios: state, question(s), checks.
"""
import pytest

from tests.assistant_eval_kit import KEY, ask, build, customer, evaluate, picker_only, plan, report, use_real_model
from tests.test_assistant import client, owner  # noqa: F401  (fixtures)

pytestmark = pytest.mark.skipif(not KEY, reason="needs ASSISTANT_EVAL_KEY (a real model key)")


@pytest.mark.asyncio
async def test_register_pppoe_customer_offers_only_pppoe_plans(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"],
                plans=[plan("Daily 50", 50), plan("Weekly 300", 300, days=7),
                       plan("Home 10M", 2000, days=30, kind="pppoe", speed="10M/10M"),
                       plan("Home 20M", 3000, days=30, kind="pppoe", speed="20M/20M")])
    use_real_model(monkeypatch)
    row = await ask(client, token, "Register a new PPPoE customer John Kamau 0712345678", monkeypatch)
    problems = evaluate(row, [picker_only("plan_id", ["Home 10M", "Home 20M"], forbidden=["Daily 50", "Weekly 300"])])
    report("pppoe-customer/only-pppoe-plans", row, problems)
    assert not problems, problems
