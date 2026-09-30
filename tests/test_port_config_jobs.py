"""Port-mode saves that outlive Cloudflare's 100 s origin timeout (2026-09-29)."""
import asyncio

import pytest
from fastapi import HTTPException

from app.api import router_operations as ro


@pytest.fixture(autouse=True)
def _clean_jobs(monkeypatch):
    ro._port_config_jobs.clear()
    monkeypatch.setattr(ro, "_PORT_CONFIG_INLINE_WAIT_SECONDS", 0.05)
    yield
    ro._port_config_jobs.clear()


def test_fast_change_answers_inline():
    async def apply():
        return {"success": True}

    assert asyncio.run(ro._run_port_config(1, "dual", apply)) == {"success": True}


def test_slow_change_returns_202_and_finishes_in_background():
    async def scenario():
        async def apply():
            await asyncio.sleep(0.2)
            return {"success": True, "dual_ports": ["ether4"]}

        response = await ro._run_port_config(7, "dual", apply)
        assert response.status_code == 202
        job_id = next(iter(ro._port_config_jobs))
        assert ro._port_config_jobs[job_id]["status"] == "applying"

        # a second save for the same router is refused instead of stacking
        with pytest.raises(HTTPException) as exc:
            await ro._run_port_config(7, "plain", apply)
        assert exc.value.status_code == 409

        await asyncio.sleep(0.3)
        job = ro._public_port_config_job(ro._port_config_jobs[job_id])
        assert job["status"] == "done"
        assert job["result"]["dual_ports"] == ["ether4"]
        assert "_task" not in job

    asyncio.run(scenario())


def test_background_failure_is_recorded():
    async def scenario():
        async def apply():
            await asyncio.sleep(0.2)
            raise HTTPException(status_code=500, detail={"message": "router said no"})

        await ro._run_port_config(9, "pppoe", apply)
        await asyncio.sleep(0.3)
        job = next(iter(ro._port_config_jobs.values()))
        assert job["status"] == "failed"
        assert job["status_code"] == 500
        assert job["error"] == {"message": "router said no"}

    asyncio.run(scenario())
