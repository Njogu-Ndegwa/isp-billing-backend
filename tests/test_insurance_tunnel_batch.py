import asyncio

from app.services import insurance_tunnel_batch as batch
from app.services.insurance_tunnel_batch import get_latest_insurance_tunnel_items_by_router


def test_latest_insurance_tunnel_items_by_router_uses_newest_job_item():
    async def run():
        async with batch._jobs_lock:
            batch._jobs.clear()
            batch._active_job_id = None
            batch._jobs["old"] = {
                "job_id": "old",
                "status": "completed",
                "created_at": "2026-06-14T00:00:00Z",
                "updated_at": "2026-06-14T00:05:00Z",
                "items": [{"router_id": 112, "status": "failed", "error": "old failure"}],
            }
            batch._jobs["new"] = {
                "job_id": "new",
                "status": "completed",
                "created_at": "2026-06-15T00:00:00Z",
                "updated_at": "2026-06-15T00:05:00Z",
                "items": [{"router_id": 112, "status": "verified", "finished_at": "2026-06-15T00:04:00Z"}],
            }

        try:
            items = await get_latest_insurance_tunnel_items_by_router([112])
        finally:
            async with batch._jobs_lock:
                batch._jobs.clear()
                batch._active_job_id = None

        assert items[112]["status"] == "verified"
        assert items[112]["job_id"] == "new"
        assert items[112]["job_updated_at"] == "2026-06-15T00:05:00Z"

    asyncio.run(run())
