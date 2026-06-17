import asyncio

from app.services import insurance_tunnel_batch as batch
from app.services.insurance_tunnel_batch import (
    InsuranceTunnelCandidate,
    RouterSnapshot,
    get_latest_insurance_tunnel_items_by_router,
)


def make_candidate(
    router_id: int,
    *,
    status: str = "online",
    owner_role: str = "reseller",
    owner_subscription_status: str = "active",
    has_known_backup: bool = False,
    token_vpn_type: str | None = None,
):
    return InsuranceTunnelCandidate(
        router=RouterSnapshot(
            id=router_id,
            name=f"Router-{router_id}",
            ip_address=f"10.0.0.{router_id}",
            username="admin",
            password="secret",
            port=8728,
            recently_offline=status == "offline",
            status=status,
        ),
        backup_ip=f"10.250.0.{router_id}",
        backup_ip_error=None,
        token_vpn_type=token_vpn_type,
        l2tp_username=None,
        l2tp_password=None,
        owner_user_id=router_id,
        owner_role=owner_role,
        owner_subscription_status=owner_subscription_status,
        has_known_backup=has_known_backup,
        skip_reason=None,
    )


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


def test_online_missing_backup_selection_filters_before_limit():
    candidates = [
        make_candidate(1, status="offline"),
        make_candidate(2, has_known_backup=True),
        make_candidate(3),
        make_candidate(4),
    ]

    selected = batch._select_candidates(
        candidates,
        selection_mode="online_missing_backup",
        tunnel_type=None,
        limit=1,
    )

    assert [candidate.router.id for candidate in selected] == [3]


def test_paid_reseller_online_missing_backup_selection_is_active_reseller_only():
    candidates = [
        make_candidate(1, owner_role="admin"),
        make_candidate(2, owner_subscription_status="trial"),
        make_candidate(3, owner_subscription_status="suspended"),
        make_candidate(4, owner_subscription_status="active"),
        make_candidate(5, owner_subscription_status="active", has_known_backup=True),
    ]

    selected = batch._select_candidates(
        candidates,
        selection_mode="paid_reseller_online_missing_backup",
        tunnel_type=None,
        limit=None,
    )

    assert [candidate.router.id for candidate in selected] == [4]


def test_tunnel_type_filter_uses_planned_token_type():
    candidates = [
        make_candidate(1, token_vpn_type="wireguard"),
        make_candidate(2, token_vpn_type="l2tp"),
        make_candidate(3, token_vpn_type=None),
    ]

    selected = batch._select_candidates(
        candidates,
        selection_mode="all",
        tunnel_type="auto",
        limit=None,
    )

    assert [candidate.router.id for candidate in selected] == [3]


def test_verification_error_includes_ping_and_tcp_details():
    error = batch._verification_error({
        "ip": "10.250.0.85",
        "port": 8728,
        "ping_success": False,
        "ping_stderr": "3 packets transmitted, 0 received",
        "tcp_success": False,
        "tcp_error": "timed out",
    })

    assert "ping=failed" in error
    assert "tcp=failed" in error
    assert "tcp_error=timed out" in error
    assert "3 packets transmitted" in error


def test_verify_candidate_retries_until_backup_reachability_passes(monkeypatch):
    candidate = make_candidate(82)
    calls = []

    async def fake_verify(_backup_ip, port=8728):
        calls.append((candidate.backup_ip, port))
        if len(calls) == 1:
            return {
                "ip": candidate.backup_ip,
                "port": port,
                "ping_success": False,
                "tcp_success": False,
                "tcp_error": "No route to host",
            }
        return {
            "ip": candidate.backup_ip,
            "port": port,
            "ping_success": True,
            "tcp_success": True,
            "tcp_error": None,
        }

    async def no_sleep(_seconds):
        return None

    async def run():
        async with batch._jobs_lock:
            batch._jobs.clear()
            batch._active_job_id = None
            batch._jobs["job"] = {
                "job_id": "job",
                "status": "running",
                "created_at": "2026-06-17T00:00:00Z",
                "updated_at": "2026-06-17T00:00:00Z",
                "items": [batch._item_from_candidate(candidate)],
            }

        try:
            await batch._verify_candidate("job", candidate, {}, {"actions": []})
            item = (await batch.get_insurance_tunnel_batch("job"))["items"][0]
        finally:
            async with batch._jobs_lock:
                batch._jobs.clear()
                batch._active_job_id = None

        assert item["status"] == "verified"
        assert item["error"] is None
        assert len(item["verification_attempts"]) == 2
        assert len(calls) == 2

    monkeypatch.setattr(batch, "verify_insurance_router", fake_verify)
    monkeypatch.setattr(batch.asyncio, "sleep", no_sleep)

    asyncio.run(run())
