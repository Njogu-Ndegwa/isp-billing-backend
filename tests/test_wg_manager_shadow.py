import importlib.util
from pathlib import Path

import pytest
from fastapi import HTTPException


def load_wg_manager_module():
    path = Path("wg-manager/main.py")
    spec = importlib.util.spec_from_file_location("wg_manager_main_for_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_wg_manager_shadow_mode_blocks_peer_mutations(monkeypatch):
    module = load_wg_manager_module()
    monkeypatch.setattr(module, "SHADOW_MODE", True)

    def subprocess_must_not_run(*_args, **_kwargs):
        pytest.fail("shadow manager attempted to run wg")

    monkeypatch.setattr(module.subprocess, "run", subprocess_must_not_run)

    with pytest.raises(HTTPException) as exc:
        module.add_peer(
            module.AddPeerRequest(public_key="test-key", allowed_ips="10.0.0.2/32")
        )

    assert exc.value.status_code == 503


def test_wg_manager_health_reports_shadow_mode(monkeypatch):
    module = load_wg_manager_module()
    monkeypatch.setattr(module, "SHADOW_MODE", True)
    monkeypatch.setattr(module, "_wireguard_health", lambda: {"available": True})
    monkeypatch.setattr(
        module,
        "_l2tp_health",
        lambda: {"required": False, "available": False},
    )
    monkeypatch.setattr(
        module,
        "_ipsec_connmark_health",
        lambda: {"healthy": True},
    )

    assert module.health()["runtime_mode"] == "shadow"
