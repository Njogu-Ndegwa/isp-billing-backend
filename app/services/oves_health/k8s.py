"""Read-only Kubernetes API client for the OVES EKS clusters.

Authenticates with a long-lived ServiceAccount token (deploy/oves-health/
rbac.yaml grants get/list on workloads, pods/log, nodes, and the Prometheus
service proxy -- nothing that can change the cluster). The cluster CA is pinned
from config, so no kubeconfig or AWS credentials live on the billing box.

Never called with a DB session open (AGENTS.md session discipline).
"""

from __future__ import annotations

import base64
import logging
import ssl
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

PROMETHEUS_PROXY = (
    "/api/v1/namespaces/monitoring/services/"
    "prometheus-operated:9090/proxy/api/v1/query"
)


@dataclass(frozen=True)
class ClusterConfig:
    name: str
    server: str
    token: str
    ca_b64: str

    @property
    def configured(self) -> bool:
        return bool(self.server and self.token)


def _ssl_context(ca_b64: str) -> ssl.SSLContext | bool:
    if not ca_b64:
        return True
    pem = base64.b64decode(ca_b64).decode("ascii")
    ctx = ssl.create_default_context()
    # load_verify_locations(cadata=) accepts PEM text directly; no temp file.
    ctx.load_verify_locations(cadata=pem)
    return ctx


class K8sClient:
    def __init__(self, cfg: ClusterConfig, timeout: float = 15.0):
        self.cfg = cfg
        self._client = httpx.AsyncClient(
            base_url=cfg.server.rstrip("/"),
            headers={"Authorization": f"Bearer {cfg.token}", "Accept": "application/json"},
            verify=_ssl_context(cfg.ca_b64),
            timeout=timeout,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def get_json(self, path: str, params: Optional[dict] = None) -> Any:
        resp = await self._client.get(path, params=params)
        resp.raise_for_status()
        return resp.json()

    async def get_text(self, path: str, params: Optional[dict] = None) -> str:
        resp = await self._client.get(path, params=params, headers={"Accept": "*/*"})
        resp.raise_for_status()
        return resp.text

    # --- typed helpers ----------------------------------------------------

    async def deployments(self, namespace: str) -> list[dict]:
        data = await self.get_json(f"/apis/apps/v1/namespaces/{namespace}/deployments")
        return data.get("items", [])

    async def statefulsets(self, namespace: str) -> list[dict]:
        data = await self.get_json(f"/apis/apps/v1/namespaces/{namespace}/statefulsets")
        return data.get("items", [])

    async def pods(self, namespace: str, label_selector: str = "") -> list[dict]:
        params = {"labelSelector": label_selector} if label_selector else None
        data = await self.get_json(f"/api/v1/namespaces/{namespace}/pods", params)
        return data.get("items", [])

    async def nodes(self) -> list[dict]:
        data = await self.get_json("/api/v1/nodes")
        return data.get("items", [])

    async def pod_log(self, namespace: str, pod: str, container: str,
                      since: datetime, limit_bytes: int = 4_000_000) -> str:
        params = {
            "container": container,
            "timestamps": "true",
            "sinceTime": since.replace(microsecond=0).isoformat() + "Z",
            "limitBytes": str(limit_bytes),
        }
        return await self.get_text(f"/api/v1/namespaces/{namespace}/pods/{pod}/log", params)

    async def prom_query(self, query: str) -> list[dict]:
        data = await self.get_json(PROMETHEUS_PROXY, {"query": query})
        if data.get("status") != "success":
            raise RuntimeError(f"prometheus: {data.get('error') or data.get('status')}")
        return data.get("data", {}).get("result", [])


def cluster_configs(settings) -> list[ClusterConfig]:
    return [
        ClusterConfig("prod", settings.OVES_K8S_PROD_SERVER, settings.OVES_K8S_PROD_TOKEN,
                      settings.OVES_K8S_PROD_CA_B64),
        ClusterConfig("dev", settings.OVES_K8S_DEV_SERVER, settings.OVES_K8S_DEV_TOKEN,
                      settings.OVES_K8S_DEV_CA_B64),
        ClusterConfig("tencent", settings.OVES_K8S_TENCENT_SERVER,
                      settings.OVES_K8S_TENCENT_TOKEN, settings.OVES_K8S_TENCENT_CA_B64),
    ]
