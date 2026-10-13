"""Minimal SigV4-signed, read-only AWS calls for health checks, without
pulling boto3 into the image.

AWS is used for the MongoDB EC2 members only: CPUCreditBalance is the metric
that actually predicts the rs0 elections (10.0.1.19 is a t2.large that sits at
zero credits, misses heartbeats for >10 s and gets voted out -- see the
accessing-oves-cluster runbook), plus CPU and the EC2 status checks.

Never called with a DB session open.
"""

from __future__ import annotations

import hashlib
import hmac
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import quote

import httpx


# ---------------------------------------------------------------------------
# AWS SigV4 (query protocol, GET)
# ---------------------------------------------------------------------------

def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def sigv4_headers(method: str, host: str, region: str, service: str, query: str,
                  access_key: str, secret_key: str, now: Optional[datetime] = None,
                  payload: bytes = b"") -> dict[str, str]:
    now = now or datetime.utcnow()
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(payload).hexdigest()
    canonical_headers = f"host:{host}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-date"
    canonical = "\n".join([method, "/", query, canonical_headers, signed_headers, payload_hash])
    scope = f"{date}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope,
                         hashlib.sha256(canonical.encode()).hexdigest()])
    k = _hmac(("AWS4" + secret_key).encode(), date)
    k = _hmac(k, region)
    k = _hmac(k, service)
    k = _hmac(k, "aws4_request")
    signature = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    return {
        "x-amz-date": amz_date,
        "Authorization": (f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
                          f"SignedHeaders={signed_headers}, Signature={signature}"),
    }


def canonical_query(params: dict[str, str]) -> str:
    return "&".join(
        f"{quote(k, safe='-_.~')}={quote(str(v), safe='-_.~')}"
        for k, v in sorted(params.items())
    )


def _strip_ns(root: ET.Element) -> ET.Element:
    for el in root.iter():
        if "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return root


class AwsReadOnly:
    def __init__(self, access_key: str, secret_key: str, region: str, timeout: float = 15.0):
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self._client = httpx.AsyncClient(timeout=timeout)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _call(self, service: str, params: dict[str, str]) -> ET.Element:
        host = f"{service}.{self.region}.amazonaws.com"
        query = canonical_query(params)
        headers = sigv4_headers("GET", host, self.region, service, query,
                                self.access_key, self.secret_key)
        resp = await self._client.get(f"https://{host}/?{query}", headers=headers)
        if resp.status_code >= 400:
            raise RuntimeError(f"aws {service} {params.get('Action')}: HTTP {resp.status_code}")
        return _strip_ns(ET.fromstring(resp.text))

    async def metric_latest(self, instance_id: str, metric: str, stat: str = "Average",
                            minutes: int = 20, period: int = 300) -> Optional[float]:
        end = datetime.utcnow()
        start = end - timedelta(minutes=minutes)
        root = await self._call("monitoring", {
            "Action": "GetMetricStatistics", "Version": "2010-08-01",
            "Namespace": "AWS/EC2", "MetricName": metric,
            "Dimensions.member.1.Name": "InstanceId",
            "Dimensions.member.1.Value": instance_id,
            "StartTime": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "EndTime": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "Period": str(period), "Statistics.member.1": stat,
        })
        points = []
        for dp in root.iter("member"):
            ts, val = dp.findtext("Timestamp"), dp.findtext(stat)
            if ts and val is not None:
                points.append((ts, float(val)))
        if not points:
            return None
        return round(sorted(points)[-1][1], 2)

    async def instance_status(self, instance_ids: list[str]) -> dict[str, dict]:
        params = {"Action": "DescribeInstanceStatus", "Version": "2016-11-15",
                  "IncludeAllInstances": "true"}
        for i, iid in enumerate(instance_ids, start=1):
            params[f"InstanceId.{i}"] = iid
        root = await self._call("ec2", params)
        out = {}
        for item in root.iter("item"):
            iid = item.findtext("instanceId")
            if not iid:
                continue
            out[iid] = {
                "state": item.findtext("instanceState/name"),
                "system_status": item.findtext("systemStatus/status"),
                "instance_status": item.findtext("instanceStatus/status"),
                "events": [e.findtext("description") for e in item.findall("eventsSet/item")],
            }
        return out

    async def credit_modes(self, instance_ids: list[str]) -> dict[str, str]:
        """instance id -> "standard" | "unlimited" (burstable instances only)."""
        params = {"Action": "DescribeInstanceCreditSpecifications", "Version": "2016-11-15"}
        for i, iid in enumerate(instance_ids, start=1):
            params[f"InstanceId.{i}"] = iid
        root = await self._call("ec2", params)
        return {item.findtext("instanceId"): item.findtext("cpuCredits")
                for item in root.iter("item") if item.findtext("instanceId")}
