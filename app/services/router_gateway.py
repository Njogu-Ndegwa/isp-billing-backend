"""Central Router I/O Gateway.

Single entry point for direct MikroTik RouterOS calls. Enforces (centrally):
- no DB session across router I/O (signature accepts only RouterSnapshot, never a Session);
- a global concurrency cap (pinned to the prior default-executor limit);
- the circuit breaker (read from mikrotik_api during Phases 0-2);
- a BACKGROUND-only 30-min offline-skip (derived at snapshot-build time);
- BACKGROUND-only DB-pressure gating.

See docs/superpowers/specs/2026-06-03-router-io-gateway-design.md
"""
from __future__ import annotations

import enum
import logging
import os
import socket
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Generic, Optional, TypeVar

from app.services.router_availability import router_recently_offline

logger = logging.getLogger("router_gateway")

T = TypeVar("T")


class Priority(enum.Enum):
    INTERACTIVE = "interactive"   # customer/admin-facing; never offline-skipped or pressure-gated
    BACKGROUND = "background"     # cleanup/retry/bandwidth; subject to offline-skip + pressure gate


class RouterOpStatus(enum.Enum):
    OK = "ok"
    SKIPPED_OFFLINE = "skipped_offline"
    SKIPPED_CIRCUIT_OPEN = "skipped_circuit_open"
    SKIPPED_DB_PRESSURE = "skipped_db_pressure"
    FAILED_CONNECT = "failed_connect"
    FAILED_OP = "failed_op"
    TIMEOUT = "timeout"


@dataclass(frozen=True)
class RouterSnapshot:
    id: int
    name: str
    ip_address: str
    port: int
    username: str
    password: str
    identity: Optional[str]
    recently_offline: bool

    @classmethod
    def from_router(cls, router, now: Optional[datetime] = None) -> "RouterSnapshot":
        return cls(
            id=router.id,
            name=router.name,
            ip_address=router.ip_address,
            port=router.port,
            username=router.username,
            password=router.password,
            identity=getattr(router, "identity", None),
            recently_offline=router_recently_offline(router, now),
        )


@dataclass(frozen=True)
class RouterOpResult(Generic[T]):
    status: RouterOpStatus
    router_id: Optional[int] = None
    value: Optional[T] = None
    error: Optional[str] = None
    duration_ms: Optional[float] = None

    @property
    def is_ok(self) -> bool:
        return self.status is RouterOpStatus.OK

    @classmethod
    def ok(cls, value, router_id=None, duration_ms=None) -> "RouterOpResult":
        return cls(RouterOpStatus.OK, router_id=router_id, value=value, duration_ms=duration_ms)

    @classmethod
    def skipped(cls, status: RouterOpStatus, router_id=None) -> "RouterOpResult":
        return cls(status, router_id=router_id)

    @classmethod
    def failed(cls, status: RouterOpStatus, error: str, router_id=None, duration_ms=None) -> "RouterOpResult":
        return cls(status, router_id=router_id, error=error, duration_ms=duration_ms)
