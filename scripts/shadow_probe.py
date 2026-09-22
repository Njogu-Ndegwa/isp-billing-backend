"""Prove that a restored shadow stack is useful but cannot become a writer.

Run this inside the ``shadow-web`` container after it becomes healthy.  The
probe uses only the container-local API and its configured database connection;
it never contacts a router or external provider and never prints credentials.
"""

from __future__ import annotations

import asyncio
import json
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from sqlalchemy import text

from app.db.database import async_engine


BASE_URL = "http://127.0.0.1:8000"


def api_request(path: str, *, method: str = "GET", payload: dict | None = None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(
        f"{BASE_URL}{path}",
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urlopen(request, timeout=10) as response:
            body = json.loads(response.read().decode("utf-8"))
            headers = {key.lower(): value for key, value in response.headers.items()}
            return response.status, headers, body
    except HTTPError as exc:
        body = json.loads(exc.read().decode("utf-8"))
        headers = {key.lower(): value for key, value in exc.headers.items()}
        return exc.code, headers, body


async def database_read_only_probe() -> dict[str, object]:
    async with async_engine.connect() as connection:
        setting = (await connection.execute(text("SHOW default_transaction_read_only"))).scalar_one()
        write_blocked = False
        try:
            # Zero matching rows means this statement cannot alter data even if
            # the read-only connection backstop was accidentally absent.
            await connection.execute(text("UPDATE users SET id = id WHERE FALSE"))
        except Exception as exc:
            if "read-only transaction" not in str(exc).lower():
                raise
            write_blocked = True
        return {
            "default_transaction_read_only": setting,
            "write_statement_blocked": write_blocked,
        }


def main() -> None:
    health_status, health_headers, health_body = api_request("/health")
    post_status, post_headers, post_body = api_request(
        "/api/payments", method="POST", payload={}
    )
    login_status, login_headers, _ = api_request(
        "/api/auth/login",
        method="POST",
        payload={
            "email": "shadow-probe-invalid@example.invalid",
            "password": "invalid",
        },
    )
    database = asyncio.run(database_read_only_probe())

    result = {
        "health_status": health_status,
        "health_runtime_mode": health_body.get("runtime_mode"),
        "health_header_mode": health_headers.get("x-isp-runtime-mode"),
        "unsafe_post_status": post_status,
        "unsafe_post_code": post_body.get("code"),
        "unsafe_post_header_mode": post_headers.get("x-isp-runtime-mode"),
        "invalid_login_status": login_status,
        "invalid_login_header_mode": login_headers.get("x-isp-runtime-mode"),
        "database": database,
    }
    print(json.dumps(result, sort_keys=True))

    expected = (
        health_status == 200
        and health_body.get("runtime_mode") == "shadow"
        and health_headers.get("x-isp-runtime-mode") == "shadow"
        and post_status == 503
        and post_body.get("code") == "shadow_mode_blocked"
        and post_headers.get("x-isp-runtime-mode") == "shadow"
        and login_status == 401
        and login_headers.get("x-isp-runtime-mode") == "shadow"
        and database["default_transaction_read_only"] == "on"
        and database["write_statement_blocked"] is True
    )
    if not expected:
        raise SystemExit("shadow safety probe failed")


if __name__ == "__main__":
    main()
