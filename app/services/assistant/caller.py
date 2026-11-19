"""Who is asking: the identity and authority carried by the request's token.

The middlewares in main.py (View-as guard, staff guard) have already checked
the token's session state by the time an assistant route runs. This module
only reads the verified claims, plus one short DB read for the staff member's
current permissions so the API index matches what the staff guard will allow.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from fastapi import HTTPException, Request
from sqlalchemy import select

from app.services.impersonation import client_ip, impersonation_claims
from app.services.staff_access import bearer_claims


@dataclass(frozen=True)
class Caller:
    user_id: int
    role: str                      # "admin" | "reseller"
    authorization: str             # the exact "Bearer ..." header, reused for every call
    organization: str = ""
    staff_id: Optional[int] = None
    staff_name: str = ""
    staff_permissions: frozenset = field(default_factory=frozenset)
    staff_is_account_admin: bool = False
    viewer_sid: Optional[int] = None   # View-as session (read-only)
    viewer_admin_id: Optional[int] = None  # the admin doing the View-as
    ip: Optional[str] = None
    user_agent: str = ""

    @property
    def is_admin(self) -> bool:
        return self.role == "admin" and self.viewer_sid is None

    @property
    def read_only(self) -> bool:
        return self.viewer_sid is not None

    @property
    def usage_owner(self) -> tuple:
        """(user_id, staff_id) that a question's cost is counted against.

        View-as questions are the viewing admin's, not the reseller's: an admin
        testing or helping must not show up as the reseller using the chat.
        """
        if self.viewer_sid is not None and self.viewer_admin_id is not None:
            return self.viewer_admin_id, None
        return self.user_id, self.staff_id

    @property
    def owner_key(self) -> tuple:
        return (self.user_id, self.staff_id, self.viewer_sid)

    def describe(self) -> str:
        if self.viewer_sid is not None:
            return (f"a Bitwave platform admin viewing the reseller account "
                    f"\"{self.organization}\" in read-only View-as mode")
        if self.role == "admin":
            return "a Bitwave platform admin (full access to every reseller and admin tool)"
        if self.staff_id is not None:
            if self.staff_is_account_admin:
                return (f"{self.staff_name or 'a staff member'}, a co-admin of the reseller account "
                        f"\"{self.organization}\" (same authority as the owner, no platform-admin tools)")
            perms = ", ".join(sorted(self.staff_permissions)) or "none"
            return (f"{self.staff_name or 'a staff member'}, staff in the reseller account "
                    f"\"{self.organization}\" with these permissions only: {perms}")
        return f"the owner of the reseller (ISP) account \"{self.organization}\""


async def caller_from_request(request: Request) -> Caller:
    """The verified caller, or 401. Holds no DB session beyond one short read."""
    claims = bearer_claims(request)
    viewer_sid = None
    if claims is None:
        imp = impersonation_claims(request)
        if imp is None:
            raise HTTPException(status_code=401, detail="Not authenticated")
        claims = imp
    viewer_admin_id = None
    if claims.get("imp_sid") is not None:
        viewer_sid = int(claims["imp_sid"])
        try:
            viewer_admin_id = int(claims.get("imp_by")) if claims.get("imp_by") is not None else None
        except (TypeError, ValueError):
            viewer_admin_id = None
    try:
        user_id = int(claims["user_id"])
        role = str(claims["role"])
    except (KeyError, TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

    staff_id = claims.get("staff_id")
    staff_perms: frozenset = frozenset()
    staff_name = str(claims.get("staff_name") or "")
    staff_admin = False
    if staff_id is not None:
        from app.db.database import async_session
        from app.db.models import ResellerStaff

        staff_id = int(staff_id)
        async with async_session() as db:
            row = (await db.execute(
                select(ResellerStaff.permissions, ResellerStaff.is_account_admin, ResellerStaff.name)
                .where(ResellerStaff.id == staff_id)
            )).first()
        if row is None:
            raise HTTPException(status_code=401, detail="Your access was changed. Please sign in again.")
        staff_perms = frozenset(row[0] or [])
        staff_admin = bool(row[1])
        staff_name = row[2] or staff_name

    return Caller(
        user_id=user_id,
        role=role,
        authorization=request.headers.get("authorization", ""),
        organization=str(claims.get("organization_name") or ""),
        staff_id=staff_id,
        staff_name=staff_name,
        staff_permissions=staff_perms,
        staff_is_account_admin=staff_admin,
        viewer_sid=viewer_sid,
        viewer_admin_id=viewer_admin_id,
        ip=client_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:200],
    )
