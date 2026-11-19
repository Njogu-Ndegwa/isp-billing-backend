"""The API index the assistant works from, built from this app's own OpenAPI.

Every bearer-authenticated JSON operation under /api/ is an action. The model
sees a compact one-line-per-action index (filtered to what the caller may use,
mirroring the staff guard's rules), asks for an action's full parameters with
``describe``, and names a concrete request that ``match`` maps back to its
action. Building it costs one ``app.openapi()`` call per process.

Not actions: public / webhook / router-agent routes (no bearer security), file
uploads, sign-in and token-minting routes, the WebFig proxy, and the
assistant's own routes.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import quote

from app.services import staff_permissions as perms
from app.services.assistant.caller import Caller

METHODS = ("get", "post", "put", "patch", "delete")

# POSTs that only read. Mirrors the View-as allowlist plus read-only diagnostics.
READ_ONLY_POSTS = frozenset({
    "/api/customers/usage/bulk",
    "/api/messaging/customer-events/preview",
    "/api/compensation/outage/preview",
    "/api/customers/{customer_id}/audit-log/router-logs",
    "/api/routers/{router_id}/diagnose/dual-port",
    "/api/routers/{router_id}/load-balancing/preflight",
    "/api/routers/{router_id}/load-balancing/verify",
})

# Request flags that make a write a dry run, when the action declares them.
DRY_RUN_FLAGS = ("dry_run", "preview", "preview_only")

EXCLUDED_PREFIXES = (
    "/api/assistant",          # no recursion
    "/api/auth/",              # sign-in, password reset
    "/api/users/register",
    "/api/admin/impersonate",  # mints a token the chat cannot use
    "/api/impersonation",
)
EXCLUDED_FRAGMENTS = ("/webfig/{", "/jsproxy")

_PARAM = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)(:path)?\}")
_SAFE_VALUE = re.compile(r"[^/?#]+")


@dataclass
class Action:
    method: str
    template: str
    title: str
    description: str
    tag: str
    path_params: list = field(default_factory=list)
    query_params: list = field(default_factory=list)
    body_schema: Optional[dict] = None
    body_required: bool = False
    regex: Optional[re.Pattern] = None
    literal_segments: int = 0
    staff_rule: Any = None
    flags: tuple = ()            # declared dry-run flags (query or body)

    @property
    def key(self) -> str:
        return f"{self.method} {self.template}"

    @property
    def always_reads(self) -> bool:
        return self.method == "GET" or (self.method == "POST" and self.template in READ_ONLY_POSTS)

    def is_read(self, query: Optional[dict], body: Any) -> bool:
        """True when this concrete request changes nothing (runs without a tap)."""
        if self.always_reads:
            return True
        for flag in self.flags:
            for source in (query, body):
                if isinstance(source, dict) and _truthy(source.get(flag)):
                    return True
        return False

    @property
    def admin_only(self) -> bool:
        return "admin" in self.template.strip("/").split("/") and self.staff_rule is None


def _truthy(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value == 1
    return isinstance(value, str) and value.strip().lower() in ("true", "1", "yes")


def _compile(template: str) -> re.Pattern:
    out, pos = [], 0
    for m in _PARAM.finditer(template):
        out.append(re.escape(template[pos:m.start()]))
        out.append(f"(?P<{m.group(1)}>[^/]+)")
        pos = m.end()
    out.append(re.escape(template[pos:]))
    return re.compile("".join(out))


def _literal_segments(template: str) -> int:
    return sum(1 for seg in template.strip("/").split("/") if seg and "{" not in seg)


# ---------------------------------------------------------------------------
# Schema compaction
# ---------------------------------------------------------------------------

def _resolve(schema: Any, components: dict, depth: int = 0, seen: tuple = ()) -> Any:
    """Inline $refs and drop noise so a schema is small enough to show the model."""
    if not isinstance(schema, dict):
        return schema
    if "$ref" in schema:
        name = schema["$ref"].rsplit("/", 1)[-1]
        if name in seen or depth > 5:
            return {"type": "object", "title": name}
        return _resolve(components.get(name, {}), components, depth + 1, seen + (name,))
    out: dict = {}
    for key, value in schema.items():
        if key in ("title", "examples", "example") and depth > 0:
            continue
        if key == "description" and isinstance(value, str):
            out[key] = value.strip().split("\n\n")[0][:240]
        elif key in ("properties",) and isinstance(value, dict):
            out[key] = {k: _resolve(v, components, depth + 1, seen) for k, v in value.items()}
        elif key in ("items", "additionalProperties") and isinstance(value, dict):
            out[key] = _resolve(value, components, depth + 1, seen)
        elif key in ("anyOf", "oneOf", "allOf") and isinstance(value, list):
            options = [_resolve(v, components, depth + 1, seen) for v in value]
            non_null = [o for o in options if not (isinstance(o, dict) and o.get("type") == "null")]
            if len(non_null) == 1 and len(options) == 2:
                merged = dict(non_null[0])
                merged["nullable"] = True
                out.update(merged)
            else:
                out[key] = options
        else:
            out[key] = value
    return out


def _short(text: Optional[str], limit: int) -> str:
    if not text:
        return ""
    first = text.strip().split("\n\n")[0].replace("\n", " ").strip()
    first = re.sub(r"\s+", " ", first)
    return first if len(first) <= limit else first[: limit - 1].rstrip() + "…"


def _title(summary: Optional[str]) -> str:
    """FastAPI's summary from the function name, minus 'Api'/'Endpoint' noise."""
    title = _short(summary, 80)
    title = re.sub(r"\s+(Api|API|Endpoint|Route|Handler)$", "", title)
    return re.sub(r"^(Api|Admin Api)\s+", "", title).strip()


def _tag(template: str) -> str:
    parts = [p for p in template.split("/") if p and p != "api" and "{" not in p]
    if not parts:
        return "other"
    if parts[0] == "admin" and len(parts) > 1:
        return f"admin/{parts[1]}"
    return parts[0]


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------

class Catalog:
    def __init__(self, actions: list[Action]):
        self.actions = actions
        self._by_key = {a.key: a for a in actions}

    @classmethod
    def from_openapi(cls, spec: dict) -> "Catalog":
        components = spec.get("components", {}).get("schemas", {})
        actions: list[Action] = []
        for template, ops in sorted(spec.get("paths", {}).items()):
            if not template.startswith("/api/"):
                continue
            if template.startswith(EXCLUDED_PREFIXES) or any(f in template for f in EXCLUDED_FRAGMENTS):
                continue
            if ":path}" in template:
                continue
            for method in METHODS:
                op = ops.get(method)
                if not op or not op.get("security"):
                    continue
                content = (op.get("requestBody") or {}).get("content") or {}
                if content and "application/json" not in content:
                    continue  # file uploads / forms: done on the page
                body_schema = None
                if "application/json" in content:
                    body_schema = _resolve(content["application/json"].get("schema") or {}, components)
                path_params, query_params = [], []
                for p in op.get("parameters") or []:
                    entry = {
                        "name": p.get("name"),
                        "required": bool(p.get("required")),
                        "schema": _resolve(p.get("schema") or {}, components),
                    }
                    if p.get("description"):
                        entry["description"] = _short(p["description"], 200)
                    if p.get("in") == "path":
                        path_params.append(entry)
                    elif p.get("in") == "query":
                        query_params.append(entry)
                flags = tuple(
                    f for f in DRY_RUN_FLAGS
                    if any(q["name"] == f for q in query_params)
                    or (isinstance(body_schema, dict) and f in (body_schema.get("properties") or {}))
                )
                rule, _ = perms.match_rule(method.upper(), template)
                actions.append(Action(
                    method=method.upper(),
                    template=template,
                    title=_title(op.get("summary")) or template,
                    description=_short(op.get("description"), 160),
                    tag=_tag(template),
                    path_params=path_params,
                    query_params=query_params,
                    body_schema=body_schema,
                    body_required=bool((op.get("requestBody") or {}).get("required")),
                    regex=_compile(template),
                    literal_segments=_literal_segments(template),
                    staff_rule=rule,
                    flags=flags,
                ))
        return cls(actions)

    # -- who may use what --------------------------------------------------

    def allowed(self, action: Action, caller: Caller) -> bool:
        """Mirror of the guards, so the model is not shown routes that will 403.

        The guards (and the handlers) still decide every real call.
        """
        if caller.read_only and not action.always_reads and not action.flags:
            return False
        if caller.role == "admin" and caller.viewer_sid is None:
            return True
        if action.admin_only:
            return False
        if caller.staff_id is None:
            return True
        if caller.staff_is_account_admin and not action.template.startswith("/api/admin/"):
            return True
        rule = action.staff_rule
        return rule is not None and rule.allows(caller.staff_permissions)

    def for_caller(self, caller: Caller) -> list[Action]:
        return [a for a in self.actions if self.allowed(a, caller)]

    # -- matching a concrete request ----------------------------------------

    def match(self, method: str, path: str) -> tuple[Optional[Action], dict]:
        method = method.upper()
        path = path.split("?", 1)[0]
        if len(path) > 1:
            path = path.rstrip("/")
        best, best_params = None, {}
        for action in self.actions:
            if action.method != method:
                continue
            m = action.regex.fullmatch(path)
            if not m:
                continue
            if best is None or action.literal_segments > best.literal_segments:
                best, best_params = action, m.groupdict()
        return best, best_params

    def get(self, method: str, template: str) -> Optional[Action]:
        return self._by_key.get(f"{method.upper()} {template}")

    # -- what the model sees ------------------------------------------------

    def index_text(self, caller: Caller) -> str:
        """One line per action, grouped. ✎ = changes data, runs only after Confirm."""
        groups: dict[str, list[str]] = {}
        for a in self.for_caller(caller):
            q = [p["name"] for p in a.query_params]
            qs = f" ?{','.join(q[:8])}" if q else ""
            mark = "" if a.always_reads else " ✎"
            desc = a.description if a.description and a.description.lower() != a.title.lower() else ""
            text = a.title + (f": {desc}" if desc else "")
            groups.setdefault(a.tag, []).append(f"{a.method} {a.template}{qs}{mark} — {text}")
        lines = []
        for tag in sorted(groups):
            lines.append(f"[{tag}]")
            lines.extend(groups[tag])
        return "\n".join(lines)

    def describe(self, action: Action) -> dict:
        out = {
            "method": action.method,
            "path": action.template,
            "title": action.title,
            "changes_data": not action.always_reads,
            "runs": "immediately" if action.always_reads else "only after the person taps Confirm",
        }
        if action.description:
            out["description"] = action.description
        if action.path_params:
            out["path_params"] = action.path_params
        if action.query_params:
            out["query_params"] = action.query_params
        if action.body_schema:
            out["body"] = action.body_schema
            out["body_required"] = action.body_required
        if action.flags:
            out["dry_run_flags"] = list(action.flags)
        return out


def build_path(action: Action, params: dict) -> Optional[str]:
    """Rebuild the concrete path with each path value checked and URL-quoted."""
    out, pos = [], 0
    for m in _PARAM.finditer(action.template):
        out.append(action.template[pos:m.start()])
        value = str(params.get(m.group(1), ""))
        if not value or not _SAFE_VALUE.fullmatch(value) or value in (".", "..") or "{" in value:
            return None
        out.append(quote(value, safe="@:+-_.~"))
        pos = m.end()
    out.append(action.template[pos:])
    return "".join(out)


_CATALOG: Optional[Catalog] = None


def get_catalog(app) -> Catalog:
    global _CATALOG
    if _CATALOG is None:
        _CATALOG = Catalog.from_openapi(app.openapi())
    return _CATALOG


def reset_catalog() -> None:
    global _CATALOG
    _CATALOG = None
