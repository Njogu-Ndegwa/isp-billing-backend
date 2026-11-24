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
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import quote

from app.services import staff_permissions as perms
from app.services.assistant.caller import Caller

METHODS = ("get", "post", "put", "patch", "delete")

# POSTs that only read. Mirrors the View-as allowlist plus read-only diagnostics.
READ_ONLY_POSTS = frozenset({
    "/api/feedback/requests",       # only writes down a feature someone asked for
    "/api/customers/usage/bulk",
    "/api/messaging/customer-events/preview",
    "/api/messaging/send/preview",  # what a send costs; sends nothing
    "/api/compensation/outage/preview",
    "/api/customers/{customer_id}/audit-log/router-logs",
    "/api/routers/{router_id}/diagnose/dual-port",
    "/api/routers/{router_id}/load-balancing/preflight",
    "/api/routers/{router_id}/load-balancing/verify",
})

# Request flags that make a write a dry run, when the action declares them.
DRY_RUN_FLAGS = ("dry_run", "preview", "preview_only")
# The opposite: a flag that makes a preview the real thing (apply=false only shows what would happen).
APPLY_FLAGS = ("apply",)
# Flags that push past the API's own refusal ("record another payment anyway", "delete it with its
# customers"). Never a form input and never set by the model: when the API refuses, the person
# sees why and taps "Do it anyway", which sends the same request again with the flag.
OVERRIDE_FLAGS = ("force", "allow_duplicate")

EXCLUDED_PREFIXES = (
    "/api/assistant",          # no recursion
    "/api/auth/",              # sign-in, password reset
    "/api/users/register",
    "/api/admin/impersonate",  # mints a token the chat cannot use
    "/api/impersonation",
    "/api/routers/create",     # a router is added with a setup code (POST /api/provision/create), never by hand
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
    # a payment the route only starts (an M-Pesa prompt): where to read whether it was paid,
    # a path template filled from the route's own reply (x-payment-status)
    payment_status: Optional[str] = None
    # "payout" when the money goes out to the person (a withdrawal), else a payment they make
    payment_kind: Optional[str] = None
    overrides: tuple = ()        # declared OVERRIDE_FLAGS (query or body)
    apply_flag: Optional[str] = None  # a declared APPLY_FLAG: without it the request is a preview
    preview: Optional[str] = None     # a separate read that previews this change (x-preview)
    # the preview is a cheap read shown on the card as soon as it is proposed (x-preview-now),
    # so its figures (what an SMS costs) are there before the first tap and one Confirm does it
    preview_now: bool = False

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
        if self.apply_flag and not any(isinstance(s, dict) and _truthy(s.get(self.apply_flag))
                                       for s in (query, body)):
            return True  # apply=false: only shows what would happen
        return False

    @property
    def previews(self) -> bool:
        """Whether the person can see what this change would do before it is done."""
        return bool(self.preview or self.flags or self.apply_flag)

    def in_query(self, name: str) -> bool:
        return any(q["name"] == name for q in self.query_params)

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


_ALTERNATION = re.compile(r"\^\(([A-Za-z0-9_.-]+(?:\|[A-Za-z0-9_.-]+)+)\)\$")


def _query_hint(param: dict) -> str:
    """name, or name=a|b|c when the value is one of a fixed few (enum or ^(a|b)$ pattern).

    Spelling the values out in the index keeps the model from guessing
    ("period=today") and burning a failed call.
    """
    name = param.get("name", "")
    schema = param.get("schema") or {}
    values = schema.get("enum")
    if not values and isinstance(schema.get("pattern"), str):
        m = _ALTERNATION.fullmatch(schema["pattern"])
        values = m.group(1).split("|") if m else None
    if values and len(values) <= 8:
        return f"{name}={'|'.join(map(str, values))}"
    kind = {"integer": "int", "number": "num", "boolean": "bool"}.get(schema.get("type"))
    if kind is None and schema.get("format") in ("date", "date-time"):
        kind = schema["format"]
    return f"{name}:{kind}" if kind else name


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
                def declared(names):
                    return tuple(
                        f for f in names
                        if any(q["name"] == f for q in query_params)
                        or (isinstance(body_schema, dict) and f in (body_schema.get("properties") or {}))
                    )
                flags = declared(DRY_RUN_FLAGS)
                apply_flags = declared(APPLY_FLAGS)
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
                    payment_status=op.get("x-payment-status") if isinstance(op.get("x-payment-status"), str) else None,
                    payment_kind=op.get("x-payment-kind") if isinstance(op.get("x-payment-kind"), str) else None,
                    overrides=declared(OVERRIDE_FLAGS),
                    apply_flag=apply_flags[0] if apply_flags and method != "get" else None,
                    preview=op.get("x-preview") if isinstance(op.get("x-preview"), str) else None,
                    preview_now=op.get("x-preview-now") is True,
                ))
        return cls(actions)

    # -- who may use what --------------------------------------------------

    def allowed(self, action: Action, caller: Caller) -> bool:
        """Mirror of the guards, so the model is not shown routes that will 403.

        The guards (and the handlers) still decide every real call.
        """
        if caller.read_only and not action.always_reads and not action.flags and not action.apply_flag:
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
            q = [_query_hint(p) for p in a.query_params]
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
            out["body"] = with_allowed_values(action.body_schema)
            out["body_required"] = action.body_required
        if action.flags:
            out["dry_run_flags"] = list(action.flags)
        if action.apply_flag:
            out["apply_flag"] = (f"{action.apply_flag}=false only previews (runs now); propose it with "
                                 f"{action.apply_flag}=true: the person sees the preview before it is done")
        if action.overrides:
            out["set_only_by_the_person"] = (
                f"{', '.join(action.overrides)}: leave out. If the API refuses (a duplicate, a conflict), "
                "the person is shown why and can tap Do it anyway")
        return out


# ---------------------------------------------------------------------------
# Field values the API schema does not spell out
# ---------------------------------------------------------------------------
# Many request models type a field as a plain string and convert it to a
# database enum inside the handler (e.g. duration_unit -> DurationUnit), so the
# OpenAPI schema cannot tell the model which values work. The database enums
# can: a field named like an enum class (DurationUnit -> duration_unit) takes
# that enum's values. Matched without regard to case, as the handlers convert.

_ENUM_VALUES: Optional[dict[str, list[str]]] = None


def enum_values() -> dict[str, list[str]]:
    global _ENUM_VALUES
    if _ENUM_VALUES is None:
        import enum as _enum

        from app.db import models

        found: dict[str, list[str]] = {}
        for name in dir(models):
            obj = getattr(models, name)
            if isinstance(obj, type) and issubclass(obj, _enum.Enum) and obj is not _enum.Enum:
                snake = re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
                found[snake] = [str(m.value) for m in obj]
        _ENUM_VALUES = found
    return _ENUM_VALUES


def with_allowed_values(schema: dict) -> dict:
    props = schema.get("properties") if isinstance(schema, dict) else None
    if not props:
        return schema
    known = enum_values()
    new_props = {}
    for key, prop in props.items():
        if isinstance(prop, dict) and "enum" not in prop and key in known:
            prop = {**prop, "allowed_values": known[key]}
        new_props[key] = prop
    return {**schema, "properties": new_props}


def body_problems(action: Action, body) -> list[str]:
    """What is wrong with a change request before anyone is asked to confirm it."""
    schema = action.body_schema
    if not isinstance(schema, dict) or schema.get("type") not in (None, "object"):
        return []
    if body is None:
        return ["this action needs a JSON body"] if action.body_required else []
    if not isinstance(body, dict):
        return ["the body must be a JSON object"]
    problems = []
    for field_name in schema.get("required") or []:
        if body.get(field_name) in (None, ""):
            problems.append(f"'{field_name}' is required")
    props = schema.get("properties") or {}
    known = enum_values()
    for key, value in body.items():
        prop = props.get(key)
        if not isinstance(prop, dict) or value is None:
            continue
        named = list(prop["x-enum-labels"]) if isinstance(prop.get("x-enum-labels"), dict) else None
        allowed = prop.get("enum") or (known.get(key) or named if isinstance(value, str) else None)
        if allowed and isinstance(value, str) and value.lower() not in {str(a).lower() for a in allowed}:
            problems.append(f"'{key}' must be one of {', '.join(map(str, allowed))} (got '{value}')")
    if props and not schema.get("additionalProperties"):
        unknown = sorted(set(body) - set(props))
        if unknown:
            problems.append(f"unknown field(s): {', '.join(unknown)}")
    return problems


# -- forms -------------------------------------------------------------------
#
# A change can be proposed as a form: the card shows the action's fields as inputs,
# filled with what the assistant knows, and the person completes or corrects them
# before Confirm. The fields come from the API's own schema, never from the model.
# A password is a masked input the person types: it goes from their browser to the
# API for that one request and is never stored, shown to the model or written into
# the chat. A list of simple values (ports, minutes, permissions) is one input;
# nested objects are left as the assistant set them.

FORM_FIELD_LIMIT = 20  # a schema may allow more with "x-form-limit" (an ad has many short fields)
# An action's own safety switches ("confirm": true on a reboot) are not questions for the person,
# nor are the flags only "Do it anyway" sets, apply (the preview comes first) or a request's
# idempotency key (made by the server for each proposal).
_FORM_HIDDEN = frozenset({"confirm", "confirmed", "dry_run", "dryrun", "preview", "apply",
                          "force", "force_rotate", "allow_duplicate", "idempotency_key"})
_FORM_KINDS = {"integer": "integer", "number": "number", "boolean": "boolean"}

# -- picking one of the person's own records ------------------------------------
#
# An id field is a picker of the person's own records, listed by name. The API says
# where they come from with "x-pick" on the property:
#
#     "x-pick": {"from": "/api/customers", "search": "search",
#                "query": {"page": 1, "per_page": 50}, "label": "{name} · {phone}"}
#
# search: the list's own filter, so a phone can find one customer among thousands;
# query: what the first page is read with; label: how a row reads, each " · " part shown
# when its values are there. Fields named like these pick from the same lists unless the
# schema says otherwise ("x-pick": false); an admin route works on another account's
# records, so it picks only where its schema says.
_CUSTOMERS = {"from": "/api/customers", "search": "search", "query": {"page": 1, "per_page": 50},
              "label": "{name} · {phone}"}
_ROUTERS = {"from": "/api/routers"}
PICK_DEFAULTS: dict[str, dict] = {
    "plan_id": {"from": "/api/plans"},
    "router_id": _ROUTERS,
    "target_router_id": _ROUTERS,
    "router_ids": _ROUTERS,
    "customer_id": _CUSTOMERS,
    "customer_ids": _CUSTOMERS,
    "exclude_customer_ids": _CUSTOMERS,
    "payment_method_id": {"from": "/api/payment-methods", "label": "{label} · {method_type}"},
    "invoice_id": {"from": "/api/subscription/invoices", "query": {"page": 1, "per_page": 24},
                   "label": "{period_label} · {currency} {balance_remaining} · {status}"},
    "template_id": {"from": "/api/messaging/templates"},
    "advertiser_id": {"from": "/api/advertisers", "label": "{name} · {business_name}"},
}
_PICK_KEYS = ("from", "search", "query", "label")


def pick_spec(action: "Action", key: str, prop: Any) -> Optional[dict]:
    spec = prop.get("x-pick") if isinstance(prop, dict) else None
    if spec is False:
        return None
    if isinstance(spec, dict) and isinstance(spec.get("from"), str):
        return {k: spec[k] for k in _PICK_KEYS if k in spec}
    if action.template.startswith("/api/admin/"):
        return None
    found = PICK_DEFAULTS.get(key)
    return dict(found) if found else None


_PLACEHOLDER = re.compile(r"\{(\w+)\}")


def _plain(value: Any) -> str:
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f"{value:,}"
    return str(value)


def pick_label(row: dict, template: Optional[str] = None) -> str:
    """How one record reads in a picker: "Amina · 0712 000 001", or its name."""
    if template:
        parts = []
        for piece in template.split(" · "):
            names = _PLACEHOLDER.findall(piece)
            if names and all(row.get(n) not in (None, "") for n in names):
                parts.append(_PLACEHOLDER.sub(lambda m: _plain(row[m.group(1)]), piece))
        if parts:
            return " · ".join(parts)[:80]
    name = row.get("name") or row.get("identity") or row.get("label")
    return str(name)[:80] if name not in (None, "") else f"#{row.get('id')}"


# -- moments on the person's own clock ----------------------------------------
#
# The API speaks UTC; a phone's date-and-time input has no zone and the person types
# their own clock. A form shows a moment as their local time (EAT for Kenya) and sends
# what they typed back as UTC, so 14:00 typed in Nairobi is 11:00Z, not 14:00Z.

def _moment(value: Any) -> Optional[datetime]:
    """A moment as naive UTC (how the API stores it); a moment without a zone is UTC."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        when = datetime.fromisoformat(value.strip().replace("Z", "+00:00").replace(" ", "T"))
    except ValueError:
        return None
    if when.tzinfo is not None:
        when = when.astimezone(timezone.utc).replace(tzinfo=None)
    return when


def local_input(value: Any, tz: Optional[str]) -> Optional[str]:
    """A moment for a date-and-time input on the person's clock: "2026-11-21T14:00"."""
    from app.services.subscription_reminders import to_local

    when = _moment(value)
    return to_local(when, tz).strftime("%Y-%m-%dT%H:%M") if when is not None else None


def utc_from_local(raw: Any, tz: Optional[str]) -> str:
    """What the person typed (their own clock, or a time with its zone) as UTC; ValueError if not a time."""
    from app.services.subscription_reminders import _zone as zone_info

    when = datetime.fromisoformat(str(raw).strip().replace("Z", "+00:00").replace(" ", "T"))
    if when.tzinfo is None:
        when = when.replace(tzinfo=zone_info(tz))
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def zone_label(tz: Optional[str]) -> str:
    from app.services.subscription_reminders import zone_abbreviation

    return zone_abbreviation(tz, datetime.utcnow())


# -- inputs shaped for what they hold ------------------------------------------

_MAC = re.compile(r"^[0-9A-Fa-f]{2}([-:.]?[0-9A-Fa-f]{2}){5}$")


def _format_of(key: str, prop: dict) -> Optional[str]:
    """A MAC, an IP or a phone number: the page shows the right keyboard and example."""
    named = prop.get("x-format")
    if isinstance(named, str):
        return named
    if key.endswith("mac") or key.endswith("mac_address"):
        return "mac"
    if key in ("ip", "ip_address", "static_ip", "backup_ip") or key.endswith("_ip"):
        return "ip"
    if key == "phone" or key.endswith(("_phone", "phone_number", "whatsapp", "whatsapp_number")) or key == "msisdn":
        return "phone"
    return None


def normal_mac(raw: str) -> str:
    """"aabbccddeeff", "AA-BB-CC-DD-EE-FF" -> "AA:BB:CC:DD:EE:FF"; ValueError if not a MAC."""
    text = raw.strip()
    if not _MAC.fullmatch(text):
        raise ValueError
    digits = re.sub(r"[^0-9A-Fa-f]", "", text).upper()
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


# -- clearing a field on an edit -----------------------------------------------
#
# An emptied optional field on an edit means "clear it", not "keep the old value". How
# an endpoint is told to clear differs: most take null; some take "" (the customer's
# profile fields). A schema says so with "x-clear" on the property, or on the model as
# {"field": value} with "*" for every field.
_KEEP = object()


def _clear_with(schema: dict, key: str, prop: Any) -> Any:
    """What the API says clears this field ("x-clear"), or _KEEP when it says nothing."""
    if isinstance(prop, dict) and "x-clear" in prop:
        return prop["x-clear"]
    spec = schema.get("x-clear")
    if isinstance(spec, dict) and (key in spec or "*" in spec):
        return spec.get(key, spec.get("*"))
    return _KEEP


def _cleared(schema: dict, key: str, prop: Any, f: dict, now: Any = None) -> Any:
    # now: the record's value, as the card may have opened already emptied ("badge_text": "")
    if f.get("required") or f["kind"] == "boolean" or f.get("default") or (
            f.get("value") in (None, "", []) and now in (None, "", [])):
        return _KEEP  # nothing there to clear, or nothing to clear it with
    said = _clear_with(schema, key, prop)
    if said is not _KEEP:
        return said
    if isinstance(prop, dict) and prop.get("nullable"):
        return None
    return _KEEP

def _field_label(key: str) -> str:
    words = key.replace("_", " ").strip()
    return (words[:1].upper() + words[1:]) if words else key


# -- fields that belong to one choice ------------------------------------------
#
# One request model often serves several kinds of thing: a payment method is a bank
# account, a till, an MTN wallet..., each with its own fields. The API says which
# fields go with which choice in the schema itself:
#
#     "x-fields-for":   {"method_type": {"mpesa_till": ["mpesa_till_number"], ...}}
#     "x-required-for": {"method_type": {"mpesa_till": ["mpesa_till_number"], ...}}
#
# and a form shows only the fields of the chosen kind. When the person can still
# change the choice in the form, each such field carries "when" and the page shows it
# only while that choice is picked. A field listed under no choice is always shown.

def choice_groups(schema: Any) -> dict[str, dict[str, list[str]]]:
    spec = schema.get("x-fields-for") if isinstance(schema, dict) else None
    if not isinstance(spec, dict):
        return {}
    return {choice: {str(v): list(m or []) for v, m in groups.items()}
            for choice, groups in spec.items() if isinstance(groups, dict)}


def _owners(groups: dict[str, list[str]]) -> dict[str, list[str]]:
    owners: dict[str, list[str]] = {}
    for value, members in groups.items():
        for name in members:
            owners.setdefault(name, []).append(value)
    return owners


def _chosen(choice: str, current: dict, context: Optional[dict]) -> Optional[str]:
    for source in (current, context or {}):
        value = source.get(choice)
        if value not in (None, "", []):
            return str(value)
    return None


def choice_matches(chosen: Any, values: list[str]) -> bool:
    """"*" is any value at all (a data cap filled in); otherwise one of the listed ones."""
    if chosen in (None, "", []):
        return False
    return "*" in values or str(chosen).lower() in {v.lower() for v in values}


def _base(choice: str) -> str:
    """"plan_id.connection_type" is decided by the plan picked: its connection type."""
    return choice.split(".", 1)[0]


def _fit_to_choices(schema: dict, fields: list[dict], current: dict, context: Optional[dict]) -> list[dict]:
    needs = schema.get("x-required-for") if isinstance(schema.get("x-required-for"), dict) else {}
    on_form = {f["name"] for f in fields}
    for choice, groups in choice_groups(schema).items():
        owners = _owners(groups)
        need = {str(v): set(m or []) for v, m in (needs.get(choice) or {}).items()}
        chosen = _chosen(choice, current, context)
        kept = []
        for f in fields:
            if f["name"] == choice and chosen is not None and f.get("value") is None:
                f = {**f, "value": chosen}  # an edit: the record's own choice
            elif f["name"] == _base(choice) != choice and f.get("value") is None                     and (context or {}).get(f["name"]) not in (None, ""):
                f = {**f, "value": context[f["name"]]}  # an edit: the record's own plan
            values = owners.get(f["name"])
            if values is None:
                kept.append(f)
            elif _base(choice) in on_form:  # the person may still change it: the page decides
                required = all(f["name"] in need.get(v, ()) for v in values)
                f = {**f, "when": {**(f.get("when") or {}), choice: values}}
                kept.append({**f, "required": True} if required else f)
            elif chosen is None:
                kept.append(f)  # unknown kind: nothing to go by, show everything as before
            elif choice_matches(chosen, values):
                kept.append({**f, "required": True} if f["name"] in need.get(chosen, ()) else f)
        fields = kept
    return fields


def drop_unchosen(schema: Any, body: dict, context: Optional[dict] = None) -> dict:
    """Leave out values for fields of a kind that was not chosen (typed, then switched)."""
    out = dict(body)
    for choice, groups in choice_groups(schema).items():
        if "." in choice:
            continue  # decided by another record (the plan's type): the page sends only the right ones
        chosen = _chosen(choice, out, context)
        if chosen is None and "*" not in groups:
            continue  # unknown kind: keep everything (an empty data cap does drop its FUP fields)
        for name, values in _owners(groups).items():
            if not choice_matches(chosen, values):
                out.pop(name, None)
    return out


def form_fields(action: Action, body: Any, context: Optional[dict] = None,
                tz: Optional[str] = None) -> Optional[list[dict]]:
    """The editable fields of a change, in the order a person fills them: required first.

    context: the record being edited, when known, for fields that depend on its kind.
    tz: the person's time zone; a moment is shown on their own clock.
    """
    from app.services.assistant.shaping import is_secret_key

    schema = action.body_schema
    if not isinstance(schema, dict) or schema.get("type") not in (None, "object"):
        return None
    props = schema.get("properties") or {}
    required = set(schema.get("required") or [])
    known = enum_values()
    current = body if isinstance(body, dict) else {}
    out: list[dict] = []
    # safety switches stay as set, never shown as inputs
    hidden = _FORM_HIDDEN | set(action.flags) | set(action.overrides) | {action.apply_flag}
    for key, prop in props.items():
        if not isinstance(prop, dict) or prop.get("readOnly") or key in hidden:
            continue
        typ = prop.get("type")
        named = prop.get("x-enum-labels") if isinstance(prop.get("x-enum-labels"), dict) else None
        # a field typed as plain text whose values the schema names ("x-enum-labels") is a choice of those
        options = prop.get("enum") or known.get(key) or (list(named) if named and typ in (None, "string") else None)
        item_kind = None
        if is_secret_key(key):
            if typ not in (None, "string"):
                continue
            kind, options = "password", None
        elif typ == "array" and isinstance(prop.get("items"), dict) and prop["items"].get("type") in ("string", "integer", "number"):
            kind = "list"
            item_kind = {"string": "text"}.get(prop["items"]["type"], prop["items"]["type"])
            options = prop["items"].get("enum") or (sorted(perms.PERMISSIONS) if key == "permissions" and "staff" in action.template else None)
        elif options:
            kind = "select"
        elif typ in _FORM_KINDS:
            kind = _FORM_KINDS[typ]
        elif typ == "string" or (typ is None and "properties" not in prop and "items" not in prop):
            kind = {"date": "date", "date-time": "datetime"}.get(prop.get("format"), "text")
        else:
            continue  # objects and lists stay as the assistant set them
        f: dict = {"name": key, "label": _field_label(key), "kind": kind, "required": key in required}
        if item_kind:
            f["item_kind"] = item_kind
        if options:
            f["options"] = [str(o) for o in options]
            if kind == "select" and (typ == "integer" or all(isinstance(o, int) and not isinstance(o, bool) for o in options)):
                f["value_kind"] = "integer"  # 5, 10, 15 minutes: sent as a number, not "10"
            labels = prop.get("x-enum-labels") or (prop.get("items") or {}).get("x-enum-labels")
            if isinstance(labels, dict):
                # people see words, the API gets its codes ("Shown everywhere" for "global")
                f["option_labels"] = {str(k): str(v) for k, v in labels.items() if str(k) in f["options"]}
        if isinstance(prop.get("description"), str) and prop["description"].strip():
            f["hint"] = prop["description"].strip()[:160]
        for bound in ("minimum", "maximum", "maxLength"):
            if isinstance(prop.get(bound), (int, float)):
                f[bound] = prop[bound]
        if isinstance(prop.get("x-upload"), dict):
            # a photo or video the person picks on their phone: the page uploads it and fills in its address
            f["upload"] = {k: v for k, v in prop["x-upload"].items() if k in ("accept", "ticket")}
        if prop.get("x-geo") in ("lat", "lng"):
            f["geo"] = prop["x-geo"]  # one half of a place: the page picks both on a map
        if isinstance(prop.get("x-presets"), list):
            # ready-made values to pick (built-in photos), drawn as pictures next to the upload
            f["presets"] = [{"label": str(p.get("label") or p.get("value")), "value": str(p["value"])}
                            for p in prop["x-presets"][:12] if isinstance(p, dict) and p.get("value")]
        if prop.get("x-admin-only"):
            f["admin_only"] = True
        if isinstance(prop.get("x-pick-where"), dict):
            f["pick_where"] = prop["x-pick-where"]  # only records that fit (vouchers: hotspot plans)
        if kind in ("integer", "text", "list") and not options:
            pick = pick_spec(action, key, prop)
            if pick:
                f["pick"] = pick  # filled with the person's own records before the card is shown
        live = prop.get("x-options-from") or (prop.get("items") or {}).get("x-options-from")
        if isinstance(live, dict) and isinstance(live.get("path"), str):
            # read from the live thing when the card is made (a router's own ports, each with its mode)
            f["options_from"] = dict(live)
            if live.get("ordered"):
                f["ordered"] = True  # the order picked is the order sent (WAN 1, WAN 2...)
            changes = live.get("changes")
            if isinstance(changes, list) and len(changes) == 2:
                f["changes"] = {"add": str(changes[0]), "remove": str(changes[1])}
        if kind == "text":
            shape = _format_of(key, prop)
            if shape:
                f["format"] = shape
            if prop.get("x-sms"):
                f["sms"] = True  # long text with its SMS count while it is typed
            if prop.get("x-sms") or prop.get("x-multiline") or (prop.get("maxLength") or 0) >= 300:
                f["multiline"] = True
        if kind == "datetime":
            f["zone"] = zone_label(tz)  # the person's own clock ("EAT")
        if action.method in ("PUT", "PATCH") and key not in required and kind != "boolean"                 and _clear_with(schema, key, prop) is not _KEEP:
            f["clears"] = True  # emptied on this edit, the API removes it (a plan's badge)
        if kind == "password":
            pass  # never sent back to the page, never pre-filled
        elif current.get(key) is not None:
            f["value"] = current[key]
        elif isinstance(context, dict) and context.get(key) is not None and not is_secret_key(key):
            f["value"] = context[key]  # an edit: the record's value now, so nothing reads as blank or "off"
        elif prop.get("default") is not None:
            f["value"] = prop["default"]
            f["default"] = True  # the API's own default, not something the person or assistant chose
        if kind == "datetime" and f.get("value") is not None:
            shown = local_input(f["value"], tz)
            if shown:
                f["value"] = shown
        out.append(f)
    out = _fit_to_choices(schema, out, current, context)
    out.sort(key=lambda f: not f["required"])  # stable: required first, schema order within
    # the limit is what is on screen at once: fields of one kind are shown one kind at a time
    # a choice that other fields hang on (photo or video) is never the one left out
    deciding = {c.split(".", 1)[0] for c in choice_groups(schema)}
    out.sort(key=lambda f: (not f["required"], f["name"] not in deciding, bool(f.get("admin_only"))))
    limit = schema.get("x-form-limit") if isinstance(schema.get("x-form-limit"), int) else FORM_FIELD_LIMIT
    shown, kept = 0, []
    for f in out:
        if "when" not in f:
            shown += 1
            if shown > limit and f["name"] not in deciding:
                continue
        kept.append(f)
    return kept or None


def _one_value(kind: str, raw: Any, options: list) -> Any:
    """One typed value read by its kind; ValueError when it cannot be."""
    if kind == "integer":
        number = float(str(raw).replace(",", "").strip())
        if not number.is_integer():
            raise ValueError
        return int(number)
    if kind == "number":
        number = float(str(raw).replace(",", "").strip())
        return int(number) if number.is_integer() else number
    if options:
        match = next((o for o in options if o.lower() == str(raw).strip().lower()), None)
        if match is None:
            raise ValueError
        return match
    return str(raw).strip()[:2000]


def apply_form_values(action: Action, base: Any, values: dict,
                      context: Optional[dict] = None, tz: Optional[str] = None) -> tuple[dict, dict, list[str]]:
    """Merge what the person typed into the proposed body, typed by the schema.

    Only the form's own fields are taken (nothing the form did not offer). An emptied
    optional field is left out, or on an edit cleared (see x-clear). A moment typed on the
    person's clock is sent as UTC. Passwords come back on their own, to be sent with the
    request and then forgotten. Returns (body, secrets, problems), e.g. a problem
    "'price' must be a number".
    """
    fields = {f["name"]: f for f in (form_fields(action, base, context, tz) or [])}
    schema = action.body_schema if isinstance(action.body_schema, dict) else {}
    props = schema.get("properties") or {}
    editing = action.method in ("PUT", "PATCH")
    body = dict(base) if isinstance(base, dict) else {}
    secrets: dict = {}
    problems: list[str] = []
    for key, raw in values.items():
        f = fields.get(key)
        if f is None:
            continue
        kind = f["kind"]
        if kind == "password":
            if isinstance(raw, str) and raw:
                secrets[key] = raw[:500]
            continue
        if f.get("changes") and isinstance(raw, dict):
            # a set changed by what was ticked and unticked ("add ether3"), never re-sent whole:
            # the router's other ports stay as they are
            add, remove = f["changes"]["add"], f["changes"]["remove"]
            try:
                for name, items in ((add, raw.get("add")), (remove, raw.get("remove"))):
                    items = [i for i in (items if isinstance(items, list) else []) if str(i).strip()]
                    body[name] = [_one_value(f.get("item_kind", "text"), i, []) for i in items][:100]
            except (TypeError, ValueError):
                problems.append(f"'{key}' must be a list of values")
                continue
            body.pop(key, None)
            continue
        if raw is None or (isinstance(raw, str) and not raw.strip()) or raw == []:
            now = context.get(key) if isinstance(context, dict) else None
            cleared = _cleared(schema, key, props.get(key), f, now) if editing else _KEEP
            if cleared is _KEEP:
                body.pop(key, None)
            else:
                body[key] = cleared  # emptied on an edit: cleared, not left as it was
            continue
        if kind == "list":
            items = raw if isinstance(raw, list) else [p for p in str(raw).replace("\n", ",").split(",")]
            items = [i for i in items if str(i).strip()]
            try:
                body[key] = [_one_value(f.get("item_kind", "text"), i, f.get("options") or []) for i in items][:100]
            except (TypeError, ValueError):
                what = {"integer": "whole numbers", "number": "numbers"}.get(f.get("item_kind", ""), "values from the list")
                problems.append(f"'{key}' must be {what}, separated by commas")
            continue
        if kind == "select" and f.get("value_kind") == "integer":
            kind = "integer"  # a picker of records, or a choice of numbers: the value is a number
        try:
            if kind == "integer":
                value: Any = int(float(str(raw).replace(",", "").strip()))
                if float(str(raw).replace(",", "").strip()) != value:
                    raise ValueError
            elif kind == "number":
                value = float(str(raw).replace(",", "").strip())
                if value.is_integer():
                    value = int(value)
            elif kind == "boolean":
                value = raw if isinstance(raw, bool) else str(raw).strip().lower() in ("true", "1", "yes", "on")
            elif kind == "select":
                match = next((o for o in f.get("options", []) if o.lower() == str(raw).strip().lower()), None)
                if match is None:
                    raise ValueError
                value = match
            elif kind == "datetime":
                value = utc_from_local(raw, tz)
            elif f.get("format") == "mac":
                value = normal_mac(str(raw))
            elif f.get("format") == "phone":
                value = re.sub(r"[\s().-]", "", str(raw))[:20]  # "0712 345 678" -> "0712345678"; the API normalises the rest
            else:
                value = str(raw).strip()[:2000]
        except (TypeError, ValueError):
            what = {"integer": "a whole number", "number": "a number", "datetime": "a date and time",
                    "select": "one of " + ", ".join(f.get("options", []))}
            if f.get("format") == "mac":
                what["text"] = "a MAC address like AA:BB:CC:DD:EE:FF"
            problems.append(f"'{key}' must be {what.get(kind, 'valid')}")
            continue
        if kind in ("integer", "number"):
            if isinstance(f.get("minimum"), (int, float)) and value < f["minimum"]:
                problems.append(f"'{key}' must be at least {f['minimum']}")
                continue
            if isinstance(f.get("maximum"), (int, float)) and value > f["maximum"]:
                problems.append(f"'{key}' must be at most {f['maximum']}")
                continue
        body[key] = value
    # a field of a kind that was not chosen (typed, then the kind switched) is not sent
    body = drop_unchosen(action.body_schema, body, context)
    secrets = {k: v for k, v in secrets.items() if k in drop_unchosen(action.body_schema, {**body, k: v}, context)}
    for f in form_fields(action, body, context, tz) or []:
        # the chosen kind's own required fields, which the schema alone cannot require
        when = f.get("when") or {}
        if f.get("required") and when and f["kind"] != "password" and body.get(f["name"]) in (None, ""):
            if all("." not in c and choice_matches(body.get(c), vs) for c, vs in when.items()):
                problems.append(f"'{f['name']}' is required")
    return body, secrets, problems


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
