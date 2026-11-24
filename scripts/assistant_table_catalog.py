"""Write the list of read routes (GET and read-only POST) a reseller's assistant can draw as a table, for the admin
frontend's table-spec test (isp-billing-admin app/lib/__tests__/fixtures/assistantCatalogGets.json).

Every read route the assistant's catalog shows a reseller is listed with its template and,
when the route declares a response model, one sample row built from that schema (field
names with typed placeholder values; no real data). The frontend test checks that each
route either has a table spec or that the generic fallback hides ids, MACs, raw RouterOS
fields and empty columns on that sample.

    python scripts/assistant_table_catalog.py ../isp-billing-admin/app/lib/__tests__/fixtures/assistantCatalogGets.json
"""
from __future__ import annotations

import json
import os
import sys
import warnings

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
warnings.filterwarnings("ignore")

from main import app  # noqa: E402
from app.services.assistant.caller import Caller  # noqa: E402
from app.services.assistant.catalog import READ_ONLY_POSTS, Catalog  # noqa: E402

SPEC = app.openapi()
SCHEMAS = SPEC.get("components", {}).get("schemas", {})


def _resolve(schema: dict, depth: int = 0) -> dict:
    while "$ref" in schema and depth < 8:
        schema = SCHEMAS.get(schema["$ref"].split("/")[-1], {})
        depth += 1
    for key in ("anyOf", "oneOf", "allOf"):
        if key in schema:
            parts = [_resolve(s, depth + 1) for s in schema[key] if s.get("type") != "null"]
            if parts:
                return parts[0]
    return schema


def _value(name: str, schema: dict):
    schema = _resolve(schema)
    t = schema.get("type")
    fmt = schema.get("format", "")
    if "enum" in schema:
        return schema["enum"][0]
    if t == "integer":
        return 3
    if t == "number":
        return 12.5
    if t == "boolean":
        return True
    if t == "string":
        if fmt == "date-time":
            return "2026-11-24T10:15:00"
        if fmt == "date":
            return "2026-11-24"
        if "mac" in name.lower():
            return "02:00:00:00:00:01"
        return f"sample {name}"
    if t == "object" and schema.get("properties"):
        return {k: _value(k, v) for k, v in list(schema["properties"].items())[:12]}
    return None


def _sample_row(op: dict):
    content = op.get("responses", {}).get("200", {}).get("content", {}).get("application/json", {})
    schema = _resolve(content.get("schema", {}))
    item = None
    if schema.get("type") == "array":
        item = _resolve(schema.get("items", {}))
    elif schema.get("type") == "object":
        for prop in (schema.get("properties") or {}).values():
            prop = _resolve(prop)
            if prop.get("type") == "array" and _resolve(prop.get("items", {})).get("properties"):
                item = _resolve(prop["items"])
                break
    if not item or not item.get("properties"):
        return None
    return {k: _value(k, v) for k, v in item["properties"].items()}


def main(out_path: str) -> None:
    catalog = Catalog.from_openapi(SPEC)
    reseller = Caller(user_id=1, role="reseller", authorization="Bearer x")
    rows = []
    for action in catalog.for_caller(reseller):
        # every read the assistant can draw: GETs, and the POSTs that only read
        if action.method != "GET" and not (action.method == "POST" and action.template in READ_ONLY_POSTS):
            continue
        op = SPEC["paths"].get(action.template, {}).get(action.method.lower(), {})
        rows.append({"template": action.template, "method": action.method, "title": action.title,
                     "sample": _sample_row(op)})
    rows.sort(key=lambda r: r["template"])
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=1, ensure_ascii=False)
        fh.write("\n")
    print(f"{len(rows)} GET routes written to {out_path}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "assistantCatalogGets.json")
