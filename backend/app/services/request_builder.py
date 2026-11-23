# backend/app/services/request_builder.py
#
# Semester-2 addition: builds *valid* requests from the OpenAPI schema so
# that "valid request" tests are actually valid (correct body, required
# query params, sensible path values) instead of empty requests that
# always fail with 400/422.

from __future__ import annotations

import re
import base64
from typing import Any, Optional
from urllib.parse import quote

PARAM_RE = re.compile(r"\{([^}]+)\}")


# ── Sample values from JSON schema ───────────────────────────────

def _string_for(name: str, fmt: str) -> str:
    n = (name or "").lower()
    if fmt == "email" or "email" in n:
        return "tester@example.com"
    if fmt == "date-time":
        return "2026-01-01T00:00:00Z"
    if fmt == "date":
        return "2026-01-01"
    if fmt == "uuid":
        return "00000000-0000-4000-8000-000000000001"
    if fmt in ("uri", "url") or n in ("url", "uri", "website"):
        return "https://example.com"
    if "password" in n:
        return "Passw0rd!123"
    if "phone" in n:
        return "9999999999"
    if "user" in n or n == "name":
        return "testuser"
    return "test"


def sample_from_schema(schema: Any, name: str = "", depth: int = 0) -> Any:
    if not isinstance(schema, dict) or depth > 6:
        return "test"
    for key in ("example", "default"):
        if key in schema and schema[key] is not None:
            return schema[key]
    if schema.get("enum"):
        return schema["enum"][0]
    if schema.get("allOf"):
        merged: dict = {"type": "object", "properties": {}, "required": []}
        for part in schema["allOf"]:
            if isinstance(part, dict):
                merged["properties"].update(part.get("properties", {}))
                merged["required"] += part.get("required", [])
        return sample_from_schema(merged, name, depth + 1)
    for key in ("oneOf", "anyOf"):
        if schema.get(key):
            return sample_from_schema(schema[key][0], name, depth + 1)

    t = schema.get("type")
    if not t:
        t = "object" if "properties" in schema else "string"
    if t == "integer":
        return max(1, int(schema.get("minimum", 1) or 1))
    if t == "number":
        return float(schema.get("minimum", 1) or 1)
    if t == "boolean":
        return True
    if t == "array":
        return [sample_from_schema(schema.get("items", {}), name, depth + 1)]
    if t == "object":
        props = schema.get("properties") or {}
        return {k: sample_from_schema(v, k, depth + 1) for k, v in props.items()}
    return _string_for(name, schema.get("format", ""))


# ── Parameters ────────────────────────────────────────────────────

def param_schema(param: dict) -> dict:
    # OAS3 keeps the type under "schema", Swagger 2 puts it on the param
    return param.get("schema") or {k: param[k] for k in ("type", "format", "enum", "default") if k in param}


def param_type(endpoint: dict, name: str) -> str:
    for p in endpoint.get("parameters", []):
        if p.get("name") == name and p.get("in") == "path":
            return param_schema(p).get("type", "string")
    return "integer" if name.lower().endswith("id") else "string"


def sample_param(param: dict) -> Any:
    if param.get("example") is not None:
        return param["example"]
    examples = param.get("examples")
    if isinstance(examples, dict) and examples:
        first = next(iter(examples.values()))
        if isinstance(first, dict) and "value" in first:
            return first["value"]
    return sample_from_schema(param_schema(param), param.get("name", ""))


def path_param_names(path: str) -> list[str]:
    return PARAM_RE.findall(path)


def fill_path(path: str, values: dict) -> str:
    """Substitute path params; values are URL-encoded so payloads like ../ survive."""
    return PARAM_RE.sub(lambda m: quote(str(values.get(m.group(1), "1")), safe=""), path)


def build_valid_request(endpoint: dict, base_url: str, seeds: Optional[dict] = None) -> dict:
    """Return kwargs for requests.request() describing a schema-valid call."""
    seeds = seeds or {}
    path_values, query = {}, {}
    for p in endpoint.get("parameters", []):
        loc, name = p.get("in"), p.get("name", "")
        if loc == "path":
            path_values[name] = seeds.get(name, sample_param(p))
        elif loc == "query" and p.get("required"):
            query[name] = sample_param(p)
    for name in path_param_names(endpoint["path"]):          # params missing from spec
        path_values.setdefault(name, seeds.get(name, 1 if param_type(endpoint, name) == "integer" else "test"))

    req: dict = {
        "method": endpoint["method"],
        "url":    base_url + fill_path(endpoint["path"], path_values),
        "params": query,
    }
    rb = endpoint.get("request_body") or {}
    if rb and endpoint["method"] in ("POST", "PUT", "PATCH"):
        body = rb.get("example") if rb.get("example") is not None else sample_from_schema(rb.get("schema", {}))
        if "json" in (rb.get("content_type") or "json"):
            req["json"] = body
        else:
            req["data"] = body if isinstance(body, dict) else {"value": body}
    req["_path_values"] = path_values
    return req


# ── Authentication ────────────────────────────────────────────────

def auth_headers(auth: Optional[dict]) -> dict:
    """
    auth = {"type": "bearer"|"api_key"|"basic", "value": "...",
            "header_name": "X-API-Key" (api_key only)}
    """
    if not auth or not auth.get("value"):
        return {}
    t, v = (auth.get("type") or "bearer").lower(), auth["value"].strip()
    if t == "api_key":
        return {auth.get("header_name") or "X-API-Key": v}
    if t == "basic":
        token = v if ":" not in v else base64.b64encode(v.encode()).decode()
        return {"Authorization": f"Basic {token}"}
    return {"Authorization": v if v.lower().startswith("bearer ") else f"Bearer {v}"}
