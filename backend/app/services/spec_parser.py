# backend/app/services/spec_parser.py
#
# Parses OpenAPI 3.x / Swagger 2.0 specs into the structure the agents use.
#
# Semester-2 changes:
#  - Resolves local $ref references (parameters, request bodies, schemas)
#  - Merges path-level and operation-level parameters
#  - Reads security schemes + global/operation `security` so every endpoint
#    knows whether the spec says it requires authentication
#  - Derives the target base URL from `servers` (OAS3) or host/basePath (Swagger 2)

from __future__ import annotations

import copy
from typing import Dict, Any, Optional
from urllib.parse import urljoin, urlparse

from app.database import save_scan, get_scan

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]


class SpecParser:

    # ── $ref resolution ───────────────────────────────────────────

    @staticmethod
    def _lookup(spec: dict, ref: str) -> Any:
        if not ref.startswith("#/"):
            return {}                       # external refs not supported
        node: Any = spec
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(node, dict) or part not in node:
                return {}
            node = node[part]
        return node

    def _resolve(self, spec: dict, node: Any, seen: tuple = (), depth: int = 0) -> Any:
        """Recursively inline local $refs. Cycles and very deep schemas are cut off."""
        if depth > 12:
            return {}
        if isinstance(node, dict):
            if "$ref" in node and isinstance(node["$ref"], str):
                ref = node["$ref"]
                if ref in seen:
                    return {"type": "object", "x-circular-ref": ref}
                target = self._lookup(spec, ref)
                return self._resolve(spec, target, seen + (ref,), depth + 1)
            return {k: self._resolve(spec, v, seen, depth + 1) for k, v in node.items()}
        if isinstance(node, list):
            return [self._resolve(spec, v, seen, depth + 1) for v in node]
        return node

    # ── Base URL ──────────────────────────────────────────────────

    @staticmethod
    def derive_base_url(spec: dict, spec_url: Optional[str] = None) -> Optional[str]:
        """Best-effort target base URL from the spec itself."""
        if "openapi" in spec:
            servers = spec.get("servers") or []
            if servers and isinstance(servers[0], dict) and servers[0].get("url"):
                url = servers[0]["url"]
                for name, var in (servers[0].get("variables") or {}).items():
                    url = url.replace("{" + name + "}", str(var.get("default", "")))
                if urlparse(url).scheme in ("http", "https"):
                    return url.rstrip("/")
                if spec_url:                               # relative server URL
                    return urljoin(spec_url, url).rstrip("/")
            elif spec_url:
                # OAS3: no `servers` means a single server "/" — relative to
                # the document's location, i.e. the spec URL's origin.
                p = urlparse(spec_url)
                return f"{p.scheme}://{p.netloc}"
            return None
        # Swagger 2.0
        host = spec.get("host")
        base_path = spec.get("basePath", "") or ""
        if host:
            scheme = (spec.get("schemes") or ["https"])[0]
            return f"{scheme}://{host}{base_path}".rstrip("/")
        if spec_url:
            p = urlparse(spec_url)
            return f"{p.scheme}://{p.netloc}{base_path}".rstrip("/")
        return None

    # ── Security ──────────────────────────────────────────────────

    @staticmethod
    def _security_schemes(spec: dict) -> dict:
        if "openapi" in spec:
            return (spec.get("components") or {}).get("securitySchemes") or {}
        return spec.get("securityDefinitions") or {}

    @staticmethod
    def _scheme_type(scheme: dict) -> str:
        t = (scheme.get("type") or "").lower()
        if t == "http":
            return (scheme.get("scheme") or "http").lower()     # bearer / basic
        if t in ("apikey", "api_key"):
            return "api_key"
        if t in ("oauth2", "openidconnect"):
            return "oauth2"
        return t or "unknown"

    # ── Parse ─────────────────────────────────────────────────────

    def parse_spec(self, spec: Dict[str, Any], spec_url: Optional[str] = None) -> Dict[str, Any]:
        """Parse OpenAPI spec and extract key information."""

        if not isinstance(spec, dict) or ("openapi" not in spec and "swagger" not in spec):
            raise ValueError("Invalid OpenAPI/Swagger spec")

        is_oas3   = "openapi" in spec
        schemes   = self._security_schemes(spec)
        global_sec = spec.get("security") or []

        endpoints = []
        for path, path_item in (spec.get("paths") or {}).items():
            if not isinstance(path_item, dict):
                continue
            path_item = self._resolve(spec, path_item)
            is_id_based = "{" in path and "}" in path
            path_params = path_item.get("parameters", []) or []

            for method, details in path_item.items():
                if method.upper() not in HTTP_METHODS or not isinstance(details, dict):
                    continue

                # Merge path-level + operation-level params (operation wins)
                merged = {(p.get("name"), p.get("in")): p for p in path_params if isinstance(p, dict)}
                for p in details.get("parameters", []) or []:
                    if isinstance(p, dict):
                        merged[(p.get("name"), p.get("in"))] = p
                params = list(merged.values())

                # Request body
                request_body: dict = {}
                if is_oas3 and details.get("requestBody"):
                    rb = details["requestBody"]
                    content = rb.get("content") or {}
                    ctype = "application/json" if "application/json" in content else next(iter(content), "")
                    request_body = {
                        "content_type": ctype,
                        "required":     bool(rb.get("required")),
                        "schema":       (content.get(ctype) or {}).get("schema", {}),
                        "example":      (content.get(ctype) or {}).get("example"),
                    }
                elif not is_oas3:
                    body = next((p for p in params if p.get("in") == "body"), None)
                    form = [p for p in params if p.get("in") == "formData"]
                    if body:
                        request_body = {"content_type": "application/json",
                                        "required": bool(body.get("required")),
                                        "schema": body.get("schema", {})}
                    elif form:
                        request_body = {"content_type": "application/x-www-form-urlencoded",
                                        "required": True,
                                        "schema": {"type": "object", "properties": {
                                            p["name"]: {"type": p.get("type", "string")} for p in form}}}
                    params = [p for p in params if p.get("in") not in ("body", "formData")]

                # Effective security: operation-level overrides global
                sec = details["security"] if "security" in details else global_sec
                sec_names = sorted({name for req in (sec or []) if isinstance(req, dict) for name in req})
                requires_auth = any(isinstance(req, dict) and req for req in (sec or []))

                endpoints.append({
                    "path":          path,
                    "method":        method.upper(),
                    "summary":       details.get("summary", "") or details.get("description", "")[:120],
                    "operation_id":  details.get("operationId", ""),
                    "parameters":    params,
                    "request_body":  request_body,
                    "responses":     list((details.get("responses") or {}).keys()),
                    "is_id_based":   is_id_based,
                    "requires_auth": requires_auth,
                    "security":      sec_names,
                })

        scheme_types = sorted({self._scheme_type(s) for s in schemes.values() if isinstance(s, dict)})
        auth_type = scheme_types[0] if len(scheme_types) == 1 else (",".join(scheme_types) or "none")

        return {
            "endpoints":       endpoints,
            "total_endpoints": len(endpoints),
            "title":           (spec.get("info") or {}).get("title", "Unnamed API"),
            "version":         (spec.get("info") or {}).get("version", "1.0.0"),
            "spec_version":    spec.get("openapi") or spec.get("swagger"),
            "base_url":        self.derive_base_url(spec, spec_url),
            "auth": {
                "type":    auth_type,
                "schemes": {n: {"type": self._scheme_type(s), "in": s.get("in"), "name": s.get("name")}
                            for n, s in schemes.items() if isinstance(s, dict)},
                "authenticated_endpoints": sum(1 for e in endpoints if e["requires_auth"]),
            },
        }

    def store_spec(self, name: str, spec: Dict[str, Any], parsed_data: Dict[str, Any]) -> str:
        """Persist spec to SQLite and return the scan ID."""
        return save_scan(name, spec, parsed_data)

    def get_spec(self, spec_id: str) -> Dict[str, Any] | None:
        """Retrieve a stored scan from SQLite."""
        return get_scan(spec_id)
