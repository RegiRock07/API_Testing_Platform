# backend/app/agents/api_testing_agent.py
#
# Live HTTP testing of every endpoint.
#
# Semester-2 changes:
#  - Schema-aware valid requests (request bodies, required query params)
#  - Resource-aware ID discovery: real IDs are harvested from collection
#    endpoints (GET /users -> "alice") instead of always using "1"
#  - Wrong-method test only uses methods the spec does NOT define
#  - Auth-aware outcomes: 401/403 on a secured endpoint without
#    credentials counts as "auth enforced" (pass), not a failure
#  - Fuzzing covers query parameters too; payloads are URL-encoded so
#    traversal strings are not normalised away; network errors are no
#    longer counted as vulnerabilities; DB error signatures detected
#  - Safe mode (default ON): never sends DELETE/PUT/PATCH to the target
#  - Endpoints tested in parallel inside a time budget -> partial results
#    instead of losing everything on a timeout
#  - Every test keeps request/response evidence for the Verifier Agent

from __future__ import annotations

import re
import time
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

import requests

from app.services.request_builder import (
    build_valid_request, fill_path, path_param_names, param_type,
    auth_headers, param_schema,
)

logger = logging.getLogger(__name__)

DESTRUCTIVE = {"DELETE", "PUT", "PATCH"}
ALL_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]

FUZZ_PAYLOADS = [
    "' OR 1=1 --",
    "<script>alert(1)</script>",
    "../../etc/passwd",
    "../../../../windows/win.ini",
    "A" * 2048,
    "%00",
    "'; DROP TABLE users;--",
    "{{7*7}}",
    "${7*7}",
    "null",
    "-1",
    "0",
]

DB_ERROR_SIGNATURES = [
    "sqlite3.", "sqlite_error", "operationalerror", "sql syntax", "mysql",
    "psycopg2", "postgresql", "ora-0", "sqlstate", "unclosed quotation",
    "syntax error at or near", "sqlalchemy",
]

REQUEST_TIMEOUT = 8


def _snippet(r: requests.Response, n: int = 300) -> str:
    try:
        return r.text[:n]
    except Exception:
        return ""


class APITestingAgent:

    def __init__(self, base_url: Optional[str] = None):
        self.base_url = base_url

    # ── HTTP helper ───────────────────────────────────────────────

    def _send(self, method: str, url: str, **kw) -> tuple[Optional[requests.Response], Optional[str]]:
        if time.time() > self.deadline:
            return None, "time budget exceeded"
        headers = {**self.headers, **kw.pop("headers", {})}
        try:
            return requests.request(method, url, headers=headers, timeout=REQUEST_TIMEOUT,
                                    allow_redirects=False, **kw), None
        except requests.RequestException as e:
            return None, f"{type(e).__name__}: {str(e)[:120]}"

    def _record(self, test: str, method: str, url: str, r, err, passed_fn, expected: str, **extra) -> dict:
        out = {"test": test, "request": {"method": method, "url": url}, "expected": expected, **extra}
        if r is None:
            out.update({"error": err, "passed": None, "skipped": True})
            return out
        out.update({
            "status_code":      r.status_code,
            "passed":           bool(passed_fn(r.status_code)),
            "response_length":  len(r.content or b""),
            "response_snippet": _snippet(r),
            "content_type":     r.headers.get("content-type", ""),
        })
        return out

    # ── ID discovery ──────────────────────────────────────────────

    def _discover_seeds(self, endpoints: list) -> dict:
        """Harvest real object identifiers from collection endpoints."""
        seeds: dict[str, list] = {}
        gets = {e["path"] for e in endpoints if e["method"] == "GET" and "{" not in e["path"]}
        for ep in endpoints:
            for name in path_param_names(ep["path"]):
                if name in seeds:
                    continue
                collection = ep["path"].split("{" + name + "}")[0].rstrip("/")
                if collection not in gets:
                    continue
                r, _ = self._send("GET", self.base_url + collection)
                if r is None or r.status_code >= 400:
                    continue
                try:
                    data = r.json()
                except ValueError:
                    continue
                if isinstance(data, dict):        # {"users": [...]} style wrappers
                    data = next((v for v in data.values() if isinstance(v, list)), [])
                if not isinstance(data, list):
                    continue
                base = name.lower().removesuffix("id").removesuffix("_")
                keys = [name, "id", "username", "name", f"{base}_id", base]
                values = []
                for item in data[:10]:
                    if not isinstance(item, dict):
                        continue
                    lower = {k.lower(): v for k, v in item.items()}
                    for k in keys:
                        v = lower.get(k.lower())
                        if isinstance(v, (int, str)) and v != "" and v not in values:
                            values.append(v)
                            break
                    if len(values) >= 2:
                        break
                if values:
                    seeds[name] = values
        return seeds

    # ── Per-endpoint tests ────────────────────────────────────────

    def _test_endpoint(self, ep: dict, path_methods: dict) -> dict:
        path, method = ep["path"], ep["method"]
        result = {"endpoint": path, "method": method, "base_url": self.base_url,
                  "requires_auth": ep.get("requires_auth", False), "tests": []}
        tests = result["tests"]

        if self.safe_mode and method in DESTRUCTIVE:
            tests.append({"test": "skipped_safe_mode", "passed": None, "skipped": True,
                          "note": f"{method} not sent to target in safe mode"})
            return result

        seeds = {k: v[0] for k, v in self.seeds.items()}
        unauth_expected = ep.get("requires_auth") and not self.headers

        # 1. Valid request
        req = build_valid_request(ep, self.base_url, seeds)
        url = req["url"]
        r, err = self._send(method, url, params=req["params"],
                            **{k: req[k] for k in ("json", "data") if k in req})
        if unauth_expected:
            tests.append(self._record("valid_request", method, url, r, err,
                                      lambda s: s in (401, 403) or s < 400,
                                      "401/403 (auth required, no credentials) or 2xx",
                                      auth_enforced=(r is not None and r.status_code in (401, 403))))
        else:
            tests.append(self._record("valid_request", method, url, r, err,
                                      lambda s: s < 400, "2xx/3xx"))

        params = path_param_names(path)
        if params:
            first = params[0]
            ptype = param_type(ep, first)

            # 2. Invalid parameter type (only meaningful for typed params)
            if ptype in ("integer", "number", "boolean"):
                bad = fill_path(path, {**req["_path_values"], first: "abc"})
                r, err = self._send(method, self.base_url + bad, params=req["params"])
                tests.append(self._record("invalid_parameter", method, self.base_url + bad, r, err,
                                          lambda s: 400 <= s < 500, "4xx (input rejected)"))

            # 3. Nonexistent resource
            missing = 999999 if ptype in ("integer", "number") else "nonexistent_zz9"
            nx = fill_path(path, {**req["_path_values"], first: missing})
            r, err = self._send(method, self.base_url + nx, params=req["params"],
                                **{k: req[k] for k in ("json", "data") if k in req})
            tests.append(self._record("nonexistent_resource", method, self.base_url + nx, r, err,
                                      lambda s: s in (404, 410) or (unauth_expected and s in (401, 403)),
                                      "404 Not Found"))

        # 4. Undocumented method (only methods the spec does NOT define here)
        defined = path_methods.get(path, set())
        candidates = [m for m in ALL_METHODS if m not in defined
                      and not (self.safe_mode and m in DESTRUCTIVE)]
        if candidates:
            wm = candidates[0]
            r, err = self._send(wm, url)
            tests.append(self._record("wrong_method", wm, url, r, err,
                                      lambda s: 400 <= s < 500, "405 (undocumented method rejected)"))

        # 5. Fuzzing — path params and query params
        targets = [("path", p) for p in params]
        targets += [("query", p["name"]) for p in ep.get("parameters", [])
                    if p.get("in") == "query" and param_schema(p).get("type", "string") in ("string", "integer")][:1]
        if targets:
            fuzz = []
            for loc, name in targets:
                for payload in FUZZ_PAYLOADS:
                    if loc == "path":
                        furl = self.base_url + fill_path(path, {**req["_path_values"], name: payload})
                        r, err = self._send(method, furl, params=req["params"],
                                            **{k: req[k] for k in ("json", "data") if k in req})
                    else:
                        furl = url
                        r, err = self._send(method, url, params={**req["params"], name: payload},
                                            **{k: req[k] for k in ("json", "data") if k in req})
                    entry = {"payload": payload[:60], "location": f"{loc}:{name}", "url": furl[:200]}
                    if r is None:
                        entry.update({"error": err, "possible_vulnerability": False})
                    else:
                        body = (r.text or "")[:4000].lower()
                        reasons = []
                        if r.status_code >= 500:
                            reasons.append("server_error")
                        if any(sig in body for sig in DB_ERROR_SIGNATURES):
                            reasons.append("db_error_signature")
                        if "<script>" in payload and payload.lower() in body \
                                and "html" in r.headers.get("content-type", ""):
                            reasons.append("reflected_xss")
                        entry.update({"status_code": r.status_code,
                                      "possible_vulnerability": bool(reasons),
                                      "reasons": reasons})
                        if reasons:
                            entry["response_snippet"] = _snippet(r, 400)
                    fuzz.append(entry)
            flagged = [f for f in fuzz if f.get("possible_vulnerability")]
            tests.append({"test": "dynamic_fuzz_testing", "total_payloads": len(fuzz),
                          "vulnerable_count": len(flagged), "passed": len(flagged) == 0,
                          "results": fuzz})

        return result

    # ── Main run ──────────────────────────────────────────────────

    def run(self, parsed_data: dict, options: Optional[dict] = None) -> dict:
        options        = options or {}
        self.base_url  = (parsed_data.get("base_url") or self.base_url or "").rstrip("/")
        self.safe_mode = options.get("safe_mode", True)
        self.headers   = auth_headers(options.get("auth"))
        self.deadline  = time.time() + float(options.get("time_budget", 150))
        endpoints      = parsed_data.get("endpoints", [])

        if not self.base_url:
            return {"agent": "api_testing", "status": "no_target", "results": [],
                    "note": "No target base URL — add `servers` to the spec or enter a target URL."}

        started = time.time()
        self.seeds = self._discover_seeds(endpoints)

        path_methods: dict[str, set] = {}
        for e in endpoints:
            path_methods.setdefault(e["path"], set()).add(e["method"])

        with ThreadPoolExecutor(max_workers=int(options.get("concurrency", 8))) as pool:
            results = list(pool.map(lambda ep: self._test_endpoint(ep, path_methods), endpoints))

        timed_out = time.time() > self.deadline
        logger.info(f"[APITesting] {len(endpoints)} endpoints in {time.time() - started:.1f}s "
                    f"(safe_mode={self.safe_mode}, timed_out={timed_out})")
        return {
            "agent":            "api_testing",
            "status":           "partial" if timed_out else "completed",
            "base_url_tested":  self.base_url,
            "safe_mode":        self.safe_mode,
            "authenticated":    bool(self.headers),
            "discovered_ids":   self.seeds,
            "duration_s":       round(time.time() - started, 1),
            "results":          results,
        }
