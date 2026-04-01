import os
import re
import json
import time
import requests
from app.services.llm_service import call_llm, parse_llm_json as _parse_llm_json, LLMError


# ─────────────────────────────────────────────────────────────────
# Payload dictionaries for fuzz testing (unchanged)
# ─────────────────────────────────────────────────────────────────

PAYLOAD_CATEGORIES = {
    "sql_injection": [
        "' OR 1=1 --",
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "1' AND '1'='1",
        "admin'--",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
        '"><script>alert(1)</script>',
    ],
    "path_traversal": [
        "../../etc/passwd",
        "../../../../windows/system32",
        "..\\..\\..\\windows\\system32",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
    ],
    "integer_overflow": ["-1", "0", "9999999999", "-9999999999"],
    "null_byte": ["%00", "\\x00", "null"],
    "ssti": ["{{7*7}}", "${7*7}", "{{{{}}}}", "<%= 7*7 %>"],
    "auth_bypass": ["admin", "administrator", "root", "null", "undefined"],
}


# ─────────────────────────────────────────────────────────────────
# 4-Outcome Classification
# ─────────────────────────────────────────────────────────────────
# PASS              — test ran, result is expected and safe
# SECURITY_FAILURE  — unexpected success on protected/invalid request
# EXPECTED_FAILURE  — API responded correctly to a bad request
# CONNECTION_ERROR  — could not reach the API at all
# ─────────────────────────────────────────────────────────────────

def classify_outcome(test_type: str, actual_status: int,
                     response_body: str = "", payload: str = None):
    """
    Classify a test result into one of 4 outcomes.
    Returns (outcome, expected_status_desc, note, evidence).
    """
    # HTTP 415 is always EXPECTED_FAILURE regardless of test type
    if actual_status == 415:
        return (
            "EXPECTED_FAILURE", "4xx",
            "Content-Type mismatch in test construction — not an API vulnerability.",
            None,
        )

    if test_type == "valid_request":
        if 200 <= actual_status < 300:
            return ("PASS", "2xx", f"API responded with {actual_status} as expected.", None)
        return (
            "SECURITY_FAILURE", "2xx",
            f"Expected 2xx for valid request, got {actual_status}.",
            f"Unexpected {actual_status} on valid request",
        )

    if test_type == "invalid_parameter":
        if actual_status in (400, 422, 415):
            return ("EXPECTED_FAILURE", "400/422/415",
                    f"API correctly rejected invalid parameter with {actual_status}.", None)
        if 200 <= actual_status < 300:
            return ("SECURITY_FAILURE", "400/422/415",
                    f"API accepted invalid parameter with {actual_status}.",
                    f"Invalid parameter accepted with status {actual_status}")
        return ("EXPECTED_FAILURE", "400/422/415",
                f"API responded with {actual_status} to invalid parameter.", None)

    if test_type == "nonexistent_resource":
        if actual_status == 404:
            return ("EXPECTED_FAILURE", "404",
                    "API correctly returned 404 for nonexistent resource.", None)
        if 200 <= actual_status < 300:
            return ("SECURITY_FAILURE", "404",
                    f"API returned {actual_status} for nonexistent resource.",
                    f"Nonexistent resource returned {actual_status}")
        return ("EXPECTED_FAILURE", "404",
                f"API responded with {actual_status} to nonexistent resource.", None)

    if test_type == "wrong_method":
        if actual_status == 405:
            return ("EXPECTED_FAILURE", "405",
                    "API correctly returned 405 for wrong HTTP method.", None)
        if 200 <= actual_status < 300:
            return ("SECURITY_FAILURE", "405",
                    f"API accepted wrong HTTP method with {actual_status}.",
                    f"Wrong method accepted with status {actual_status}")
        return ("EXPECTED_FAILURE", "405",
                f"API responded with {actual_status} to wrong HTTP method.", None)

    if test_type == "fuzz_testing":
        if 400 <= actual_status < 500:
            return ("EXPECTED_FAILURE", "4xx",
                    f"API correctly rejected fuzz payload with {actual_status}.", None)
        if 200 <= actual_status < 300:
            body_lower = (response_body or "").lower()
            evidence_parts = []
            if payload and payload.lower() in body_lower:
                evidence_parts.append("Reflected payload in response")
            if any(kw in body_lower for kw in
                   ["traceback", "stack trace", "exception", "error at line"]):
                evidence_parts.append("Stack trace detected in response")
            if evidence_parts:
                return ("SECURITY_FAILURE", "4xx",
                        f"Fuzz payload accepted with {actual_status}.",
                        "; ".join(evidence_parts))
            return ("EXPECTED_FAILURE", "4xx",
                    f"API returned {actual_status} but no evidence of exploitation.", None)
        if actual_status >= 500:
            return ("SECURITY_FAILURE", "4xx",
                    f"Server error {actual_status} triggered by fuzz payload.",
                    f"Server crash on fuzz input (status {actual_status})")
        return ("EXPECTED_FAILURE", "4xx",
                f"API responded with {actual_status} to fuzz payload.", None)

    # Default for unknown / llm_generated test types
    if 200 <= actual_status < 300:
        return ("PASS", "N/A", f"API responded with {actual_status}.", None)
    if 400 <= actual_status < 500:
        return ("EXPECTED_FAILURE", "N/A", f"API responded with {actual_status}.", None)
    return ("EXPECTED_FAILURE", "N/A", f"API responded with {actual_status}.", None)


# Map LLM test-case categories to plan test_types
_CATEGORY_TO_TYPE = {
    "positive": "valid_request",
    "negative": "invalid_parameter",
    "edge_case": "invalid_parameter",
    "security": "fuzz_testing",
    "fallback": "valid_request",
}


class APITestingAgent:

    def __init__(self, base_url=None):
        self.base_url = base_url or "http://localhost:8001"
        self.timeout = 10

    # ── Low-level HTTP ────────────────────────────────────────────

    def _make_request(self, method: str, url: str,
                      headers: dict = None, json_body=None) -> dict:
        """Make an HTTP request and return raw response data."""
        print(f"[APITestingAgent] Executing request: {method.upper()} {url}")
        try:
            kwargs = {"method": method.upper(), "url": url, "timeout": self.timeout}
            if headers:
                kwargs["headers"] = headers
            if json_body and method.upper() in ("POST", "PUT", "PATCH"):
                kwargs["json"] = json_body
            start = time.time()
            r = requests.request(**kwargs)
            elapsed = (time.time() - start) * 1000
            return {
                "status_code": r.status_code,
                "response_body": r.text[:2000] if r.text else "",
                "response_headers": dict(r.headers),
                "response_time_ms": round(elapsed, 2),
                "connection_error": False,
                "error": None,
            }
        except requests.exceptions.ConnectionError:
            return {"status_code": None, "response_body": "",
                    "response_headers": {}, "response_time_ms": None,
                    "connection_error": True, "error": "connection refused"}
        except requests.exceptions.Timeout:
            return {"status_code": None, "response_body": "",
                    "response_headers": {}, "response_time_ms": None,
                    "connection_error": True, "error": "timeout"}
        except Exception as e:
            return {"status_code": None, "response_body": "",
                    "response_headers": {}, "response_time_ms": None,
                    "connection_error": False, "error": str(e)}

    def _check_connectivity(self) -> tuple:
        """Check if target API is reachable."""
        print(f"[APITestingAgent] Connectivity check directly hitting: {self.base_url}")
        try:
            r = requests.get(self.base_url, timeout=self.timeout)
            return True, f"reachable (status {r.status_code})"
        except requests.exceptions.ConnectionError:
            return False, "connection refused"
        except requests.exceptions.Timeout:
            return False, "connection timeout"
        except Exception as e:
            return False, str(e)

    # ── Classified test runner ────────────────────────────────────

    def _run_classified_test(self, test_type: str, method: str,
                             url: str, payload: str = None) -> dict:
        """Run a single HTTP test and classify its outcome."""
        resp = self._make_request(method, url)

        if resp["connection_error"]:
            return {
                "test_type": test_type,
                "outcome": "CONNECTION_ERROR",
                "expected_status": None,
                "actual_status": None,
                "note": f"Connection error: {resp['error']}",
                "evidence": None,
                "response_time_ms": None,
            }

        outcome, expected, note, evidence = classify_outcome(
            test_type, resp["status_code"], resp["response_body"], payload
        )

        result = {
            "test_type": test_type,
            "outcome": outcome,
            "expected_status": expected,
            "actual_status": resp["status_code"],
            "note": note,
            "evidence": evidence,
            "response_time_ms": resp["response_time_ms"],
        }
        # Keep raw data for fuzz tests (needed by 500-interpreter)
        if test_type == "fuzz_testing":
            result["response_body"] = resp["response_body"][:500]
            result["response_headers"] = resp["response_headers"]
        return result

    # ── LLM helpers (kept for optional enrichment) ────────────────

    def _interpret_500_response(self, path, method, payload,
                                status_code, response_text,
                                response_headers) -> bool | None:
        """Use LLM to determine if a 500 response is a real vulnerability."""
        system_prompt = (
            "You are an expert API security analyst.\n"
            "Determine whether an HTTP 500 response indicates a real security vulnerability.\n"
            "Respond ONLY in valid JSON."
        )
        user_prompt = f"""Analyze this HTTP 500 response.

Endpoint: {method} {path}
Payload: {payload}
Status: {status_code}
Response (500 chars): {response_text[:500]}
Headers: {dict(response_headers)}

Respond ONLY with:
{{ "real_vulnerability": true or false, "reason": "explanation" }}

Prefer false (benign) if uncertain. Respond ONLY with JSON."""

        try:
            raw = call_llm([
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ])
        except LLMError as e:
            print(f"[APITestingAgent] LLM Error: {e}")
            return None

        parsed = _parse_llm_json(raw, fallback=None)
        return parsed.get("real_vulnerability", None) if parsed else None

    def _heuristic_check(self, expected_logic: str, status: int, body: str) -> bool:
        """Simple fallback when LLM is unavailable."""
        logic_lower = expected_logic.lower()
        if "status_code ==" in logic_lower:
            parts = logic_lower.split("==")
            if len(parts) == 2:
                try:
                    return status == int(parts[1].strip().strip("'\""))
                except ValueError:
                    pass
        if "status_code in" in logic_lower:
            try:
                start = logic_lower.index("[")
                end = logic_lower.index("]") + 1
                vals = json.loads(logic_lower[start:end])
                return status in vals
            except Exception:
                pass
        if "200" in logic_lower:
            return status == 200
        if "401" in logic_lower or "403" in logic_lower:
            return status in [401, 403]
        return status < 400

    # ── Payloads ──────────────────────────────────────────────────

    def _get_payloads_for_endpoint(self, path: str,
                                   planner_fuzz_cats: list = None) -> list:
        """Return payloads relevant to this endpoint."""
        if planner_fuzz_cats:
            cats = planner_fuzz_cats
        else:
            cats = []
            path_lower = path.lower()
            if any(k in path_lower for k in
                   ["user", "account", "order", "profile", "id"]):
                cats.extend(["sql_injection", "auth_bypass"])
            if any(k in path_lower for k in ["search", "query", "filter"]):
                cats.extend(["sql_injection", "xss"])
            if any(k in path_lower for k in
                   ["file", "upload", "download", "doc", "image"]):
                cats.extend(["path_traversal"])
            if not cats:
                cats = ["sql_injection", "xss", "path_traversal", "ssti"]

        payloads = []
        for cat in cats:
            if cat in PAYLOAD_CATEGORIES:
                payloads.extend(PAYLOAD_CATEGORIES[cat])
        return list(dict.fromkeys(payloads))

    # ── BOLA Validation ──────────────────────────────────────────

    def _run_bola_validation(self, endpoint_path: str,
                             method: str) -> dict:
        """
        BOLA validation: compare ID=1 vs ID=2 without auth.
        Returns a single test result dict.
        """
        baseline_path = re.sub(r"\{.*?\}", "1", endpoint_path)
        tampered_path = re.sub(r"\{.*?\}", "2", endpoint_path)
        baseline_url = self.base_url.rstrip("/") + baseline_path
        tampered_url = self.base_url.rstrip("/") + tampered_path

        baseline = self._make_request(method, baseline_url)
        if baseline["connection_error"]:
            return {
                "test_type": "bola_validation",
                "outcome": "CONNECTION_ERROR",
                "expected_status": "403/404 on tampered",
                "actual_status": None,
                "note": f"Connection error on baseline: {baseline['error']}",
                "evidence": None,
                "bola_baseline_status": None,
                "bola_tampered_status": None,
                "bola_response_differs": None,
            }

        tampered = self._make_request(method, tampered_url)
        if tampered["connection_error"]:
            return {
                "test_type": "bola_validation",
                "outcome": "CONNECTION_ERROR",
                "expected_status": "403/404 on tampered",
                "actual_status": None,
                "note": f"Connection error on tampered: {tampered['error']}",
                "evidence": None,
                "bola_baseline_status": baseline["status_code"],
                "bola_tampered_status": None,
                "bola_response_differs": None,
            }

        b_status = baseline["status_code"]
        t_status = tampered["status_code"]
        bodies_differ = baseline["response_body"] != tampered["response_body"]

        if t_status in (403, 404):
            outcome, note, evidence = (
                "EXPECTED_FAILURE",
                f"Auth protected correctly — tampered request returned {t_status}.",
                None,
            )
        elif b_status == 200 and t_status == 200 and bodies_differ:
            outcome, note, evidence = (
                "SECURITY_FAILURE",
                "Endpoint returned different 200 responses for ID=1 and ID=2 without auth.",
                "Endpoint returned different 200 responses for ID=1 and ID=2 without auth",
            )
        elif b_status == 200 and t_status == 200:
            outcome, note, evidence = (
                "EXPECTED_FAILURE",
                "Both requests returned identical 200 — likely static/default resource.",
                None,
            )
        else:
            outcome, note, evidence = (
                "EXPECTED_FAILURE",
                f"Baseline={b_status}, tampered={t_status}.",
                None,
            )

        return {
            "test_type": "bola_validation",
            "outcome": outcome,
            "expected_status": "403/404 on tampered",
            "actual_status": t_status,
            "note": note,
            "evidence": evidence,
            "bola_baseline_status": b_status,
            "bola_tampered_status": t_status,
            "bola_response_differs": bodies_differ,
        }

    # ── Auth Bypass Validation ────────────────────────────────────

    def _run_auth_bypass_validation(self, endpoint_path: str,
                                    method: str) -> list:
        """
        Auth bypass validation: 3 variants (no_token, invalid_token, none_algorithm_jwt).
        Returns a list of test result dicts.
        """
        test_path = re.sub(r"\{.*?\}", "1", endpoint_path)
        url = self.base_url.rstrip("/") + test_path

        variants = [
            ("no_token", {}, "Request without any authorization"),
            ("invalid_token",
             {"Authorization": "Bearer INVALID_TOKEN_SENTINEL_12345"},
             "Request with invalid bearer token"),
            ("none_algorithm_jwt",
             {"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhdHRhY2tlciJ9."},
             "Request with none-algorithm JWT"),
        ]

        results = []
        for variant_name, headers, description in variants:
            resp = self._make_request(method, url, headers=headers)

            if resp["connection_error"]:
                results.append({
                    "test_type": "auth_bypass_validation",
                    "auth_test_variant": variant_name,
                    "outcome": "CONNECTION_ERROR",
                    "expected_status": "401/403",
                    "actual_status": None,
                    "note": f"Connection error: {resp['error']}",
                    "evidence": None,
                    "auth_bypass_detected": False,
                })
                continue

            status = resp["status_code"]
            if 200 <= status < 300:
                sev = ""
                if variant_name == "none_algorithm_jwt":
                    sev = " (CRITICAL — accepts unsigned JWT)"
                results.append({
                    "test_type": "auth_bypass_validation",
                    "auth_test_variant": variant_name,
                    "outcome": "SECURITY_FAILURE",
                    "expected_status": "401/403",
                    "actual_status": status,
                    "note": f"Auth bypass: {description} returned {status}{sev}.",
                    "evidence": f"{description} returned {status}{sev}",
                    "auth_bypass_detected": True,
                })
            else:
                results.append({
                    "test_type": "auth_bypass_validation",
                    "auth_test_variant": variant_name,
                    "outcome": "EXPECTED_FAILURE",
                    "expected_status": "401/403",
                    "actual_status": status,
                    "note": f"Auth correctly blocked: {description} → {status}.",
                    "evidence": None,
                    "auth_bypass_detected": False,
                })

        return results

    # ── Helpers for extracting flagged endpoints ──────────────────

    def _get_bola_flagged_endpoints(self, security_result: dict) -> list:
        """Extract (path, method) tuples flagged for BOLA."""
        eps = set()
        for f in security_result.get("findings", []):
            vuln = (f.get("vulnerability") or "").lower()
            if "bola" in vuln or "broken object" in vuln:
                ep = f.get("endpoint", "")
                if "{" in ep:
                    eps.add((ep, f.get("method", "GET")))
        return list(eps)

    def _get_auth_flagged_endpoints(self, security_result: dict) -> list:
        """Extract (path, method) tuples flagged for auth issues."""
        eps = set()
        for f in security_result.get("findings", []):
            vuln = (f.get("vulnerability") or "").lower()
            if "auth" in vuln or "authentication" in vuln:
                eps.add((f.get("endpoint", ""), f.get("method", "GET")))
        return list(eps)

    # ── LLM test-case runner ──────────────────────────────────────

    def _run_llm_test_case(self, test_case: dict, base_url: str,
                           auth_config: dict = None) -> dict:
        """Execute a single LLM-generated test case with 4-outcome classification."""
        name = test_case.get("name", "unnamed")
        method = test_case.get("method", "GET")
        path = test_case.get("path", "/")
        payload = test_case.get("payload")
        headers = dict(test_case.get("headers", {}))
        expected_logic = test_case.get("expected_logic", "")
        category = test_case.get("category", "positive")
        test_type = _CATEGORY_TO_TYPE.get(category, "valid_request")

        # Apply auth from scan config
        if auth_config:
            if auth_config.get("bearer_token") and "Authorization" not in headers:
                headers["Authorization"] = f"Bearer {auth_config['bearer_token']}"
            if auth_config.get("api_key") and "X-API-Key" not in headers:
                headers["X-API-Key"] = auth_config["api_key"]
            if auth_config.get("basic_username"):
                import base64
                creds = f"{auth_config['basic_username']}:{auth_config.get('basic_password', '')}"
                headers["Authorization"] = f"Basic {base64.b64encode(creds.encode()).decode()}"

        url = base_url.rstrip("/") + path
        json_body = payload if payload and method.upper() in ("POST", "PUT", "PATCH") else None
        resp = self._make_request(method, url, headers=headers, json_body=json_body)

        if resp["connection_error"]:
            return {
                "test_name": name, "test_type": test_type, "category": category,
                "outcome": "CONNECTION_ERROR",
                "expected_status": None, "actual_status": None,
                "note": f"Connection error: {resp['error']}",
                "evidence": None,
                "response_time_ms": None, "auth_used": bool(auth_config),
            }

        outcome, expected, note, evidence = classify_outcome(
            test_type, resp["status_code"], resp["response_body"]
        )

        return {
            "test_name": name, "test_type": test_type, "category": category,
            "outcome": outcome,
            "expected_status": expected, "actual_status": resp["status_code"],
            "note": note, "evidence": evidence,
            "response_time_ms": resp["response_time_ms"],
            "auth_used": bool(auth_config),
            "actual_body_preview": resp["response_body"][:200],
        }

    # ── Main run method ───────────────────────────────────────────

    def run(self, parsed_data: dict, planner_result: dict = None,
            test_generation_result: dict = None, auth_config: dict = None,
            security_result: dict = None) -> dict:
        """
        Run API tests with 4-outcome classification.
        Optionally runs BOLA and auth bypass validation when security_result is provided.
        """
        if "base_url" in parsed_data:
            self.base_url = parsed_data["base_url"]

        # Connectivity pre-check
        reachable, reach_msg = self._check_connectivity()
        if not reachable:
            skeleton_results = []
            for ep in parsed_data.get("endpoints", []):
                skeleton_results.append({
                    "endpoint": ep.get("path"),
                    "method": ep.get("method"),
                    "tests": [{
                        "test_type": "connectivity_check",
                        "outcome": "CONNECTION_ERROR",
                        "note": "API was unreachable — skipped all tests for this endpoint",
                        "actual_status": None,
                        "connection_error": True
                    }]
                })
            return {
                "agent": "api_testing", "status": "skipped",
                "api_was_reachable": False, "base_url_tested": self.base_url,
                "results": skeleton_results, "skip_reason": f"API not reachable: {reach_msg}",
                "security_failure_count": 0, "expected_failure_count": 0,
                "pass_count": 0, "connection_error_count": len(skeleton_results),
            }

        all_tests = []   # flat list — used to compute counters
        results = []     # grouped by endpoint — existing structure

        # ── Phase 1: LLM-generated test cases ─────────────────────
        llm_test_cases = []
        if test_generation_result and test_generation_result.get("test_cases"):
            llm_test_cases = test_generation_result["test_cases"]

        if not llm_test_cases:
            # Fallback health-check tests (no Ollama needed)
            llm_test_cases = [
                {"name": "health_check", "method": "GET", "path": "/health",
                 "payload": None, "headers": {}, "expected_logic": "status_code == 200",
                 "category": "fallback", "target_endpoint": "/health",
                 "target_method": "GET"},
                {"name": "unauthorized_access_blocked", "method": "GET",
                 "path": "/users/1", "payload": None, "headers": {},
                 "expected_logic": "status_code in [401, 403]",
                 "category": "fallback", "target_endpoint": "/users/{user_id}",
                 "target_method": "GET"},
            ]

        # Group by target endpoint
        endpoint_groups = {}
        for tc in llm_test_cases:
            key = (tc.get("target_endpoint", tc.get("path")),
                   tc.get("target_method", tc.get("method")))
            endpoint_groups.setdefault(key, []).append(tc)

        for (ep_path, ep_method), tcs in endpoint_groups.items():
            ep_result = {"endpoint": ep_path, "method": ep_method,
                         "base_url": self.base_url, "tests": []}
            for tc in tcs:
                t = self._run_llm_test_case(tc, self.base_url, auth_config)
                ep_result["tests"].append(t)
                all_tests.append(t)
            results.append(ep_result)

        # ── Phase 2: Static fallback tests ────────────────────────
        if not test_generation_result or not test_generation_result.get("llm_used"):
            planner_fuzz = None
            if planner_result and planner_result.get("plan"):
                planner_fuzz = planner_result["plan"].get(
                    "suggested_fuzz_categories", {})

            for ep in parsed_data.get("endpoints", []):
                path = ep["path"]
                method = ep["method"]
                test_path = re.sub(r"\{.*?\}", "1", path)
                url = self.base_url + test_path

                ep_result = {"endpoint": path, "method": method,
                             "base_url": self.base_url, "tests": []}

                # valid_request
                t = self._run_classified_test("valid_request", method, url)
                ep_result["tests"].append(t)
                all_tests.append(t)

                # invalid_parameter
                if "{" in path:
                    inv_path = re.sub(r"\{.*?\}", "abc", path)
                    t = self._run_classified_test(
                        "invalid_parameter", method, self.base_url + inv_path)
                    ep_result["tests"].append(t)
                    all_tests.append(t)

                # nonexistent_resource
                if "{" in path:
                    ne_path = re.sub(r"\{.*?\}", "999999", path)
                    t = self._run_classified_test(
                        "nonexistent_resource", method, self.base_url + ne_path)
                    ep_result["tests"].append(t)
                    all_tests.append(t)

                # wrong_method
                wrong = "POST" if method != "POST" else "GET"
                t = self._run_classified_test("wrong_method", wrong, url)
                ep_result["tests"].append(t)
                all_tests.append(t)

                # fuzz_testing
                if "{" in path:
                    fuzz_cats = planner_fuzz.get(path) if planner_fuzz else None
                    payloads = self._get_payloads_for_endpoint(path, fuzz_cats)

                    for payload in payloads:
                        fuzz_path = path
                        for param in re.findall(r"\{(.*?)\}", path):
                            fuzz_path = fuzz_path.replace(f"{{{param}}}", payload)
                        fuzz_url = self.base_url + fuzz_path
                        t = self._run_classified_test(
                            "fuzz_testing", method, fuzz_url, payload=payload)

                        # Optional LLM refinement for 500s
                        if (t["actual_status"] and t["actual_status"] >= 500
                                and t["outcome"] == "SECURITY_FAILURE"):
                            llm_result = self._interpret_500_response(
                                path=path, method=method, payload=payload,
                                status_code=t["actual_status"],
                                response_text=t.get("response_body", ""),
                                response_headers=t.get("response_headers", {}),
                            )
                            if llm_result is False:
                                t["outcome"] = "EXPECTED_FAILURE"
                                t["note"] = (f"Server error {t['actual_status']} — "
                                             "LLM assessed as benign.")
                                t["evidence"] = None

                        ep_result["tests"].append(t)
                        all_tests.append(t)

                results.append(ep_result)

        # ── Phase 3: BOLA validation tests ────────────────────────
        if security_result and reachable:
            for ep_path, ep_method in self._get_bola_flagged_endpoints(
                    security_result):
                t = self._run_bola_validation(ep_path, ep_method)
                # Attach to existing endpoint group or create new
                attached = False
                for r in results:
                    if r["endpoint"] == ep_path and r["method"] == ep_method:
                        r["tests"].append(t)
                        attached = True
                        break
                if not attached:
                    results.append({
                        "endpoint": ep_path, "method": ep_method,
                        "base_url": self.base_url, "tests": [t],
                    })
                all_tests.append(t)

        # ── Phase 4: Auth bypass validation tests ─────────────────
        if security_result and reachable:
            for ep_path, ep_method in self._get_auth_flagged_endpoints(
                    security_result):
                auth_tests = self._run_auth_bypass_validation(
                    ep_path, ep_method)
                attached = False
                for r in results:
                    if r["endpoint"] == ep_path and r["method"] == ep_method:
                        r["tests"].extend(auth_tests)
                        attached = True
                        break
                if not attached:
                    results.append({
                        "endpoint": ep_path, "method": ep_method,
                        "base_url": self.base_url, "tests": auth_tests,
                    })
                all_tests.extend(auth_tests)

        # ── Compute counters ──────────────────────────────────────
        sec_fail = sum(1 for t in all_tests
                       if t.get("outcome") == "SECURITY_FAILURE")
        exp_fail = sum(1 for t in all_tests
                       if t.get("outcome") == "EXPECTED_FAILURE")
        passed = sum(1 for t in all_tests
                     if t.get("outcome") == "PASS")
        conn_err = sum(1 for t in all_tests
                       if t.get("outcome") == "CONNECTION_ERROR")

        return {
            "agent": "api_testing",
            "status": "completed",
            "api_was_reachable": True,
            "base_url_tested": self.base_url,
            "auth_used": bool(auth_config),
            "results": results,
            "security_failure_count": sec_fail,
            "expected_failure_count": exp_fail,
            "pass_count": passed,
            "connection_error_count": conn_err,
        }
