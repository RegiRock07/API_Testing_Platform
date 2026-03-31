import os
import re
import json
import time
import requests
from urllib.parse import urljoin
from app.services.llm_service import call_llm, parse_llm_json as _parse_llm_json, LLMError


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
        "\"><script>alert(1)</script>",
    ],
    "path_traversal": [
        "../../etc/passwd",
        "../../../../windows/system32",
        "..\\..\\..\\windows\\system32",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
    ],
    "integer_overflow": [
        "-1",
        "0",
        "9999999999",
        "-9999999999",
    ],
    "null_byte": [
        "%00",
        "\x00",
        "null",
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "{{{{}}}}",
        "<%= 7*7 %>",
    ],
    "auth_bypass": [
        "admin",
        "administrator",
        "root",
        "null",
        "undefined",
    ],
}


class APITestingAgent:

    def __init__(self, base_url=None):
        self.base_url = base_url or "http://localhost:8001"
        self.timeout = 5

    def _interpret_500_response(
        self,
        path: str,
        method: str,
        payload: str,
        status_code: int,
        response_text: str,
        response_headers: dict,
    ) -> bool | None:
        """Use LLM to determine if a 500 response is a real vulnerability or benign."""
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
            raw = None

        if raw is None:
            return None
        parsed = _parse_llm_json(raw, fallback=None)
        return parsed.get("real_vulnerability", None) if parsed else None

    def _mini_evaluator(self, test_name: str, method: str, path: str,
                         actual_status: int, actual_body: str,
                         actual_headers: dict, expected_logic: str) -> dict:
        """
        Mini-Evaluator: Use LLM to compare actual response against expected_logic.
        Returns {passed: bool, reason: str, assertion_matched: bool}
        """
        system_prompt = (
            "You are an expert API test evaluator.\n"
            "Given a test case and actual response, determine if the test PASSED or FAILED.\n"
            "Respond ONLY in valid JSON."
        )

        user_prompt = f"""Evaluate this API test result:

Test Name: {test_name}
Method: {method}
Path: {path}
Expected Logic: {expected_logic}

Actual HTTP Status: {actual_status}
Actual Response Body (1000 chars): {actual_body[:1000]}
Actual Response Headers: {dict(actual_headers)}

Rules:
- Evaluate expected_logic as a Python-like predicate where you substitute actual values
- Examples: "status_code == 200" means pass if status is 200
- Examples: "'id' in response" means pass if 'id' appears in body
- Examples: "status_code in [401, 403]" means pass if status is 401 or 403
- Be strict: a test PASSES only if the expected_logic is clearly satisfied
- If expected_logic is ambiguous, evaluate conservatively

Respond ONLY with this exact JSON (no markdown, no explanation):
{{
  "passed": true or false,
  "assertion_matched": true or false,
  "reason": "2-3 sentence explanation of why this passed or failed"
}}

Respond ONLY with the JSON object."""

        try:
            raw = call_llm([
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ])
        except LLMError as e:
            print(f"[APITestingAgent] LLM Error: {e}")
            raw = None

        if raw is None:
            # Fallback: LLM unavailable — use simple heuristic
            try:
                assertion_matched = self._heuristic_check(expected_logic, actual_status, actual_body)
                return {
                    "passed": assertion_matched,
                    "assertion_matched": assertion_matched,
                    "reason": "LMMM unavailable, used heuristic fallback"
                }
            except Exception:
                return {
                    "passed": actual_status < 400,
                    "assertion_matched": actual_status < 400,
                    "reason": "LMMM unavailable, defaulted to status < 400"
                }

        parsed = _parse_llm_json(raw, fallback=None)
        if not parsed:
            return {
                "passed": actual_status < 400,
                "assertion_matched": actual_status < 400,
                "reason": "Parse failed, defaulted to status < 400"
            }

        return {
            "passed": bool(parsed.get("passed", actual_status < 400)),
            "assertion_matched": bool(parsed.get("assertion_matched", actual_status < 400)),
            "reason": str(parsed.get("reason", ""))
        }

    def _heuristic_check(self, expected_logic: str, status: int, body: str) -> bool:
        """Simple fallback when LLM is unavailable."""
        logic_lower = expected_logic.lower()
        if "status_code ==" in logic_lower or "status_code ==" in logic_lower:
            parts = logic_lower.split("==")
            if len(parts) == 2:
                expected_val = parts[1].strip().strip("'\"")
                try:
                    return status == int(expected_val)
                except ValueError:
                    pass
        if "status_code in" in logic_lower:
            try:
                start = logic_lower.index("[")
                end = logic_lower.index("]") + 1
                vals = eval(logic_lower[start:end])
                return status in vals
            except Exception:
                pass
        if "200" in logic_lower:
            return status == 200
        if "401" in logic_lower or "403" in logic_lower:
            return status in [401, 403]
        return status < 400

    def _check_connectivity(self) -> tuple[bool, str]:
        """Check if target API is reachable."""
        try:
            r = requests.get(self.base_url, timeout=self.timeout)
            return True, f"reachable (status {r.status_code})"
        except requests.exceptions.ConnectionError:
            return False, "connection refused"
        except requests.exceptions.Timeout:
            return False, "connection timeout"
        except Exception as e:
            return False, str(e)

    def _get_payloads_for_endpoint(self, path: str, planner_fuzz_cats: list = None) -> list:
        """Return payloads relevant to this endpoint."""
        if planner_fuzz_cats:
            cats = planner_fuzz_cats
        else:
            cats = []
            path_lower = path.lower()
            if any(k in path_lower for k in ["user", "account", "order", "profile", "id"]):
                cats.extend(["sql_injection", "auth_bypass"])
            if any(k in path_lower for k in ["search", "query", "filter"]):
                cats.extend(["sql_injection", "xss"])
            if any(k in path_lower for k in ["file", "upload", "download", "doc", "image"]):
                cats.extend(["path_traversal"])
            if not cats:
                cats = ["sql_injection", "xss", "path_traversal", "ssti"]

        payloads = []
        for cat in cats:
            if cat in PAYLOAD_CATEGORIES:
                payloads.extend(PAYLOAD_CATEGORIES[cat])
        return list(dict.fromkeys(payloads))

    def _run_llm_test_case(self, test_case: dict, base_url: str,
                           auth_config: dict = None) -> dict:
        """
        Execute a single LLM-generated test case using httpx and evaluate with Mini-Evaluator.
        """
        name = test_case.get("name", "unnamed")
        method = test_case.get("method", "GET")
        path = test_case.get("path", "/")
        payload = test_case.get("payload")
        headers = test_case.get("headers", {})
        expected_logic = test_case.get("expected_logic", "")

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

        try:
            start_time = time.time()
            kwargs = {"method": method.upper(), "url": url, "headers": headers, "timeout": self.timeout}
            if payload and method.upper() in ["POST", "PUT", "PATCH"]:
                kwargs["json"] = payload

            r = requests.request(**kwargs)
            elapsed_ms = (time.time() - start_time) * 1000

            status_code = r.status_code
            response_body = r.text[:1000]
            response_headers = dict(r.headers)
            connection_error = False

        except requests.exceptions.ConnectionError:
            return {
                "test_name": name,
                "test_type": "llm_generated",
                "category": test_case.get("category", "unknown"),
                "passed": False,
                "connection_error": True,
                "auth_used": bool(auth_config),
                "status_code": None,
                "response_time_ms": None,
                "note": "connection refused — endpoint unreachable",
                "assertion_matched": None,
                "reason": "Target API is unreachable"
            }
        except requests.exceptions.Timeout:
            return {
                "test_name": name,
                "test_type": "llm_generated",
                "category": test_case.get("category", "unknown"),
                "passed": False,
                "connection_error": True,
                "auth_used": bool(auth_config),
                "status_code": None,
                "response_time_ms": None,
                "note": "request timed out",
                "assertion_matched": None,
                "reason": "Request timed out"
            }
        except Exception as e:
            return {
                "test_name": name,
                "test_type": "llm_generated",
                "category": test_case.get("category", "unknown"),
                "passed": False,
                "connection_error": False,
                "auth_used": bool(auth_config),
                "status_code": None,
                "response_time_ms": None,
                "note": str(e),
                "assertion_matched": None,
                "reason": f"Request error: {e}"
            }

        # Mini-Evaluator: LLM compares actual response to expected_logic
        evaluation = self._mini_evaluator(
            test_name=name,
            method=method,
            path=path,
            actual_status=status_code,
            actual_body=response_body,
            actual_headers=response_headers,
            expected_logic=expected_logic
        )

        return {
            "test_name": name,
            "test_type": "llm_generated",
            "category": test_case.get("category", "unknown"),
            "passed": evaluation["passed"],
            "connection_error": connection_error,
            "auth_used": bool(auth_config),
            "status_code": status_code,
            "response_time_ms": round(elapsed_ms, 2) if elapsed_ms else None,
            "note": evaluation["reason"],
            "assertion_matched": evaluation["assertion_matched"],
            "expected_logic": expected_logic,
            "actual_body_preview": response_body[:200]
        }

    def run(self, parsed_data: dict, planner_result: dict = None,
            test_generation_result: dict = None, auth_config: dict = None) -> dict:
        """
        Run API tests: LLM-generated test cases + fallback static tests.
        """
        if "base_url" in parsed_data:
            self.base_url = parsed_data["base_url"]

        # Step 1: Connectivity pre-check
        reachable, reach_msg = self._check_connectivity()
        if not reachable:
            return {
                "agent": "api_testing",
                "status": "skipped",
                "api_was_reachable": False,
                "base_url_tested": self.base_url,
                "results": [],
                "skip_reason": f"API not reachable: {reach_msg}"
            }

        # Collect LLM-generated test cases
        llm_test_cases = []
        if test_generation_result and test_generation_result.get("test_cases"):
            llm_test_cases = test_generation_result["test_cases"]

        # If no LLM test cases (Ollama down → fallback), use default health checks
        if not llm_test_cases:
            llm_test_cases = [
                {
                    "name": "health_check",
                    "method": "GET",
                    "path": "/health",
                    "payload": None,
                    "headers": {},
                    "expected_logic": "status_code == 200",
                    "category": "fallback",
                    "target_endpoint": "/health",
                    "target_method": "GET"
                },
                {
                    "name": "unauthorized_access_blocked",
                    "method": "GET",
                    "path": "/users/1",
                    "payload": None,
                    "headers": {},
                    "expected_logic": "status_code in [401, 403] or 'id' not in response",
                    "category": "fallback",
                    "target_endpoint": "/users/{user_id}",
                    "target_method": "GET"
                }
            ]

        # Group test cases by their target_endpoint for results structure
        endpoint_groups = {}
        for tc in llm_test_cases:
            key = (tc.get("target_endpoint", tc.get("path")), tc.get("target_method", tc.get("method")))
            if key not in endpoint_groups:
                endpoint_groups[key] = []
            endpoint_groups[key].append(tc)

        results = []
        total_llm_tests = 0
        passed_llm_tests = 0

        for (endpoint_path, method), test_cases in endpoint_groups.items():
            endpoint_result = {
                "endpoint": endpoint_path,
                "method": method,
                "base_url": self.base_url,
                "tests": []
            }

            for tc in test_cases:
                total_llm_tests += 1
                test_outcome = self._run_llm_test_case(tc, self.base_url, auth_config)
                endpoint_result["tests"].append(test_outcome)
                if test_outcome["passed"]:
                    passed_llm_tests += 1

            results.append(endpoint_result)

        # ── Static fallback tests (only when no LLM cases were generated) ──
        if not test_generation_result or not test_generation_result.get("llm_used"):
            planner_fuzz = None
            if planner_result and planner_result.get("plan"):
                planner_fuzz = planner_result["plan"].get("suggested_fuzz_categories", {})

            for ep in parsed_data.get("endpoints", []):
                path = ep["path"]
                method = ep["method"]
                test_path = re.sub(r"\{.*?\}", "1", path)
                url = self.base_url + test_path

                endpoint_result = {
                    "endpoint": path,
                    "method": method,
                    "base_url": self.base_url,
                    "tests": []
                }

                # 1. Valid Request
                result = self._run_static_test(method, url)
                endpoint_result["tests"].append({"test": "valid_request", **result})

                # 2. Invalid Parameter
                if "{" in path:
                    invalid_path = re.sub(r"\{.*?\}", "abc", path)
                    result = self._run_static_test(method, self.base_url + invalid_path)
                    endpoint_result["tests"].append({"test": "invalid_parameter", **result})

                # 3. Nonexistent Resource
                if "{" in path:
                    invalid_path = re.sub(r"\{.*?\}", "999999", path)
                    result = self._run_static_test(method, self.base_url + invalid_path)
                    endpoint_result["tests"].append({"test": "nonexistent_resource", **result})

                # 4. Wrong HTTP Method
                wrong_method = "POST" if method != "POST" else "GET"
                result = self._run_static_test(wrong_method, url)
                endpoint_result["tests"].append({"test": "wrong_method", **result})

                # 5. Context-aware fuzz
                if "{" in path:
                    fuzz_cats = planner_fuzz.get(path) if planner_fuzz else None
                    payloads = self._get_payloads_for_endpoint(path, fuzz_cats)
                    fuzz_results = []

                    for payload in payloads:
                        fuzz_path = path
                        for param in re.findall(r"\{(.*?)\}", path):
                            fuzz_path = fuzz_path.replace(f"{{{param}}}", payload)
                        fuzz_url = self.base_url + fuzz_path
                        result = self._run_static_test(method, fuzz_url)

                        possible_vuln = False
                        interpretation_note = None

                        if result.get("status_code") and result["status_code"] >= 500:
                            llm_result = self._interpret_500_response(
                                path=path, method=method, payload=payload,
                                status_code=result["status_code"],
                                response_text=result.get("response_body", ""),
                                response_headers=result.get("response_headers", {})
                            )
                            if llm_result is True:
                                possible_vuln = True
                                interpretation_note = "LLM confirmed: real vulnerability"
                            elif llm_result is False:
                                interpretation_note = "LLM confirmed: benign crash"
                            else:
                                possible_vuln = True
                                interpretation_note = "LLM unavailable, flagged as potential"
                        elif result.get("error") and not result.get("connection_error"):
                            possible_vuln = True
                            interpretation_note = "Non-connection error flagged as potential"

                        fuzz_results.append({
                            "payload": payload,
                            "url": fuzz_url,
                            "status_code": result.get("status_code"),
                            "error": result.get("error"),
                            "possible_vulnerability": possible_vuln,
                            "interpretation_note": interpretation_note,
                        })

                    vulnerable_count = len([f for f in fuzz_results if f["possible_vulnerability"]])
                    endpoint_result["tests"].append({
                        "test": "dynamic_fuzz_testing",
                        "total_payloads": len(fuzz_results),
                        "vulnerable_count": vulnerable_count,
                        "passed": vulnerable_count == 0,
                        "results": fuzz_results
                    })

                results.append(endpoint_result)

        return {
            "agent": "api_testing",
            "status": "completed",
            "api_was_reachable": True,
            "base_url_tested": self.base_url,
            "auth_used": bool(auth_config),
            "results": results,
            "llm_generated_tests_run": total_llm_tests,
            "llm_generated_tests_passed": passed_llm_tests,
        }

    def _run_static_test(self, method: str, url: str, **kwargs):
        """Make a request for static tests."""
        try:
            r = requests.request(method=method, url=url, timeout=self.timeout, **kwargs)
            return {
                "passed": r.status_code < 400,
                "status_code": r.status_code,
                "error": None,
                "connection_error": False,
                "response_body": r.text[:500] if r.text else "",
                "response_headers": dict(r.headers),
            }
        except requests.exceptions.ConnectionError:
            return {
                "passed": False, "status_code": None, "error": "connection refused",
                "connection_error": True, "response_body": "", "response_headers": {},
            }
        except requests.exceptions.Timeout:
            return {
                "passed": False, "status_code": None, "error": "timeout",
                "connection_error": True, "response_body": "", "response_headers": {},
            }
        except Exception as e:
            return {
                "passed": False, "status_code": None, "error": str(e),
                "connection_error": False, "response_body": "", "response_headers": {},
            }
