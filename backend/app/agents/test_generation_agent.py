import os
import json
import requests
from typing import TypedDict


def parse_llm_json(raw_text: str, fallback=None):
    """Strip markdown fences and parse LLM JSON response."""
    try:
        text = raw_text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        text = text.strip()
        return json.loads(text)
    except Exception as e:
        print(f"[TestGeneratorAgent] LLM JSON parse failed: {e}")
        return fallback


# ─────────────────────────────────────────
# Fallback: static test suite when Ollama is unavailable
# ─────────────────────────────────────────

FALLBACK_TEST_CASES = [
    {
        "name": "health_check",
        "method": "GET",
        "path": "/health",
        "payload": None,
        "headers": {},
        "expected_logic": "status_code == 200 and response contains 'status' or 'healthy'"
    },
    {
        "name": "openapi_spec_accessible",
        "method": "GET",
        "path": "/openapi.json",
        "payload": None,
        "headers": {},
        "expected_logic": "status_code == 200 and valid JSON with 'paths' key"
    },
    {
        "name": "unauthorized_access_blocked",
        "method": "GET",
        "path": "/users/1",
        "payload": None,
        "headers": {},
        "expected_logic": "status_code in [401, 403] or response does not contain sensitive user data"
    }
]


class TestGeneratorAgent:

    def __init__(self):
        self.ollama_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self.model = os.getenv("TEST_GENERATION_MODEL", os.getenv("OLLAMA_DEFAULT_MODEL", "llama3.1:8b"))
        self.timeout = int(os.getenv("OLLAMA_TIMEOUT", "60"))

    def _call_llm(self, messages: list) -> str | None:
        try:
            response = requests.post(
                f"{self.ollama_url}/api/chat",
                json={"model": self.model, "messages": messages, "stream": False},
                timeout=self.timeout
            )
            response.raise_for_status()
            return response.json()["message"]["content"]
        except Exception as e:
            print(f"[TestGeneratorAgent] Ollama call failed: {e}")
            return None

    def _generate_for_endpoint(self, endpoint: dict, all_endpoints: list) -> list:
        """Generate 5-10 test cases for a single endpoint using LLM."""
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        summary = endpoint.get("summary", "")
        parameters = endpoint.get("parameters", [])
        request_body = endpoint.get("requestBody", {})
        responses = endpoint.get("responses", [])

        system_prompt = (
            "You are an expert API security tester.\n"
            "For the given endpoint, generate a JSON array of 5-10 specific test cases.\n"
            "Each test must be one of these categories: positive, negative, edge_case, security.\n"
            "Respond ONLY with a valid JSON array. No explanation, no markdown."
        )

        user_prompt = f"""Generate test cases for this API endpoint:

Endpoint: {method} {path}
Summary: {summary}
Parameters: {json.dumps(parameters, indent=2)}
Request Body: {json.dumps(request_body, indent=2)}
Expected Responses: {responses}

All endpoints in this API ({len(all_endpoints)} total):
{json.dumps(all_endpoints, indent=2)[:3000]}

For each test case provide:
- name: short descriptive string (e.g. "valid_user_id_returns_200")
- method: HTTP method (use same as endpoint or alter for wrong_method tests)
- path: the URL path (keep same or modify for edge cases like /users/999999)
- payload: dict of body fields OR None
- headers: dict (e.g. {{"Authorization": "Bearer <token>"}} OR leave empty {{}})
- expected_logic: string describing pass condition (e.g. "status_code == 200 and 'id' in response")

Test case categories to cover:
1. POSITIVE (happy path): valid request that should succeed
2. NEGATIVE (wrong data types): wrong parameter types, missing required fields
3. EDGE CASES: max/min values, empty strings, null bytes, very large numbers
4. SECURITY: auth bypass attempts, injection payloads, rate limit probes

Respond ONLY with a JSON array of test case objects like:
[
  {{
    "name": "string",
    "method": "string",
    "path": "string",
    "payload": dict_or_null,
    "headers": dict,
    "expected_logic": "string",
    "category": "positive|negative|edge_case|security"
  }}
]

Return between 5 and 10 test cases total for this endpoint.
Do not add any text before or after the JSON array."""

        raw = self._call_llm([
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ])

        if raw is None:
            return []

        parsed = parse_llm_json(raw, fallback=[])
        if not isinstance(parsed, list):
            return []

        # Validate and sanitize each test case
        valid_cases = []
        for tc in parsed:
            if not isinstance(tc, dict):
                continue
            if not tc.get("name") or not tc.get("method") or not tc.get("path"):
                continue
            valid_cases.append({
                "name": str(tc.get("name")),
                "method": str(tc.get("method", method)).upper(),
                "path": str(tc.get("path", path)),
                "payload": tc.get("payload") if tc.get("payload") is not None else None,
                "headers": tc.get("headers", {}),
                "expected_logic": str(tc.get("expected_logic", "")),
                "category": tc.get("category", "positive"),
                "target_endpoint": path,
                "target_method": method
            })
        return valid_cases

    def run(self, parsed_data: dict, planner_result: dict = None) -> dict:
        """
        Generate LLM-driven test cases for all endpoints.

        Args:
            parsed_data: full parsed OpenAPI spec
            planner_result: optional planner output for context

        Returns:
            {
                "agent": "test_generation",
                "status": "completed" | "skipped",
                "llm_used": bool,
                "test_cases_generated": int,
                "test_cases": [...]
            }
        """
        endpoints = parsed_data.get("endpoints", [])
        if not endpoints:
            return {
                "agent": "test_generation",
                "status": "skipped",
                "llm_used": False,
                "test_cases_generated": 0,
                "test_cases": []
            }

        all_cases = []
        for endpoint in endpoints:
            cases = self._generate_for_endpoint(endpoint, endpoints)
            all_cases.extend(cases)

        if not all_cases:
            # Ollama unavailable — use fallback
            return {
                "agent": "test_generation",
                "status": "skipped",
                "llm_used": False,
                "test_cases_generated": len(FALLBACK_TEST_CASES),
                "test_cases": [
                    {**tc, "target_endpoint": tc["path"], "target_method": tc["method"], "category": "fallback"}
                    for tc in FALLBACK_TEST_CASES
                ]
            }

        return {
            "agent": "test_generation",
            "status": "completed",
            "llm_used": True,
            "test_cases_generated": len(all_cases),
            "test_cases": all_cases
        }
