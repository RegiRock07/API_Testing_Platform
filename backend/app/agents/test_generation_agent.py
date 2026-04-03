# backend/app/agents/test_generation_agent.py
#
# Generates targeted test cases for each endpoint using the LLM.
# The APITestingAgent in Step 5 will use these cases to run smarter,
# context-aware tests instead of generic fuzz payloads only.
#
# Falls back to a set of standard rule-based test cases if LLM fails,
# so the pipeline always has something to work with.

import json
import logging

from app.services.llm_service import call_llm, parse_llm_json, LLMError

logger = logging.getLogger(__name__)


class TestGeneratorAgent:

    # ── Rule-based fallback ───────────────────────────────────────
    # Generates standard test cases without LLM.

    @staticmethod
    def _fallback_cases_for_endpoint(endpoint: dict) -> list:
        path   = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        cases  = []

        # Always include a valid request test
        cases.append({
            "name":           "valid_request",
            "method":         method,
            "path":           path,
            "payload":        None,
            "headers":        {},
            "expected_logic": "status_code < 400",
            "category":       "positive",
            "target_endpoint": path,
            "target_method":   method,
        })

        # For parameterized paths add negative + nonexistent tests
        if "{" in path:
            cases.append({
                "name":           "invalid_parameter_type",
                "method":         method,
                "path":           path.replace("{" + path.split("{")[1].split("}")[0] + "}", "abc"),
                "payload":        None,
                "headers":        {},
                "expected_logic": "status_code in [400, 422]",
                "category":       "negative",
                "target_endpoint": path,
                "target_method":   method,
            })
            cases.append({
                "name":           "nonexistent_resource",
                "method":         method,
                "path":           path.replace("{" + path.split("{")[1].split("}")[0] + "}", "999999"),
                "payload":        None,
                "headers":        {},
                "expected_logic": "status_code == 404",
                "category":       "negative",
                "target_endpoint": path,
                "target_method":   method,
            })

        # Wrong method test
        wrong_method = "POST" if method != "POST" else "GET"
        cases.append({
            "name":           "wrong_http_method",
            "method":         wrong_method,
            "path":           path,
            "payload":        None,
            "headers":        {},
            "expected_logic": "status_code == 405",
            "category":       "negative",
            "target_endpoint": path,
            "target_method":   method,
        })

        return cases

    # ── LLM generation for a single endpoint ─────────────────────

    def _generate_for_endpoint(self, endpoint: dict, all_endpoints: list) -> list:
        path         = endpoint.get("path", "")
        method       = endpoint.get("method", "GET")
        summary      = endpoint.get("summary", "")
        parameters   = endpoint.get("parameters", [])
        request_body = endpoint.get("request_body", {})
        responses    = endpoint.get("responses", [])

        system_prompt = (
            "You are an expert API security tester.\n"
            "Generate specific test cases for the given endpoint.\n"
            "Respond ONLY with a valid JSON array. No explanation, no markdown."
        )

        user_prompt = f"""Generate test cases for this API endpoint:

Endpoint: {method} {path}
Summary: {summary}
Parameters: {json.dumps(parameters, indent=2)}
Request Body: {json.dumps(request_body, indent=2)}
Expected Responses: {responses}

Generate between 3 and 5 test cases covering:
1. POSITIVE: valid request that should succeed
2. NEGATIVE: wrong types, missing fields
3. EDGE_CASE: empty strings, null, very large numbers, special chars
4. SECURITY: auth bypass attempts, injection payloads

Respond ONLY with a JSON array like:
[
  {{
    "name": "descriptive_test_name",
    "method": "GET",
    "path": "/actual/path/here",
    "payload": null,
    "headers": {{}},
    "expected_logic": "status_code == 200",
    "category": "positive"
  }}
]

Do not add any text before or after the JSON array."""

        try:
            raw = call_llm([
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ])
        except LLMError as e:
            logger.warning(f"[TestGen] LLM failed for {method} {path}: {e}")
            return self._fallback_cases_for_endpoint(endpoint)

        parsed = parse_llm_json(raw, fallback=None)
        if not isinstance(parsed, list) or not parsed:
            logger.warning(f"[TestGen] LLM returned invalid format for {method} {path}, using fallback")
            return self._fallback_cases_for_endpoint(endpoint)

        # Validate and normalise each case
        valid_cases = []
        for tc in parsed:
            if not isinstance(tc, dict):
                continue
            if not tc.get("name") or not tc.get("method") or not tc.get("path"):
                continue
            valid_cases.append({
                "name":            str(tc.get("name")),
                "method":          str(tc.get("method", method)).upper(),
                "path":            str(tc.get("path", path)),
                "payload":         tc.get("payload"),
                "headers":         tc.get("headers", {}),
                "expected_logic":  str(tc.get("expected_logic", "")),
                "category":        tc.get("category", "positive"),
                "target_endpoint": path,
                "target_method":   method,
            })

        # Always fall back to rule-based if LLM gave us nothing usable
        if not valid_cases:
            return self._fallback_cases_for_endpoint(endpoint)

        return valid_cases

    # ── Main run ──────────────────────────────────────────────────

    def run(self, parsed_data: dict, planner_result: dict = None) -> dict:
        endpoints = parsed_data.get("endpoints", [])

        if not endpoints:
            return {
                "agent":                "test_generation",
                "status":               "skipped",
                "llm_used":             False,
                "test_cases_generated": 0,
                "test_cases":           [],
            }

        all_cases = []
        llm_used  = False

        for endpoint in endpoints:
            cases = self._generate_for_endpoint(endpoint, endpoints)
            # Mark whether any LLM cases came through
            if any(c.get("category") not in ("positive", "negative") for c in cases):
                llm_used = True
            # Tag each case with source endpoint for the testing agent
            for c in cases:
                c.setdefault("target_endpoint", endpoint["path"])
                c.setdefault("target_method",   endpoint["method"])
            all_cases.extend(cases)

        logger.info(
            f"[TestGen] Generated {len(all_cases)} test cases "
            f"for {len(endpoints)} endpoints (llm_used={llm_used})"
        )

        return {
            "agent":                "test_generation",
            "status":               "completed",
            "llm_used":             llm_used,
            "test_cases_generated": len(all_cases),
            "test_cases":           all_cases,
        }