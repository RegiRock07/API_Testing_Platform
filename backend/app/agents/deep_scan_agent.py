# backend/app/agents/deep_scan_agent.py
#
# Runs only when the orchestrator's conditional edge decides there are
# enough serious findings (any CRITICAL, 2+ HIGH or 3+ MEDIUM).
#
# Picks the most severe findings (CRITICAL > HIGH > MEDIUM, then by
# confidence) and asks the LLM for a proof-of-concept exploit scenario.
# If the LLM is unavailable or returns bad JSON, a rule-based PoC is
# attached instead, like every other LLM agent's fallback. Each PoC
# records which one produced it in `exploit_poc.generated_by`.
# The agent never crashes the pipeline.

import logging
import re

from app.services.llm_service import call_llm, parse_llm_json, LLMError

logger = logging.getLogger(__name__)

MAX_FINDINGS_TO_ENRICH = 2

SEVERITY_RANK   = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}
CONFIDENCE_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _example_path(endpoint: str) -> str:
    """/users/{user_id}/orders -> /users/1/orders"""
    return re.sub(r"\{[^}]+\}", "1", endpoint or "/")


def build_fallback_poc(finding: dict, base_url: str = "") -> dict:
    """Rule-based PoC text, keyed on the finding's risk type."""
    endpoint = finding.get("endpoint", "/")
    method   = (finding.get("method") or "GET").upper()
    risk     = (finding.get("risk_type") or finding.get("vulnerability") or "").lower()
    target   = (base_url or "https://target").rstrip("/")
    url      = target + _example_path(endpoint)
    body     = " -H 'Content-Type: application/json' -d '{}'" if method in ("POST", "PUT", "PATCH") else ""
    curl     = f"curl -i -X {method} '{url}'{body}"

    if "bola" in risk or "object id" in risk:
        other = re.sub(r"\{[^}]+\}", "2", endpoint)
        return {
            "summary": f"Access another user's object through {method} {endpoint} by changing the ID in the path.",
            "steps": [
                f"Step 1: Authenticate as user A and call {method} {_example_path(endpoint)} for A's own object.",
                f"Step 2: Repeat the request with another object's ID ({other}) using user A's credentials.",
                "Step 3: Compare the responses: if B's data comes back, object-level authorization is missing.",
            ],
            "sample_curl": f"curl -i -X {method} '{target}{other}' -H 'Authorization: Bearer <user-A-token>'",
            "expected_vulnerable_response": "200 OK with another user's object in the body.",
            "verification_test": "The same request returns 403 or 404 for objects the caller does not own.",
        }
    if "authentication" in risk or "auth" in risk:
        return {
            "summary": f"Call {method} {endpoint} without any credentials.",
            "steps": [
                "Step 1: Send the request with no Authorization header, cookie or API key.",
                "Step 2: Check whether the operation succeeds (2xx) or changes server state.",
            ],
            "sample_curl": curl,
            "expected_vulnerable_response": "2xx response: the operation runs for an anonymous caller.",
            "verification_test": "The unauthenticated request returns 401, and the spec declares a security scheme for it.",
        }
    if "data exposure" in risk or "excessive" in risk:
        return {
            "summary": f"Check whether {method} {endpoint} returns more fields than the client needs.",
            "steps": [
                f"Step 1: Call {method} {_example_path(endpoint)} as a low-privilege user.",
                "Step 2: Look for sensitive fields (emails, roles, internal IDs, hashes, tokens) in the response.",
            ],
            "sample_curl": curl,
            "expected_vulnerable_response": "Response includes sensitive or internal fields not shown in the UI.",
            "verification_test": "The response contains only the fields the caller's role needs (allow-listed response model).",
        }
    if "rate limit" in risk:
        return {
            "summary": f"Send a burst of requests to {method} {endpoint} and check for throttling.",
            "steps": [
                "Step 1: Send 50+ identical requests in a few seconds.",
                "Step 2: Check whether any request is rejected with 429 Too Many Requests.",
            ],
            "sample_curl": f"for i in $(seq 1 50); do {curl} -o /dev/null -s -w '%{{http_code}}\\n'; done",
            "expected_vulnerable_response": "Every request succeeds; no 429 and no Retry-After header.",
            "verification_test": "Requests beyond the limit return 429 with a Retry-After header.",
        }
    return {
        "summary": f"Manually verify the '{finding.get('risk_type', 'reported')}' issue on {method} {endpoint}.",
        "steps": [
            f"Step 1: Reproduce a normal {method} request to {_example_path(endpoint)}.",
            "Step 2: Modify the request according to the finding description and compare responses.",
        ],
        "sample_curl": curl,
        "expected_vulnerable_response": "Behaviour matches the finding description.",
        "verification_test": "The modified request is rejected with a 4xx status.",
    }


class DeepScanAgent:

    def run(self, security_result: dict, base_url: str = "") -> dict:
        findings = security_result.get("findings", [])

        if not findings:
            return {
                "agent":               "deep_scan",
                "status":              "skipped",
                "deep_scan_performed": False,
                "llm_used":            False,
                "findings_enriched":   [],
                "note":                "No findings to enrich",
            }

        # Most severe first; confidence breaks ties. LOW is never enriched.
        priority_findings = sorted(
            (f for f in findings if f.get("severity") in SEVERITY_RANK),
            key=lambda f: (SEVERITY_RANK[f["severity"]],
                           CONFIDENCE_RANK.get(f.get("confidence"), 0)),
            reverse=True,
        )[:MAX_FINDINGS_TO_ENRICH]

        if not priority_findings:
            return {
                "agent":               "deep_scan",
                "status":              "skipped",
                "deep_scan_performed": False,
                "llm_used":            False,
                "findings_enriched":   [],
                "note":                "No CRITICAL/HIGH/MEDIUM findings to enrich",
            }

        logger.info(f"[DeepScan] Enriching {len(priority_findings)} priority findings")

        system_prompt = (
            "You are an expert penetration tester.\n"
            "Generate a proof-of-concept exploit scenario for a security finding.\n"
            "Respond ONLY with valid JSON. No explanation, no markdown."
        )

        enriched_findings = []
        llm_count = 0

        for finding in priority_findings:
            endpoint    = finding.get("endpoint", "unknown")
            method      = (finding.get("method") or "GET").upper()
            risk_type   = finding.get("risk_type", finding.get("vulnerability", "Unknown"))
            severity    = finding.get("severity", "MEDIUM")
            description = finding.get("description", "")

            user_prompt = f"""Generate a proof-of-concept exploit for this security finding:

Endpoint: {method} {endpoint}
Risk Type: {risk_type}
Severity: {severity}
Description: {description}

Respond ONLY with a valid JSON object:
{{
  "exploit_poc": {{
    "summary": "One sentence describing what the exploit does",
    "steps": [
      "Step 1: what the attacker does",
      "Step 2: what the attacker does"
    ],
    "sample_curl": "curl -X {method} 'https://target{endpoint}' -H 'Content-Type: application/json'",
    "expected_vulnerable_response": "What a vulnerable server returns",
    "verification_test": "How to verify this is fixed"
  }}
}}

Do not include any text before or after the JSON."""

            enriched = dict(finding)  # copy; keeps the finding's `id`
            poc = None

            try:
                raw = call_llm([
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_prompt},
                ])
                parsed = parse_llm_json(raw, fallback=None)
                if isinstance(parsed, dict) and isinstance(parsed.get("exploit_poc"), dict):
                    poc = {**parsed["exploit_poc"], "generated_by": "llm"}
                    llm_count += 1
                    logger.info(f"[DeepScan] LLM PoC generated for {method} {endpoint}")
                else:
                    logger.warning(f"[DeepScan] LLM returned invalid format for {method} {endpoint}")
            except LLMError as e:
                logger.warning(f"[DeepScan] LLM failed for {method} {endpoint}: {e}")
            except Exception as e:
                logger.warning(f"[DeepScan] Unexpected error for {method} {endpoint}: {e}")

            if poc is None:
                poc = {**build_fallback_poc(finding, base_url), "generated_by": "rule_based"}

            enriched["exploit_poc"] = poc
            enriched_findings.append(enriched)

        logger.info(
            f"[DeepScan] Completed — enriched {len(enriched_findings)} findings "
            f"({llm_count} via LLM)"
        )

        return {
            "agent":               "deep_scan",
            "status":              "completed",
            "deep_scan_performed": True,
            "llm_used":            llm_count > 0,
            "findings_enriched":   enriched_findings,
        }
