# backend/app/agents/deep_scan_agent.py
#
# Runs only when the orchestrator conditional edge decides there are
# enough serious findings (3+ HIGH or any CRITICAL).
#
# For each priority finding it asks the LLM to generate a
# proof-of-concept exploit scenario. If the LLM fails for any
# individual finding, that finding is returned as-is (no PoC).
# The agent never crashes the pipeline.

import logging
from app.services.llm_service import call_llm, parse_llm_json, LLMError

logger = logging.getLogger(__name__)


class DeepScanAgent:

    def run(self, security_result: dict) -> dict:
        findings = security_result.get("findings", [])

        if not findings:
            return {
                "agent":               "deep_scan",
                "status":              "skipped",
                "deep_scan_performed": False,
                "findings_enriched":   [],
                "note":                "No findings to enrich",
            }

        # Only enrich CRITICAL and HIGH findings, cap at 5
        priority_findings = [
            f for f in findings
            if f.get("severity") in ("CRITICAL", "HIGH", "MEDIUM")
        ][:2]

        if not priority_findings:
            return {
                "agent":               "deep_scan",
                "status":              "skipped",
                "deep_scan_performed": False,
                "findings_enriched":   [],
                "note":                "No HIGH/CRITICAL findings to enrich",
            }

        logger.info(
            f"[DeepScan] Enriching {len(priority_findings)} priority findings"
        )

        system_prompt = (
            "You are an expert penetration tester.\n"
            "Generate a proof-of-concept exploit scenario for a security finding.\n"
            "Respond ONLY with valid JSON. No explanation, no markdown."
        )

        enriched_findings = []

        for finding in priority_findings:
            endpoint    = finding.get("endpoint", "unknown")
            method      = finding.get("method", finding.get("risk_type", "GET"))
            risk_type   = finding.get("risk_type", finding.get("vulnerability", "Unknown"))
            severity    = finding.get("severity", "HIGH")
            description = finding.get("description", "")

            user_prompt = f"""Generate a proof-of-concept exploit for this security finding:

Endpoint: {endpoint}
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

            enriched = dict(finding)  # copy original finding

            try:
                raw = call_llm([
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_prompt},
                ])
                parsed = parse_llm_json(raw, fallback=None)
                if parsed and "exploit_poc" in parsed:
                    enriched["exploit_poc"] = parsed["exploit_poc"]
                    logger.info(f"[DeepScan] PoC generated for {endpoint}")
                else:
                    logger.warning(
                        f"[DeepScan] LLM returned invalid format for {endpoint}"
                    )
            except LLMError as e:
                logger.warning(f"[DeepScan] LLM failed for {endpoint}: {e}")
            except Exception as e:
                logger.warning(f"[DeepScan] Unexpected error for {endpoint}: {e}")

            enriched_findings.append(enriched)

        logger.info(
            f"[DeepScan] Completed — enriched {len(enriched_findings)} findings"
        )

        return {
            "agent":               "deep_scan",
            "status":              "completed",
            "deep_scan_performed": True,
            "findings_enriched":   enriched_findings,
        }