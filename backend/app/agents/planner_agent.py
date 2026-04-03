# backend/app/agents/planner_agent.py
#
# Analyzes the parsed OpenAPI spec and produces a structured security
# testing plan. Used by the orchestrator BEFORE the security and
# api_testing agents so they have context about risk priorities.
#
# Always returns structured data — LLM is used when available,
# rule-based fallback runs automatically if LLM fails.

import json
import logging

from app.services.llm_service import call_llm, parse_llm_json, LLMError

logger = logging.getLogger(__name__)


class PlannerAgent:

    # ── Rule-based fallback ───────────────────────────────────────
    # Runs when LLM is unavailable. Derives the same output fields
    # from parsed_data alone so the planner tab is never empty.

    @staticmethod
    def _build_fallback_plan(parsed_data: dict) -> dict:
        endpoints  = parsed_data.get("endpoints", [])
        title      = parsed_data.get("title", "Unknown API")
        auth       = parsed_data.get("auth", {})
        auth_type  = auth.get("type", "none")

        # Identify high-risk endpoints by simple rules
        high_risk = []
        for ep in endpoints:
            path   = ep["path"]
            method = ep["method"]
            risks, tests, vectors = [], [], []

            if "{" in path:
                risks.append("Path parameter may allow BOLA")
                tests.append("BOLA validation")
                vectors.append("Object ID enumeration")

            if method in ("POST", "PUT", "PATCH", "DELETE"):
                if auth_type == "none":
                    risks.append("Mutating method without authentication")
                    tests.append("Auth bypass validation")
                    vectors.append("Unauthenticated write")

            admin_kw = ["admin", "manage", "internal", "system", "debug"]
            if any(kw in path.lower() for kw in admin_kw):
                risks.append("Administrative endpoint")
                tests.append("Privilege escalation test")
                vectors.append("Function-level auth bypass")

            if risks:
                level = "HIGH" if len(risks) >= 2 else "MEDIUM"
                high_risk.append({
                    "path":               path,
                    "method":             method,
                    "risk_level":         level,
                    "risk_reasons":       risks,
                    "recommended_tests":  tests,
                    "attack_vectors":     vectors,
                })

        # Testing priorities — first 5 endpoints
        priorities = []
        for ep in endpoints[:5]:
            reason = "Baseline coverage"
            if "{" in ep["path"]:
                reason = "Parameterized path — BOLA candidate"
            elif ep["method"] in ("POST", "PUT", "DELETE"):
                reason = "Mutating method — auth validation needed"
            priorities.append({
                "path":   ep["path"],
                "method": ep["method"],
                "reason": reason,
            })

        # Risk summary sentence
        param_count    = len([e for e in endpoints if "{" in e["path"]])
        mutating_count = len([e for e in endpoints
                               if e["method"] in ("POST", "PUT", "PATCH", "DELETE")])
        auth_note = (
            "No authentication detected — high risk."
            if auth_type == "none"
            else f"Auth pattern detected: {auth_type}."
        )
        risk_summary = (
            f"{title} exposes {len(endpoints)} endpoints, "
            f"{param_count} with path parameters and "
            f"{mutating_count} mutating operations. {auth_note}"
        )

        # Fuzz categories per parameterized endpoint
        fuzz = {}
        for ep in endpoints:
            if "{" not in ep["path"]:
                continue
            cats = []
            pl   = ep["path"].lower()
            if any(kw in pl for kw in ["user", "id", "account", "order"]):
                cats.extend(["sql_injection", "auth_bypass"])
            if any(kw in pl for kw in ["search", "query", "filter"]):
                cats.extend(["sql_injection", "xss"])
            if any(kw in pl for kw in ["file", "upload", "download"]):
                cats.append("path_traversal")
            if not cats:
                cats = ["sql_injection", "xss"]
            fuzz[ep["path"]] = cats

        return {
            "risk_summary":            risk_summary,
            "auth_pattern_detected":   auth_type,
            "high_risk_endpoints":     high_risk,
            "testing_priorities":      priorities,
            "business_logic_risks": (
                [f"API has {param_count} parameterized endpoints — IDOR risk."]
                if param_count > 0
                else ["No obvious business logic risks detected from spec alone."]
            ),
            "suggested_fuzz_categories": fuzz,
        }

    # ── Main run ──────────────────────────────────────────────────

    def run(self, parsed_data: dict) -> dict:
        endpoints = parsed_data.get("endpoints", [])
        title     = parsed_data.get("title", "Unknown API")
        version   = parsed_data.get("version", "Unknown")
        base_url  = parsed_data.get("base_url", "")

        system_prompt = (
            "You are an expert API security architect.\n"
            "Analyze the OpenAPI specification and create a security testing plan.\n"
            "Respond ONLY in valid JSON. No explanation, no markdown."
        )

        user_prompt = f"""Analyze this OpenAPI specification and produce a structured security testing plan.

API Title: {title}
Version: {version}
Base URL: {base_url}
Endpoints ({len(endpoints)} total):
{json.dumps(endpoints, indent=2)}

Respond ONLY with a valid JSON object matching this exact structure:
{{
  "risk_summary": "2-3 sentence overview of risk posture",
  "auth_pattern_detected": "none|api_key|bearer|basic|oauth|unknown",
  "high_risk_endpoints": [
    {{
      "path": "string",
      "method": "string",
      "risk_level": "CRITICAL|HIGH|MEDIUM",
      "risk_reasons": ["string"],
      "recommended_tests": ["string"],
      "attack_vectors": ["string"]
    }}
  ],
  "testing_priorities": [
    {{"path": "string", "method": "string", "reason": "string"}}
  ],
  "business_logic_risks": ["string"],
  "suggested_fuzz_categories": {{
    "endpoint_path": ["sql_injection", "xss", "path_traversal"]
  }}
}}

Do not include any text before or after the JSON."""

        # Try LLM first
        raw = None
        try:
            raw = call_llm([
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ])
        except LLMError as e:
            logger.warning(f"[PlannerAgent] LLM unavailable, using fallback: {e}")

        if raw is not None:
            result = parse_llm_json(raw, fallback=None)
            if result is not None:
                logger.info(
                    f"[Planner] LLM plan generated for {len(endpoints)} endpoints"
                )
                return {
                    "agent":    "planner",
                    "status":   "completed",
                    "llm_used": True,
                    "plan":     result,
                }

        # Fallback — always returns structured data
        fallback_plan = self._build_fallback_plan(parsed_data)
        logger.info(
            f"[Planner] Fallback plan generated for {len(endpoints)} endpoints"
        )
        return {
            "agent":    "planner",
            "status":   "completed",
            "llm_used": False,
            "plan":     fallback_plan,
        }