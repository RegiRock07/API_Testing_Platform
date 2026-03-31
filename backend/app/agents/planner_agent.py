import json
import re
from app.services.llm_service import call_llm, parse_llm_json, LLMError


class PlannerAgent:

    def __init__(self):
        pass

    # ── Rule-based fallback (Problem 4) ───────────────────────────

    @staticmethod
    def _build_fallback_plan(parsed_data: dict) -> dict:
        """
        Derive a structured planner output from parsed_data alone.
        Guarantees the planner tab always has content.
        """
        endpoints = parsed_data.get("endpoints", [])
        auth = parsed_data.get("auth", {})
        title = parsed_data.get("title", "Unknown API")

        # Auth pattern detection
        auth_type = auth.get("type", "none")
        auth_pattern = {
            "apiKey": "api_key",
            "http": auth.get("scheme", "bearer") if auth_type == "http" else "unknown",
            "oauth2": "oauth",
            "openIdConnect": "oauth",
        }.get(auth_type, "none" if auth_type == "none" else "unknown")

        # Identify high-risk endpoints
        high_risk = []
        for ep in endpoints:
            path = ep["path"]
            method = ep["method"]
            risks = []
            tests = []
            vectors = []

            if "{" in path:
                risks.append("Path parameter may allow BOLA")
                tests.append("BOLA validation")
                vectors.append("Object ID enumeration")

            if method in ("POST", "PUT", "PATCH", "DELETE"):
                ep_sec = ep.get("security", [])
                global_sec = auth_type != "none"
                if not ep_sec and not global_sec:
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
                    "path": path,
                    "method": method,
                    "risk_level": level,
                    "risk_reasons": risks,
                    "recommended_tests": tests,
                    "attack_vectors": vectors,
                })

        # Testing priorities — first 5 endpoints
        priorities = []
        for ep in endpoints[:5]:
            reason = "Included for baseline coverage"
            if "{" in ep["path"]:
                reason = "Parameterized path — BOLA candidate"
            elif ep["method"] in ("POST", "PUT", "DELETE"):
                reason = "Mutating method — auth validation"
            priorities.append({
                "path": ep["path"],
                "method": ep["method"],
                "reason": reason,
            })

        # Risk summary
        param_count = len([e for e in endpoints if "{" in e["path"]])
        mutating_count = len([e for e in endpoints
                              if e["method"] in ("POST", "PUT", "PATCH", "DELETE")])
        risk_summary = (
            f"{title} exposes {len(endpoints)} endpoints, "
            f"{param_count} of which use path parameters and "
            f"{mutating_count} perform mutating operations. "
            f"Auth pattern: {auth_pattern}. "
            f"{'No authentication detected — high risk.' if auth_pattern == 'none' else 'Review auth coverage per endpoint.'}"
        )

        # Suggested fuzz categories
        fuzz = {}
        for ep in endpoints:
            path = ep["path"]
            if "{" not in path:
                continue
            cats = []
            pl = path.lower()
            if any(kw in pl for kw in ["user", "id", "account", "order"]):
                cats.extend(["sql_injection", "auth_bypass"])
            if any(kw in pl for kw in ["search", "query", "filter"]):
                cats.extend(["sql_injection", "xss"])
            if any(kw in pl for kw in ["file", "upload", "download"]):
                cats.append("path_traversal")
            if not cats:
                cats = ["sql_injection", "xss"]
            fuzz[path] = cats

        return {
            "risk_summary": risk_summary,
            "auth_pattern_detected": auth_pattern,
            "high_risk_endpoints": high_risk,
            "testing_priorities": priorities,
            "business_logic_risks": [
                f"API with {param_count} parameterized endpoints may be susceptible to IDOR attacks."
            ] if param_count > 0 else ["No obvious business logic risks detected from spec alone."],
            "suggested_fuzz_categories": fuzz,
        }

    # ── Main run ──────────────────────────────────────────────────

    def run(self, parsed_data: dict) -> dict:
        endpoints = parsed_data.get("endpoints", [])
        title = parsed_data.get("title", "Unknown API")
        version = parsed_data.get("version", "Unknown")
        base_url = parsed_data.get("base_url", "")

        system_prompt = (
            "You are an expert API security architect.\n"
            "Analyze the OpenAPI specification and create a security testing plan.\n"
            "Respond ONLY in valid JSON."
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

        try:
            raw = call_llm([
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ])
        except LLMError as e:
            print(f"[PlannerAgent] LLM Error: {e}")
            raw = None

        if raw is not None:
            result = parse_llm_json(raw, fallback=None)
            if result is not None:
                return {
                    "agent": "planner",
                    "status": "completed",
                    "llm_used": True,
                    "plan": result,
                }

        # Fallback: rule-based — ALWAYS returns structured data
        fallback_plan = self._build_fallback_plan(parsed_data)
        return {
            "agent": "planner",
            "status": "completed",
            "llm_used": False,
            "plan": fallback_plan,
        }
