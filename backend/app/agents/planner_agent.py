import os
import json
import requests


from app.services.llm_service import call_llm, parse_llm_json, LLMError

class PlannerAgent:

    def __init__(self):
        # Configuration is now handled in llm_service
        pass

    def run(self, parsed_data: dict) -> dict:
        endpoints = parsed_data.get("endpoints", [])
        title = parsed_data.get("title", "Unknown API")
        version = parsed_data.get("version", "Unknown")
        base_url = parsed_data.get("base_url", "")

        system_prompt = (
            "You are an expert API security architect performing a penetration test.\n"
            "Your task is to analyze the provided OpenAPI specification and create a structured security testing plan.\n"
            "Respond ONLY in valid JSON. Do not add any explanation, markdown, or text outside the JSON."
        )

        user_prompt = f"""Analyze this OpenAPI specification and produce a structured security testing plan.

API Title: {title}
Version: {version}
Base URL: {base_url}
Endpoints ({len(endpoints)} total):
{json.dumps(endpoints, indent=2)}

Respond ONLY with a valid JSON object matching this exact structure:
{{
  "risk_summary": "2-3 sentence overview of the API's overall risk posture",
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
  "business_logic_risks": [
    "string describing inferred business logic vulnerability"
  ],
  "suggested_fuzz_categories": {{
    "endpoint_path": ["sql_injection", "xss", "path_traversal"]
  }}
}}

Do not include any text before or after the JSON. Do not use markdown code blocks."""

        try:
            raw = call_llm([
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ])
        except LLMError as e:
            print(f"[PlannerAgent] LLM Error: {e}")
            raw = None

        if raw is None:
            return {
                "agent": "planner",
                "status": "skipped",
                "llm_used": False,
                "plan": {}
            }

        result = parse_llm_json(raw, fallback=None)
        if result is None:
            return {
                "agent": "planner",
                "status": "skipped",
                "llm_used": False,
                "plan": {}
            }

        return {
            "agent": "planner",
            "status": "completed",
            "llm_used": True,
            "plan": result
        }
