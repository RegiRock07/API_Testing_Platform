import os
import json
import requests


def parse_llm_json(raw_text: str, fallback=None):
    try:
        text = raw_text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        text = text.strip()
        return json.loads(text)
    except Exception as e:
        print(f"[PlannerAgent] LLM JSON parse failed: {e}. Raw: {raw_text[:200]}")
        return fallback


class PlannerAgent:

    def __init__(self):
        self.ollama_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self.model = os.getenv("PLANNER_MODEL", os.getenv("OLLAMA_DEFAULT_MODEL", "llama3.1:8b"))
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
            print(f"[PlannerAgent] Ollama call failed: {e}")
            return None

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

        raw = self._call_llm([
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ])

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
