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
        print(f"[DeepScanAgent] LLM JSON parse failed: {e}. Raw: {raw_text[:200]}")
        return fallback


class DeepScanAgent:

    def __init__(self):
        self.ollama_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self.model = os.getenv("DEEP_SCAN_MODEL", os.getenv("OLLAMA_DEFAULT_MODEL", "llama3.1:8b"))
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
            print(f"[DeepScanAgent] Ollama call failed: {e}")
            return None

    def run(self, security_result: dict) -> dict:
        findings = security_result.get("findings", [])
        if not findings:
            return {
                "agent": "deep_scan",
                "status": "skipped",
                "deep_scan_performed": False,
                "findings_enriched": []
            }

        # Take top 5 critical/high findings
        priority_findings = [
            f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")
        ][:5]

        if not priority_findings:
            return {
                "agent": "deep_scan",
                "status": "skipped",
                "deep_scan_performed": False,
                "findings_enriched": []
            }

        system_prompt = (
            "You are an expert penetration tester.\n"
            "Your task is to generate proof-of-concept exploit scenarios for security findings.\n"
            "Respond ONLY in valid JSON. Do not add any explanation, markdown, or text outside the JSON."
        )

        enriched_findings = []

        for finding in priority_findings:
            endpoint = finding.get("endpoint", "unknown")
            method = finding.get("method", "GET")
            vulnerability = finding.get("vulnerability", "Unknown")
            severity = finding.get("severity", "HIGH")
            description = finding.get("description", "")
            evidence = finding.get("evidence", "")

            user_prompt = f"""Generate a proof-of-concept exploit for this security finding:

Endpoint: {method} {endpoint}
Vulnerability: {vulnerability}
Severity: {severity}
Description: {description}
Evidence: {evidence}

Respond ONLY with a valid JSON object matching this exact structure:
{{
  "exploit_poc": {{
    "summary": "Brief description of the exploit",
    "steps": [
      "Step 1: Description of action to take",
      "Step 2: Description of action to take"
    ],
    "sample_curl": "curl -X {method} '{endpoint}' -H 'Content-Type: application/json' -d '{{...}}'",
    "expected_vulnerable_response": "Description of what the vulnerable server would return",
    "verification_test": "How to verify this vulnerability is fixed"
  }}
}}

Do not include any text before or after the JSON."""

            raw = self._call_llm([
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ])

            enriched = dict(finding)
            if raw:
                parsed = parse_llm_json(raw, fallback=None)
                if parsed and "exploit_poc" in parsed:
                    enriched["exploit_poc"] = parsed["exploit_poc"]

            enriched_findings.append(enriched)

        return {
            "agent": "deep_scan",
            "status": "completed",
            "deep_scan_performed": True,
            "findings_enriched": enriched_findings
        }
