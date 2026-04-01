import os
import json
import requests
from app.services.llm_service import call_llm, parse_llm_json, LLMError


# ─────────────────────────────────────────────────────────────────
# Severity cap: STATIC findings may never exceed MEDIUM
# ─────────────────────────────────────────────────────────────────
_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _cap_severity(severity: str, detection_type: str) -> str:
    """Enforce: STATIC findings max severity = MEDIUM."""
    if detection_type == "STATIC" and _SEVERITY_ORDER.get(severity, 0) > 2:
        return "MEDIUM"
    return severity


def _better_confidence(a: str, b: str) -> str:
    rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    return a if rank.get(a, 0) >= rank.get(b, 0) else b


class SecurityAgent:

    def __init__(self):
        pass

    # ── Graduated BOLA Detection (replaces blanket rule) ─────────

    def _detect_bola(self, ep: dict, parsed_data: dict,
                     planner_high_risk_paths: set) -> list:
        """
        API1: BOLA — graduated detection per Reform Master Plan.
        - No path param → no finding
        - Path param + no security + user-scoped name → MEDIUM
        - Path param + security present → LOW
        - Planner flagged high-risk → bump to MEDIUM (never above without DYNAMIC)
        """
        path = ep["path"]
        method = ep["method"]

        if "{" not in path:
            return []

        endpoint_security = ep.get("security", [])
        global_auth = parsed_data.get("auth", {})
        has_security = bool(endpoint_security) or global_auth.get("type", "none") != "none"

        # Check for user-scoped parameter names
        user_scoped = ["user_id", "userId", "account_id", "accountId",
                       "order_id", "orderId", "profile_id", "profileId",
                       "customer_id", "customerId", "id"]
        param_names = [p.get("name", "") for p in ep.get("parameters", [])]
        # Also extract from path template
        import re
        path_params = re.findall(r"\{(.*?)\}", path)
        all_params = param_names + path_params
        is_user_scoped = any(p in user_scoped for p in all_params)

        if not has_security and is_user_scoped:
            confidence = "MEDIUM"
        elif has_security:
            confidence = "LOW"
        else:
            confidence = "LOW"

        # Planner bump
        if path in planner_high_risk_paths and confidence == "LOW":
            confidence = "MEDIUM"

        severity = _cap_severity("MEDIUM", "STATIC")

        return [{
            "endpoint": path,
            "method": method,
            "vulnerability": "Potential BOLA — Object ID in Path (Static)",
            "owasp_category": "OWASP API1:2023",
            "severity": severity,
            "confidence": confidence,
            "detection_type": "STATIC",
            "description": "Endpoint uses object identifiers which may allow unauthorized access.",
            "evidence": f"Path parameter in {path}",
            "exploit_scenario": f"Attacker changes ID in {path} to access another user's resource.",
            "remediation": "Implement object-level authorization checks.",
        }]

    # ── Graduated Auth Detection (replaces blanket rule) ──────────

    def _detect_auth(self, ep: dict, parsed_data: dict) -> list:
        """
        API2: Broken Authentication — graduated detection.
        - Security scheme defined → no finding
        - No security + mutating method → MEDIUM, STATIC
        - No security + read-only (GET) → LOW, STATIC
        """
        path = ep["path"]
        method = ep["method"]

        endpoint_security = ep.get("security", [])
        global_auth = parsed_data.get("auth", {})
        has_security = bool(endpoint_security) or global_auth.get("type", "none") != "none"

        if has_security:
            return []

        mutating = method in ("POST", "PUT", "PATCH", "DELETE")
        confidence = "MEDIUM" if mutating else "LOW"
        severity = _cap_severity("MEDIUM" if mutating else "LOW", "STATIC")

        return [{
            "endpoint": path,
            "method": method,
            "vulnerability": "Potential Missing Authentication (Static)",
            "owasp_category": "OWASP API2:2023",
            "severity": severity,
            "confidence": confidence,
            "detection_type": "STATIC",
            "description": f"{method} endpoint has no security scheme defined in spec.",
            "evidence": f"No security scheme on {method} {path}.",
            "exploit_scenario": f"Attacker sends {method} to {path} without credentials.",
            "remediation": "Add authentication (JWT, OAuth, API keys) and require valid credentials.",
        }]

    # ── OWASP API5-10 detectors (existing, now with detection_type/confidence) ──

    def _detect_api5_bfla(self, ep: dict, parsed_data: dict) -> list:
        findings = []
        path = ep["path"]
        method = ep["method"]

        admin_keywords = ["admin", "manage", "configure", "system",
                          "internal", "debug", "elevate"]
        is_admin = any(kw in path.lower() for kw in admin_keywords)
        sensitive = ["DELETE", "PATCH", "PUT"]

        if is_admin and method in sensitive:
            findings.append({
                "endpoint": path, "method": method,
                "vulnerability": "Broken Function Level Authorization (BFLA)",
                "owasp_category": "OWASP API5:2023",
                "severity": _cap_severity("MEDIUM", "STATIC"),
                "confidence": "MEDIUM",
                "detection_type": "STATIC",
                "description": "Admin endpoint allows sensitive method without explicit auth in spec.",
                "evidence": f"Admin keyword in path + {method}",
                "exploit_scenario": f"Attacker calls {method} on {path} without authorization.",
                "remediation": "Implement function-level authorization checks.",
            })

        if method == "DELETE" and not is_admin:
            endpoint_security = ep.get("security", [])
            global_auth = parsed_data.get("auth", {})
            has_sec = bool(endpoint_security) or global_auth.get("type", "none") != "none"
            if not has_sec:
                findings.append({
                    "endpoint": path, "method": method,
                    "vulnerability": "Broken Function Level Authorization (BFLA)",
                    "owasp_category": "OWASP API5:2023",
                    "severity": _cap_severity("MEDIUM", "STATIC"),
                    "confidence": "LOW",
                    "detection_type": "STATIC",
                    "description": "DELETE without function-level authorization.",
                    "evidence": f"DELETE on {path} with no security scheme",
                    "exploit_scenario": f"Attacker deletes resources at {path}.",
                    "remediation": "Verify DELETE requires proper authorization.",
                })

        return findings

    def _detect_api3_excessive_data(self, ep: dict) -> list:
        path = ep["path"]
        method = ep["method"]
        if method != "GET":
            return []
        sensitive = ["users", "accounts", "orders", "profiles"]
        if not any(kw in path.lower() for kw in sensitive):
            return []
        return [{
            "endpoint": path, "method": method,
            "vulnerability": "Excessive Data Exposure",
            "owasp_category": "OWASP API3:2023",
            "severity": _cap_severity("MEDIUM", "STATIC"),
            "confidence": "LOW",
            "detection_type": "STATIC",
            "description": "Endpoint may expose more data than client needs.",
            "evidence": f"GET {path} returns sensitive objects.",
            "exploit_scenario": "API returns full database objects including internal fields.",
            "remediation": "Implement response filtering; return only necessary fields.",
        }]

    def _detect_api4_rate_limit(self, ep: dict) -> list:
        path = ep["path"]
        method = ep["method"]
        keywords = ["login", "auth", "token", "search", "password"]
        if not any(kw in path.lower() for kw in keywords):
            return []
        return [{
            "endpoint": path, "method": method,
            "vulnerability": "Lack of Rate Limiting",
            "owasp_category": "OWASP API4:2023",
            "severity": _cap_severity("MEDIUM", "STATIC"),
            "confidence": "LOW",
            "detection_type": "STATIC",
            "description": "Endpoint may lack rate limiting.",
            "evidence": f"Rate-limit-sensitive path: {path}",
            "exploit_scenario": "Attacker brute-forces or overwhelms the service.",
            "remediation": "Implement rate limiting (e.g., 100 req/min per IP).",
        }]

    def _detect_api6_resource(self, ep: dict, parsed_data: dict) -> list:
        findings = []
        path = ep["path"]
        method = ep["method"]

        rate_kw = ["login", "auth", "token", "search", "password", "upload", "download"]
        has_rl = parsed_data.get("x-rate-limit") or parsed_data.get("throttling")
        if any(kw in path.lower() for kw in rate_kw) and not has_rl:
            findings.append({
                "endpoint": path, "method": method,
                "vulnerability": "Unrestricted Resource Consumption",
                "owasp_category": "OWASP API6:2023",
                "severity": _cap_severity("MEDIUM", "STATIC"),
                "confidence": "LOW",
                "detection_type": "STATIC",
                "description": "Endpoint may lack rate limiting.",
                "evidence": f"No throttle/rateLimit policy on {path}",
                "exploit_scenario": "Attacker overwhelms the service.",
                "remediation": "Implement rate limiting and restrict payload sizes.",
            })
        return findings

    def _detect_api7_ssrf(self, ep: dict, parsed_data: dict) -> list:
        findings = []
        path = ep["path"]
        method = ep["method"]
        url_patterns = ["url", "uri", "href", "src", "redirect",
                        "forward", "callback", "next", "dest"]
        for param in ep.get("parameters", []):
            pname = param.get("name", "").lower()
            if param.get("in") in ("query", "path") and any(
                    p in pname for p in url_patterns):
                findings.append({
                    "endpoint": path, "method": method,
                    "vulnerability": "Server-Side Request Forgery (SSRF)",
                    "owasp_category": "OWASP API7:2023",
                    "severity": _cap_severity("MEDIUM", "STATIC"),
                    "confidence": "MEDIUM",
                    "detection_type": "STATIC",
                    "description": f"Parameter '{param.get('name')}' suggests URL handling.",
                    "evidence": f"URL-like parameter: {param.get('name')}",
                    "exploit_scenario": f"Attacker provides malicious URL as {param.get('name')}.",
                    "remediation": "Validate URL parameters against an allowlist.",
                })
        return findings

    def _detect_api8_misconfig(self, ep: dict, parsed_data: dict,
                               deployment_result: dict = None) -> list:
        findings = []
        path = ep["path"]
        method = ep["method"]
        if deployment_result:
            for df in deployment_result.get("findings", []):
                if df.get("issue") == "docs_exposed" or \
                   "Documentation Exposed" in df.get("vulnerability", ""):
                    findings.append({
                        "endpoint": path, "method": method,
                        "vulnerability": "Security Misconfiguration (API8)",
                        "owasp_category": "OWASP API8:2023",
                        "severity": _cap_severity("MEDIUM", "STATIC"),
                        "confidence": "MEDIUM",
                        "detection_type": "STATIC",
                        "description": "API documentation is exposed.",
                        "evidence": "Deployment agent: docs_exposed",
                        "exploit_scenario": "Attacker accesses docs to map the API.",
                        "remediation": "Disable docs in production.",
                    })
                    break
        return findings

    def _detect_api9_inventory(self, parsed_data: dict) -> list:
        findings = []
        paths = [ep["path"] for ep in parsed_data.get("endpoints", [])]
        has_v1 = any("/v1/" in p for p in paths)
        has_v2 = any("/v2/" in p for p in paths)
        if has_v1 and not has_v2:
            findings.append({
                "endpoint": "/v1/*", "method": "MULTIPLE",
                "vulnerability": "Improper Inventory Management (API9)",
                "owasp_category": "OWASP API9:2023",
                "severity": _cap_severity("MEDIUM", "STATIC"),
                "confidence": "LOW",
                "detection_type": "STATIC",
                "description": "API has v1 but no v2 — possible versioning gap.",
                "evidence": "Found /v1/ paths but no /v2/",
                "exploit_scenario": "Old API versions may have unpatched vulnerabilities.",
                "remediation": "Implement API versioning strategy.",
            })
        for ep in parsed_data.get("endpoints", []):
            if ep.get("deprecated") or "deprecated" in ep.get("summary", "").lower():
                findings.append({
                    "endpoint": ep["path"], "method": ep["method"],
                    "vulnerability": "Improper Inventory Management (API9)",
                    "owasp_category": "OWASP API9:2023",
                    "severity": _cap_severity("MEDIUM", "STATIC"),
                    "confidence": "MEDIUM",
                    "detection_type": "STATIC",
                    "description": "Deprecated endpoint still operational.",
                    "evidence": f"Deprecated: {ep['path']}",
                    "exploit_scenario": "Deprecated endpoints may have unpatched vulns.",
                    "remediation": "Monitor deprecated endpoints and plan removal.",
                })
        return findings

    def _detect_api10_unsafe(self, ep: dict, parsed_data: dict) -> list:
        findings = []
        path = ep["path"]
        method = ep["method"]
        callback_patterns = ["webhook", "callback", "notify", "hook"]
        if any(p in path.lower() for p in callback_patterns):
            findings.append({
                "endpoint": path, "method": method,
                "vulnerability": "Unsafe Consumption of APIs (API10)",
                "owasp_category": "OWASP API10:2023",
                "severity": _cap_severity("MEDIUM", "STATIC"),
                "confidence": "LOW",
                "detection_type": "STATIC",
                "description": "Webhook/callback endpoint may accept external requests.",
                "evidence": f"Callback pattern in path: {path}",
                "exploit_scenario": "Attacker sends malicious payloads via webhook.",
                "remediation": "Implement signature verification for webhooks.",
            })
        return findings

    # ── Fallback: rule-based (no LLM) ─────────────────────────────

    def _fallback_logic(self, parsed_data: dict,
                        deployment_result: dict = None,
                        planner_high_risk_paths: set = None) -> list:
        """Full rule-based detection for all OWASP categories."""
        if planner_high_risk_paths is None:
            planner_high_risk_paths = set()
        findings = []
        endpoints = parsed_data.get("endpoints", [])

        for ep in endpoints:
            findings.extend(self._detect_bola(ep, parsed_data, planner_high_risk_paths))
            findings.extend(self._detect_auth(ep, parsed_data))
            findings.extend(self._detect_api3_excessive_data(ep))
            findings.extend(self._detect_api4_rate_limit(ep))
            findings.extend(self._detect_api5_bfla(ep, parsed_data))
            findings.extend(self._detect_api6_resource(ep, parsed_data))
            findings.extend(self._detect_api7_ssrf(ep, parsed_data))
            findings.extend(self._detect_api8_misconfig(ep, parsed_data, deployment_result))
            findings.extend(self._detect_api10_unsafe(ep, parsed_data))

        findings.extend(self._detect_api9_inventory(parsed_data))
        return findings

    # ── Deduplication ─────────────────────────────────────────────

    @staticmethod
    def _deduplicate(findings: list) -> list:
        """
        Graduated deduplication: path-level for BOLA/Auth/Inventory, method-level otherwise.
        Keep the finding with higher confidence and track affected_methods.
        """
        best = {}
        for f in findings:
            ep = f.get("endpoint")
            method = f.get("method")
            vuln = f.get("vulnerability")
            vuln_lower = (vuln or "").lower()

            is_path_level = False
            if "bola" in vuln_lower or "missing authentication" in vuln_lower or "inventory" in vuln_lower:
                is_path_level = True

            if is_path_level:
                key = (ep, None, vuln)
            else:
                key = (ep, method, vuln)

            existing = best.get(key)
            if existing is None:
                f["affected_methods"] = [method] if method and method != "MULTIPLE" else []
                best[key] = f
            else:
                if method and method != "MULTIPLE" and method not in existing.get("affected_methods", []):
                    existing.setdefault("affected_methods", []).append(method)

                if _SEVERITY_ORDER.get(f.get("confidence", "LOW"), 0) > \
                   _SEVERITY_ORDER.get(existing.get("confidence", "LOW"), 0):
                    f["affected_methods"] = existing.get("affected_methods", [])
                    best[key] = f
        return list(best.values())

    # ── Main run ──────────────────────────────────────────────────

    def run(self, parsed_data: dict, planner_result: dict = None,
            deployment_result: dict = None) -> dict:
        endpoints = parsed_data.get("endpoints", [])
        planner_plan = planner_result.get("plan", {}) if planner_result else {}
        high_risk_eps = planner_plan.get("high_risk_endpoints", []) if planner_plan else []
        planner_high_risk_paths = {e.get("path") for e in high_risk_eps if e.get("path")}

        system_prompt = (
            "You are an expert API security analyst.\n"
            "Analyze each endpoint for OWASP API Top 10 2023 vulnerabilities.\n"
            "Respond ONLY in valid JSON. No explanation or markdown."
        )

        all_findings = []

        for ep in endpoints:
            path = ep["path"]
            method = ep["method"]
            summary = ep.get("summary", "")
            parameters = ep.get("parameters", [])
            responses = ep.get("responses", [])
            request_body = ep.get("request_body", {})

            user_prompt = f"""Analyze this endpoint for security vulnerabilities:

Endpoint: {method} {path}
Summary: {summary}
Parameters: {json.dumps(parameters)}
Request Body: {json.dumps(request_body)}
Responses: {json.dumps(responses)}

Respond with a JSON array of findings:
[
  {{
    "vulnerability": "Specific name",
    "owasp_category": "OWASP APIx:2023",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "confidence": "HIGH|MEDIUM|LOW",
    "description": "...",
    "evidence": "...",
    "exploit_scenario": "...",
    "remediation": "..."
  }}
]

Return [] if no issues. No text outside JSON."""

            try:
                raw = call_llm([
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ])
            except LLMError as e:
                print(f"[SecurityAgent] LLM Error: {e}")
                raw = None

            if raw is not None:
                result = parse_llm_json(raw, fallback=None)
                if result is not None and isinstance(result, list):
                    for finding in result:
                        finding["endpoint"] = path
                        finding["method"] = method
                        # All LLM findings are STATIC (spec analysis only)
                        finding["detection_type"] = "STATIC"
                        finding.setdefault("confidence", "MEDIUM")
                        # Apply severity cap
                        finding["severity"] = _cap_severity(
                            finding.get("severity", "MEDIUM"), "STATIC")
                    all_findings.extend(result)
                    continue

            # Fallback: rule-based
            fb = self._fallback_logic(
                {"endpoints": [ep], "auth": parsed_data.get("auth", {}),
                 "servers": parsed_data.get("servers", []),
                 "components": parsed_data.get("components", {})},
                deployment_result, planner_high_risk_paths)
            all_findings.extend(fb)

        # API9 runs on the full spec (not per-endpoint in LLM path)
        all_findings.extend(self._detect_api9_inventory(parsed_data))

        # Deduplicate
        deduped = self._deduplicate(all_findings)

        critical_count = sum(1 for f in deduped if f.get("severity") == "CRITICAL")
        high_count = sum(1 for f in deduped if f.get("severity") == "HIGH")

        return {
            "agent": "security",
            "status": "completed",
            "llm_used": any(f.get("detection_type") == "DYNAMIC" for f in deduped),
            "total_findings": len(deduped),
            "critical_count": critical_count,
            "high_count": high_count,
            "findings": deduped,
        }