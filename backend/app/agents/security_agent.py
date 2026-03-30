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
        print(f"[SecurityAgent] LLM JSON parse failed: {e}. Raw: {raw_text[:200]}")
        return fallback


class SecurityAgent:

    def __init__(self):
        self.ollama_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self.model = os.getenv("SECURITY_MODEL", os.getenv("OLLAMA_DEFAULT_MODEL", "llama3.1:8b"))
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
            print(f"[SecurityAgent] Ollama call failed: {e}")
            return None

    def _detect_api5_bfla(self, ep: dict, parsed_data: dict) -> list:
        """API5: Broken Function Level Authorization detection."""
        findings = []
        path = ep["path"]
        method = ep["method"]

        # Admin path patterns
        admin_keywords = ["admin", "manage", "configure", "system", "internal", "debug", "elevate"]
        is_admin_path = any(kw in path.lower() for kw in admin_keywords)

        # Sensitive methods that could indicate BFLA
        sensitive_methods = ["DELETE", "PATCH", "PUT"]

        # Check for admin endpoints with sensitive methods
        if is_admin_path and method in sensitive_methods:
            findings.append({
                "endpoint": path,
                "method": method,
                "vulnerability": "Broken Function Level Authorization (BFLA)",
                "owasp_category": "OWASP API5:2023",
                "severity": "HIGH",
                "confidence": "POTENTIAL",
                "description": "Admin endpoint allows sensitive method without explicit authorization checks in spec.",
                "evidence": f"Path contains admin keyword and method {method} is allowed",
                "exploit_scenario": f"An attacker calls {method} on {path} to modify administrative functions without proper authorization.",
                "remediation": "Implement function-level authorization checks. Ensure users can only access functions they are authorized for based on their role."
            })

        # Check for DELETE on resource endpoints (function-level)
        if method == "DELETE" and not is_admin_path:
            findings.append({
                "endpoint": path,
                "method": method,
                "vulnerability": "Broken Function Level Authorization (BFLA)",
                "owasp_category": "OWASP API5:2023",
                "severity": "MEDIUM",
                "confidence": "POTENTIAL",
                "description": "DELETE method may allow deletion of resources without proper function-level authorization.",
                "evidence": f"DELETE endpoint at {path} may not have proper authorization",
                "exploit_scenario": f"An attacker deletes resources at {path} that should require elevated privileges.",
                "remediation": "Verify that DELETE operations require appropriate authorization and cannot be accessed by unauthorized users."
            })

        # Check if security is defined at endpoint level for sensitive methods
        endpoint_security = ep.get("security", [])
        if method in sensitive_methods and not endpoint_security:
            # Check if global security exists
            global_security = parsed_data.get("auth", {})
            if global_security.get("type") == "none":
                findings.append({
                    "endpoint": path,
                    "method": method,
                    "vulnerability": "Broken Function Level Authorization (BFLA)",
                    "owasp_category": "OWASP API5:2023",
                    "severity": "HIGH",
                    "confidence": "POTENTIAL",
                    "description": f"{method} endpoint has no security scheme defined, suggesting potential function-level auth gap.",
                    "evidence": f"Method {method} on {path} has no endpoint-level or global security defined",
                    "exploit_scenario": f"An attacker invokes {method} on {path} without authentication to perform privileged operations.",
                    "remediation": "Define explicit security schemes at the endpoint level and verify user roles before executing sensitive operations."
                })

        return findings

    def _detect_api6_unrestricted_resource(self, ep: dict, parsed_data: dict) -> list:
        """API6: Unrestricted Resource Consumption detection."""
        findings = []
        path = ep["path"]
        method = ep["method"]

        # Check for missing rate limiting on high-risk endpoints
        rate_limit_keywords = ["login", "auth", "token", "search", "password", "upload", "download"]
        has_rate_limit = parsed_data.get("x-rate-limit") or parsed_data.get("throttling")

        if any(kw in path.lower() for kw in rate_limit_keywords) and not has_rate_limit:
            findings.append({
                "endpoint": path,
                "method": method,
                "vulnerability": "Unrestricted Resource Consumption",
                "owasp_category": "OWASP API6:2023",
                "severity": "HIGH",
                "confidence": "POTENTIAL",
                "description": "Endpoint may lack rate limiting, allowing attackers to consume excessive resources.",
                "evidence": f"Path contains '{'/'.join(rate_limit_keywords)}' but no throttling/rateLimit policy defined",
                "exploit_scenario": "An attacker makes repeated requests to overwhelm the service or exhaust resources.",
                "remediation": "Implement rate limiting (e.g., 100 req/min per IP) and restrict payload sizes."
            })

        # Check request body for missing size constraints
        request_body = ep.get("request_body", {})
        if request_body:
            content = request_body.get("content", {})
            for media_type, schema_ref in content.items():
                schema = schema_ref if isinstance(schema_ref, dict) else {}
                if isinstance(schema_ref, dict):
                    schema = schema_ref.get("schema", {})

                # Check for missing maxItems on arrays
                if schema.get("type") == "array":
                    if "maxItems" not in schema:
                        findings.append({
                            "endpoint": path,
                            "method": method,
                            "vulnerability": "Unrestricted Resource Consumption",
                            "owasp_category": "OWASP API6:2023",
                            "severity": "MEDIUM",
                            "confidence": "POTENTIAL",
                            "description": "Array field in request body has no maxItems constraint.",
                            "evidence": f"Request body array has no maxItems limit",
                            "exploit_scenario": "An attacker sends arrays with excessive items to consume server memory.",
                            "remediation": "Add maxItems constraint to array schemas to limit resource consumption."
                        })

                # Check for missing maxLength on strings
                if schema.get("type") == "string":
                    if "maxLength" not in schema and "format" not in schema:
                        findings.append({
                            "endpoint": path,
                            "method": method,
                            "vulnerability": "Unrestricted Resource Consumption",
                            "owasp_category": "OWASP API6:2023",
                            "severity": "LOW",
                            "confidence": "POTENTIAL",
                            "description": "String field in request body has no maxLength constraint.",
                            "evidence": f"Request body string field has no maxLength limit",
                            "exploit_scenario": "An attacker sends very long strings to exhaust server memory or storage.",
                            "remediation": "Add maxLength constraint to string schemas to limit input size."
                        })

        # Check parameters for missing size constraints
        parameters = ep.get("parameters", [])
        for param in parameters:
            if param.get("in") == "query" and param.get("type") == "string":
                if "maxLength" not in param and param.get("required"):
                    findings.append({
                        "endpoint": path,
                        "method": method,
                        "vulnerability": "Unrestricted Resource Consumption",
                        "owasp_category": "OWASP API6:2023",
                        "severity": "LOW",
                        "confidence": "POTENTIAL",
                        "description": f"Required query parameter '{param.get('name')}' has no maxLength constraint.",
                        "evidence": f"Parameter {param.get('name')} lacks size constraints",
                        "exploit_scenario": f"An attacker provides extremely long values for {param.get('name')} to cause resource exhaustion.",
                        "remediation": "Add maxLength constraint to query parameters to limit input size."
                    })

        return findings

    def _detect_api7_ssrf(self, ep: dict, parsed_data: dict) -> list:
        """API7: Server-Side Request Forgery (SSRF) detection."""
        findings = []
        path = ep["path"]
        method = ep["method"]

        # URL-like parameter name patterns
        url_param_patterns = ["url", "uri", "href", "src", "path", "redirect", "forward", "callback", "next", "dest", "destination"]

        parameters = ep.get("parameters", [])
        for param in parameters:
            param_name = param.get("name", "").lower()
            param_in = param.get("in", "")

            # Check for URL-like parameter names in path/query
            if param_in in ["query", "path"] and any(pattern in param_name for pattern in url_param_patterns):
                findings.append({
                    "endpoint": path,
                    "method": method,
                    "vulnerability": "Server-Side Request Forgery (SSRF)",
                    "owasp_category": "OWASP API7:2023",
                    "severity": "HIGH",
                    "confidence": "POTENTIAL",
                    "description": f"Parameter '{param.get('name')}' suggests URL handling that could enable SSRF attacks.",
                    "evidence": f"Parameter name contains URL-like pattern: {param.get('name')}",
                    "exploit_scenario": f"An attacker provides a malicious URL (e.g., file:///etc/passwd or http://169.254.169.254/) as {param.get('name')} to access internal resources.",
                    "remediation": "Validate and sanitize URL parameters. Implement allowlists for permitted destinations and block internal IP ranges."
                })

            # Check for string type with format: uri
            if param.get("type") == "string" and param.get("format") == "uri":
                findings.append({
                    "endpoint": path,
                    "method": method,
                    "vulnerability": "Server-Side Request Forgery (SSRF)",
                    "owasp_category": "OWASP API7:2023",
                    "severity": "HIGH",
                    "confidence": "POTENTIAL",
                    "description": "Parameter accepts URI format, potentially enabling SSRF attacks.",
                    "evidence": f"Parameter {param.get('name')} has format: uri",
                    "exploit_scenario": "An attacker provides a malicious URI to access internal services or cloud metadata.",
                    "remediation": "Implement strict URI validation, use allowlists for permitted destinations, and reject internal IP addresses."
                })

        # Check request body for URL-like fields
        request_body = ep.get("request_body", {})
        if request_body:
            content = request_body.get("content", {})
            for media_type, schema_ref in content.items():
                if isinstance(schema_ref, dict):
                    schema = schema_ref.get("schema", {})

                    def check_schema_for_urls(schema_obj, path_prefix=""):
                        url_findings = []
                        if schema_obj.get("type") == "string" and schema_obj.get("format") == "uri":
                            url_findings.append({
                                "endpoint": path,
                                "method": method,
                                "vulnerability": "Server-Side Request Forgery (SSRF)",
                                "owasp_category": "OWASP API7:2023",
                                "severity": "HIGH",
                                "confidence": "POTENTIAL",
                                "description": f"Request body contains URI-format field that could enable SSRF.",
                                "evidence": f"Schema path: {path_prefix}{schema_obj.get('name', 'unnamed')}",
                                "exploit_scenario": "An attacker sends a malicious URI in the request body to access internal resources.",
                                "remediation": "Validate URI input against an allowlist of permitted destinations."
                            })

                        # Check for properties
                        properties = schema_obj.get("properties", {})
                        for prop_name, prop_val in properties.items():
                            url_findings.extend(check_schema_for_urls(prop_val, f"{path_prefix}{prop_name}."))

                        # Check for additionalProperties
                        additional = schema_obj.get("additionalProperties")
                        if additional and isinstance(additional, dict):
                            url_findings.extend(check_schema_for_urls(additional, f"{path_prefix}[additionalProperties]."))

                        return url_findings

                    findings.extend(check_schema_for_urls(schema))

        return findings

    def _detect_api8_security_misconfiguration(self, ep: dict, parsed_data: dict, deployment_result: dict = None) -> list:
        """API8: Security Misconfiguration - cross-reference with Deployment agent."""
        findings = []
        path = ep["path"]
        method = ep["method"]

        # Cross-reference with deployment agent results
        if deployment_result:
            deployment_findings = deployment_result.get("findings", [])

            # Check if docs are exposed
            for df in deployment_findings:
                if df.get("vulnerability") == "API Documentation Exposed" or df.get("issue") == "docs_exposed":
                    findings.append({
                        "endpoint": path,
                        "method": method,
                        "vulnerability": "Security Misconfiguration (API8)",
                        "owasp_category": "OWASP API8:2023",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "description": "API documentation is exposed, revealing internal structure to attackers.",
                        "evidence": "Deployment agent detected docs_exposed: true",
                        "exploit_scenario": "An attacker accesses exposed API docs to understand the API structure and find vulnerabilities.",
                        "remediation": "Disable or restrict access to API documentation in production."
                    })

            # Check for missing security headers
            for df in deployment_findings:
                if "security header" in df.get("vulnerability", "").lower() or df.get("issue") == "missing_security_headers":
                    findings.append({
                        "endpoint": path,
                        "method": method,
                        "vulnerability": "Security Misconfiguration (API8)",
                        "owasp_category": "OWASP API8:2023",
                        "severity": "MEDIUM",
                        "confidence": "HIGH",
                        "description": "Missing security headers detected by deployment agent.",
                        "evidence": f"Deployment finding: {df.get('vulnerability', 'missing security headers')}",
                        "exploit_scenario": "Without proper security headers, API is vulnerable to clickjacking, XSS, and other attacks.",
                        "remediation": "Configure security headers (CSP, X-Frame-Options, X-Content-Type-Options, etc.) on the API server."
                    })

        # Check for verbose error responses
        responses = ep.get("responses", [])
        if "500" in responses or "400" in responses:
            # Check if error responses have descriptions (could be verbose)
            for resp_code in responses:
                if resp_code in ["500", "400"]:
                    findings.append({
                        "endpoint": path,
                        "method": method,
                        "vulnerability": "Security Misconfiguration (API8)",
                        "owasp_category": "OWASP API8:2023",
                        "severity": "LOW",
                        "confidence": "POTENTIAL",
                        "description": f"Endpoint has {resp_code} error responses which may expose sensitive information in error messages.",
                        "evidence": f"Response code {resp_code} defined without specification of error content restrictions",
                        "exploit_scenario": "Verbose error messages may reveal internal implementation details.",
                        "remediation": "Ensure error responses do not expose stack traces or internal system information."
                    })

        return findings

    def _detect_api9_improper_inventory(self, parsed_data: dict) -> list:
        """API9: Improper Inventory Management detection."""
        findings = []
        endpoints = parsed_data.get("endpoints", [])

        # Collect all paths to check versioning
        paths = [ep["path"] for ep in endpoints]

        # Check for versioning gaps
        has_v1 = any("/v1/" in p for p in paths)
        has_v2 = any("/v2/" in p for p in paths)

        if has_v1 and not has_v2:
            findings.append({
                "endpoint": "/v1/*",
                "method": "MULTIPLE",
                "vulnerability": "Improper Inventory Management (API9)",
                "owasp_category": "OWASP API9:2023",
                "severity": "MEDIUM",
                "confidence": "POTENTIAL",
                "description": "API has v1 endpoints but no v2 endpoints, indicating lack of versioning strategy.",
                "evidence": "Found /v1/ paths but no /v2/ paths in the spec",
                "exploit_scenario": "Old API versions may have unpatched vulnerabilities and attackers may continue using deprecated v1 endpoints.",
                "remediation": "Implement API versioning strategy. Consider deprecating v1 and migrating clients to v2."
            })

        # Check for deprecated endpoints
        for ep in endpoints:
            summary = ep.get("summary", "").lower()
            description = ""  # Would need to be added to parsed_data if available

            if "deprecated" in summary or ep.get("deprecated"):
                findings.append({
                    "endpoint": ep["path"],
                    "method": ep["method"],
                    "vulnerability": "Improper Inventory Management (API9)",
                    "owasp_category": "OWASP API9:2023",
                    "severity": "MEDIUM",
                    "confidence": "HIGH",
                    "description": "Endpoint is marked as deprecated but may still be operational.",
                    "evidence": f"Endpoint marked deprecated: {ep['path']}",
                    "exploit_scenario": "Clients may still use deprecated endpoints which may have unpatched vulnerabilities.",
                    "remediation": "Ensure deprecated endpoints are still monitored and have reduced time-to-live for security patches."
                })

        # Check for shadow APIs (endpoints that look like they might be undocumented)
        # This is more of an inference check
        shadow_keywords = ["hidden", "secret", "private", "internal", "test", "debug"]
        for ep in endpoints:
            path_lower = ep["path"].lower()
            if any(kw in path_lower for kw in shadow_keywords):
                findings.append({
                    "endpoint": ep["path"],
                    "method": ep["method"],
                    "vulnerability": "Improper Inventory Management - Shadow API (API9)",
                    "owasp_category": "OWASP API9:2023",
                    "severity": "LOW",
                    "confidence": "LOW",
                    "description": "Endpoint path contains keywords that may indicate undocumented or internal functionality.",
                    "evidence": f"Path contains shadow keyword: {ep['path']}",
                    "exploit_scenario": "Shadow endpoints may have weaker security controls and could be exploited if discovered.",
                    "remediation": "Review endpoint list and ensure all endpoints are documented and properly secured."
                })

        return findings

    def _detect_api10_unsafe_consumption(self, ep: dict, parsed_data: dict) -> list:
        """API10: Unsafe Consumption of APIs detection."""
        findings = []
        path = ep["path"]
        method = ep["method"]

        # Check servers array for non-localhost URLs
        servers = parsed_data.get("servers", [])
        external_servers = []
        for server in servers:
            if isinstance(server, dict):
                url = server.get("url", "")
            else:
                url = str(server)

            if url and not any(local in url.lower() for local in ["localhost", "127.0.0.1", "0.0.0.0"]):
                if url.startswith("http"):
                    external_servers.append(url)

        if external_servers:
            findings.append({
                "endpoint": path,
                "method": method,
                "vulnerability": "Unsafe Consumption of APIs (API10)",
                "owasp_category": "OWASP API10:2023",
                "severity": "MEDIUM",
                "confidence": "POTENTIAL",
                "description": "API spec references external servers, suggesting integration with third-party services that may not be trustworthy.",
                "evidence": f"External servers defined: {', '.join(external_servers)}",
                "exploit_scenario": "API may be integrating with untrusted external services, potentially exposing data to malicious third parties.",
                "remediation": "Validate and sanitize all data from external API integrations. Use allowlists for trusted services only."
            })

        # Check for OAuth/webhook URLs in security schemes
        security_schemes = parsed_data.get("components", {}).get("securitySchemes", {})
        for scheme_name, scheme in security_schemes.items():
            if isinstance(scheme, dict):
                scheme_type = scheme.get("type", "")
                if scheme_type == "oauth2":
                    flows = scheme.get("flows", {})
                    for flow_name, flow in flows.items():
                        auth_url = flow.get("authorizationUrl", "")
                        token_url = flow.get("tokenUrl", "")
                        if auth_url and not any(local in auth_url.lower() for local in ["localhost", "127.0.0.1"]):
                            findings.append({
                                "endpoint": path,
                                "method": method,
                                "vulnerability": "Unsafe Consumption of APIs (API10)",
                                "owasp_category": "OWASP API10:2023",
                                "severity": "MEDIUM",
                                "confidence": "POTENTIAL",
                                "description": "OAuth flow references external authorization server.",
                                "evidence": f"OAuth {flow_name} authorizationUrl: {auth_url}",
                                "exploit_scenario": "OAuth integration with external providers may expose authentication flow to malicious services.",
                                "remediation": "Use trusted OAuth providers and validate all redirects."
                            })
                        if token_url and not any(local in token_url.lower() for local in ["localhost", "127.0.0.1"]):
                            findings.append({
                                "endpoint": path,
                                "method": method,
                                "vulnerability": "Unsafe Consumption of APIs (API10)",
                                "owasp_category": "OWASP API10:2023",
                                "severity": "LOW",
                                "confidence": "POTENTIAL",
                                "description": "OAuth flow references external token server.",
                                "evidence": f"OAuth {flow_name} tokenUrl: {token_url}",
                                "exploit_scenario": "External token servers may be compromised or untrustworthy.",
                                "remediation": "Use trusted OAuth providers and ensure token endpoints are secure."
                            })

                # Check for API keys in query parameters
                if scheme_type == "apiKey":
                    api_key_location = scheme.get("in", "")
                    if api_key_location == "query":
                        findings.append({
                            "endpoint": path,
                            "method": method,
                            "vulnerability": "Unsafe Consumption of APIs (API10)",
                            "owasp_category": "OWASP API10:2023",
                            "severity": "LOW",
                            "confidence": "HIGH",
                            "description": "API key is passed in query parameter, which may be logged in URLs and exposed.",
                            "evidence": f"Security scheme '{scheme_name}' passes API key in query string",
                            "exploit_scenario": "API keys in query parameters can be leaked through server logs, browser history, and referrer headers.",
                            "remediation": "Use header-based API key authentication instead of query parameters. Pass keys in Authorization header."
                        })

        # Check for webhook/callback patterns in path
        callback_patterns = ["webhook", "callback", "notify", "hook", "event"]
        if any(pattern in path.lower() for pattern in callback_patterns):
            findings.append({
                "endpoint": path,
                "method": method,
                "vulnerability": "Unsafe Consumption of APIs (API10)",
                "owasp_category": "OWASP API10:2023",
                "severity": "MEDIUM",
                "confidence": "POTENTIAL",
                "description": "Endpoint appears to be a webhook/callback receiver that may accept requests from external sources.",
                "evidence": f"Path contains webhook/callback pattern: {path}",
                "exploit_scenario": "Webhook endpoints may receive malicious payloads from external sources and could be exploited if input is not properly validated.",
                "remediation": "Implement signature verification for webhooks, use HTTPS, and validate all incoming payload data."
            })

        return findings

    def _fallback_logic(self, parsed_data: dict, deployment_result: dict = None) -> list:
        """Original rule-based logic from v1 + OWASP API5-10 detection. Used when LLM is unavailable."""
        findings = []
        endpoints = parsed_data.get("endpoints", [])
        sensitive_keywords = ["users", "accounts", "orders", "profiles"]

        for ep in endpoints:
            path = ep["path"]
            method = ep["method"]

            # API1: BOLA - Object-level authorization
            if "{" in path and "}" in path:
                findings.append({
                    "endpoint": path,
                    "method": method,
                    "vulnerability": "Broken Object Level Authorization (BOLA)",
                    "owasp_category": "OWASP API1:2023",
                    "severity": "HIGH",
                    "confidence": "POTENTIAL",
                    "description": "Endpoint uses object identifiers which may allow unauthorized access to other user resources.",
                    "evidence": f"Path contains path parameter: {path}",
                    "exploit_scenario": f"An attacker changes the ID in {path} to access another user's {path.split('/')[-1].strip('{}')}.",
                    "remediation": "Implement object-level authorization checks to verify the user owns the requested resource."
                })

            # API2: Broken Authentication
            sensitive_methods = ["POST", "PUT", "PATCH", "DELETE"]
            if method in sensitive_methods:
                endpoint_security = ep.get("security", [])
                if not endpoint_security:
                    findings.append({
                        "endpoint": path,
                        "method": method,
                        "vulnerability": "Broken Authentication",
                        "owasp_category": "OWASP API2:2023",
                        "severity": "HIGH",
                        "confidence": "POTENTIAL",
                        "description": f"{method} endpoint may require authentication but none was detected in the spec.",
                        "evidence": f"Method {method} on {path} has no security scheme defined.",
                        "exploit_scenario": f"An attacker sends a {method} request to {path} without credentials and gains unauthorized access.",
                        "remediation": "Add authentication (JWT, OAuth, API keys) and ensure all sensitive endpoints require valid credentials."
                    })

            # API3: Excessive Data Exposure
            if method == "GET":
                if any(keyword in path.lower() for keyword in sensitive_keywords):
                    findings.append({
                        "endpoint": path,
                        "method": method,
                        "vulnerability": "Excessive Data Exposure",
                        "owasp_category": "OWASP API3:2023",
                        "severity": "MEDIUM",
                        "confidence": "POTENTIAL",
                        "description": "Endpoint may expose sensitive object data in responses beyond what the client needs.",
                        "evidence": f"GET endpoint {path} returns full objects for {', '.join(sensitive_keywords)}.",
                        "exploit_scenario": "API returns full database objects including internal fields that should not be exposed to clients.",
                        "remediation": "Implement response filtering to return only necessary fields. Use a whitelist of allowed fields."
                    })

            # API4: Lack of Rate Limiting
            rate_limit_keywords = ["login", "auth", "token", "search", "password"]
            if any(keyword in path.lower() for keyword in rate_limit_keywords):
                findings.append({
                    "endpoint": path,
                    "method": method,
                    "vulnerability": "Lack of Rate Limiting",
                    "owasp_category": "OWASP API4:2023",
                    "severity": "MEDIUM",
                    "confidence": "POTENTIAL",
                    "description": "Endpoint may be vulnerable to brute-force or abuse without rate limiting.",
                    "evidence": f"Path contains '{'/'.join(rate_limit_keywords)}' but no rate limit policy is defined.",
                    "exploit_scenario": "An attacker makes repeated requests to this endpoint to brute-force credentials or overwhelm the service.",
                    "remediation": "Implement rate limiting (e.g., 100 req/min per IP) and return 429 Too Many Requests when exceeded."
                })

            # API5: BFLA - Broken Function Level Authorization
            findings.extend(self._detect_api5_bfla(ep, parsed_data))

            # API6: Unrestricted Resource Consumption
            findings.extend(self._detect_api6_unrestricted_resource(ep, parsed_data))

            # API7: SSRF - Server-Side Request Forgery
            findings.extend(self._detect_api7_ssrf(ep, parsed_data))

            # API8: Security Misconfiguration
            findings.extend(self._detect_api8_security_misconfiguration(ep, parsed_data, deployment_result))

        # API9: Improper Inventory Management (runs on overall spec)
        findings.extend(self._detect_api9_improper_inventory(parsed_data))

        # API10: Unsafe Consumption of APIs
        for ep in endpoints:
            findings.extend(self._detect_api10_unsafe_consumption(ep, parsed_data))

        return findings

    def run(self, parsed_data: dict, planner_result: dict = None, deployment_result: dict = None) -> dict:
        endpoints = parsed_data.get("endpoints", [])
        planner_plan = planner_result.get("plan", {}) if planner_result else {}
        high_risk_endpoints = planner_plan.get("high_risk_endpoints", []) if planner_plan else []

        system_prompt = (
            "You are an expert API security analyst performing a penetration test.\n"
            "Your task is to analyze each API endpoint for security vulnerabilities.\n"
            "Respond ONLY in valid JSON. Do not add any explanation, markdown, or text outside the JSON."
        )

        all_findings = []

        for ep in endpoints:
            path = ep["path"]
            method = ep["method"]
            summary = ep.get("summary", "")
            parameters = ep.get("parameters", [])
            responses = ep.get("responses", [])
            request_body = ep.get("request_body", {})

            # Get planner context for this endpoint if available
            planner_context = None
            for hre in high_risk_endpoints:
                if hre.get("path") == path and hre.get("method") == method:
                    planner_context = hre
                    break

            endpoint_context = f"""Endpoint: {method} {path}
Summary: {summary}
Parameters: {json.dumps(parameters)}
Request Body: {json.dumps(request_body)}
Responses: {json.dumps(responses)}"""
            if planner_context:
                endpoint_context += f"""
Planner Assessment:
  Risk Level: {planner_context.get('risk_level', 'UNKNOWN')}
  Risk Reasons: {json.dumps(planner_context.get('risk_reasons', []))}
  Recommended Tests: {json.dumps(planner_context.get('recommended_tests', []))}
  Attack Vectors: {json.dumps(planner_context.get('attack_vectors', []))}"""

            user_prompt = f"""Analyze this API endpoint for security vulnerabilities:

{endpoint_context}

Respond ONLY with a valid JSON array of findings (empty array if no issues):
[
  {{
    "vulnerability": "Specific vulnerability name",
    "owasp_category": "OWASP API category (e.g., OWASP API1:2023 through OWASP API10:2023)",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "confidence": "HIGH|MEDIUM|LOW",
    "description": "Specific description of the vulnerability for this endpoint",
    "evidence": "What in the spec suggests this vulnerability exists",
    "exploit_scenario": "How an attacker would exploit this vulnerability",
    "remediation": "Specific steps to fix this vulnerability for this endpoint"
  }}
]

OWASP API Security Top 10 2023 categories to consider:
- OWASP API1:2023 - Broken Object Level Authorization (BOLA): Path parameters that could allow accessing other users' resources
- OWASP API2:2023 - Broken Authentication: Endpoints without proper authentication
- OWASP API3:2023 - Excessive Data Exposure: Endpoints returning more data than needed
- OWASP API4:2023 - Lack of Rate Limiting: Endpoints vulnerable to brute-force or abuse
- OWASP API5:2023 - Broken Function Level Authorization (BFLA): Admin endpoints or sensitive methods without proper auth
- OWASP API6:2023 - Unrestricted Resource Consumption: Missing size limits on arrays, strings, no rate limiting
- OWASP API7:2023 - Server-Side Request Forgery (SSRF): URL/URI parameters that could access internal resources
- OWASP API8:2023 - Security Misconfiguration: Verbose errors, missing security headers, exposed docs
- OWASP API9:2023 - Improper Inventory Management: Versioning gaps, deprecated endpoints, shadow APIs
- OWASP API10:2023 - Unsafe Consumption of APIs: External server references, webhooks, API keys in query params

Rules:
- CRITICAL: Direct code execution, SQL injection, authentication bypass
- HIGH: BOLA, broken auth, sensitive data exposure without auth
- MEDIUM: Lack of rate limiting, excessive data exposure, missing security headers
- LOW: Informational or low-risk items
- If the endpoint has no security issues, return []
- Do not include any text before or after the JSON array."""

            raw = self._call_llm([
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ])

            if raw is not None:
                result = parse_llm_json(raw, fallback=None)
                if result is not None and isinstance(result, list):
                    for finding in result:
                        finding["endpoint"] = path
                        finding["method"] = method
                    all_findings.extend(result)
                    continue

            # Fallback: use v1+v2 rule-based logic for this endpoint
            fallback_findings = self._fallback_logic({"endpoints": [ep]}, deployment_result)
            all_findings.extend(fallback_findings)

        # Deduplicate: (endpoint, method, vulnerability) must be unique
        seen = set()
        deduped = []
        for f in all_findings:
            key = (f.get("endpoint"), f.get("method"), f.get("vulnerability"))
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        critical_count = len([f for f in deduped if f.get("severity") == "CRITICAL"])
        high_count = len([f for f in deduped if f.get("severity") == "HIGH"])

        return {
            "agent": "security",
            "status": "completed",
            "llm_used": any(f.get("confidence") != "POTENTIAL" for f in deduped) if deduped else False,
            "total_findings": len(deduped),
            "critical_count": critical_count,
            "high_count": high_count,
            "findings": deduped
        }