class SecurityAgent:

    def run(self, parsed_data):

        findings = []
        endpoints = parsed_data["endpoints"]

        sensitive_keywords = ["users", "accounts", "orders", "profiles"]

        for ep in endpoints:

            path = ep["path"]
            method = ep["method"]

            
            # OWASP API1: BOLA
            
            if "{" in path and "}" in path:
                findings.append({
                    "endpoint": path,
                    "risk_type": "Broken Object Level Authorization (BOLA)",
                    "severity": "HIGH",
                    "confidence": "POTENTIAL",
                    "description": "Endpoint uses object identifiers which may allow unauthorized access to other user resources."
                })

            
            # OWASP API2: Broken Authentication
            
            sensitive_methods = ["POST", "PUT", "PATCH", "DELETE"]

            if method in sensitive_methods:
                findings.append({
                    "endpoint": path,
                    "risk_type": "Broken Authentication",
                    "severity": "HIGH",
                    "confidence": "POTENTIAL",
                    "description": f"{method} endpoint may require authentication but none detected."
                })

            
            # OWASP API3: Excessive Data Exposure
            
            if method == "GET":
                if any(keyword in path.lower() for keyword in sensitive_keywords):

                    findings.append({
                        "endpoint": path,
                        "risk_type": "Excessive Data Exposure",
                        "severity": "MEDIUM",
                        "confidence": "POTENTIAL",
                        "description": "Endpoint may expose sensitive object data in responses."
                    })

        
            # OWASP API4: Lack of Rate Limiting
        
            rate_limit_keywords = ["login", "auth", "token", "search", "password"]

            if any(keyword in path.lower() for keyword in rate_limit_keywords):

                findings.append({
                    "endpoint": path,
                    "risk_type": "Lack of Rate Limiting",
                    "severity": "MEDIUM",
                    "confidence": "POTENTIAL",
                    "description": "Endpoint may be vulnerable to brute-force or abuse without rate limiting."
                })

        return {
            "agent": "security",
            "status": "completed",
            "total_findings": len(findings),
            "findings": findings
        }