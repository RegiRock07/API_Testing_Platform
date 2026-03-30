class ReportGenerator:

    def generate(self, agent_output: dict) -> dict:
        security = agent_output.get("security", {})
        api = agent_output.get("api_testing", {})
        deployment = agent_output.get("deployment", {})
        deep_scan = agent_output.get("deep_scan", {})
        planner = agent_output.get("planner", {})
        synthesis = agent_output.get("synthesis", {})
        test_gen = agent_output.get("test_generation", {})

        findings = security.get("findings", [])

        # Deep scan enriched findings override originals
        if deep_scan.get("deep_scan_performed"):
            enriched_map = {
                (f.get("endpoint"), f.get("method"), f.get("vulnerability")): f
                for f in deep_scan.get("findings_enriched", [])
            }
            final_findings = []
            for f in findings:
                key = (f.get("endpoint"), f.get("method"), f.get("vulnerability"))
                if key in enriched_map:
                    final_findings.append(enriched_map[key])
                else:
                    final_findings.append(f)
        else:
            final_findings = findings

        # Correlated findings from synthesis
        correlated = synthesis.get("correlated_findings", final_findings)

        # Count severity levels
        critical_count = len([f for f in correlated if f.get("severity") == "CRITICAL"])
        high_count = len([f for f in correlated if f.get("severity") == "HIGH"])
        medium_count = len([f for f in correlated if f.get("severity") == "MEDIUM"])
        low_count = len([f for f in correlated if f.get("severity") == "LOW"])

        # Flatten nested tests array
        all_tests = [t for ep in api.get("results", []) for t in ep.get("tests", [])]
        connection_errors = len([t for t in all_tests if t.get("connection_error")])
        real_failures = len([t for t in all_tests if t.get("passed") is False and not t.get("connection_error")])
        passed_tests = len([t for t in all_tests if t.get("passed") is True])

        # Recommendations (dedup preserving order)
        recs_ordered = []
        recs_seen = set()
        for f in correlated:
            vuln = f.get("vulnerability") or f.get("risk_type", "")
            if "bola" in vuln.lower() or "object level" in vuln.lower():
                rec = "Implement object-level authorization checks to ensure users can only access their own resources."
            elif "auth" in vuln.lower() and "broken" in vuln.lower():
                rec = "Add proper authentication and authorization mechanisms (JWT, OAuth, API keys)."
            elif "excessive data" in vuln.lower():
                rec = "Limit sensitive fields returned in API responses and implement response filtering."
            elif "rate limit" in vuln.lower():
                rec = "Implement rate limiting on sensitive endpoints to prevent brute-force and abuse attacks."
            elif "sql injection" in vuln.lower():
                rec = "Use parameterized queries to prevent SQL injection attacks."
            elif "xss" in vuln.lower():
                rec = "Sanitize and escape user inputs to prevent Cross-Site Scripting (XSS)."
            elif "ssti" in vuln.lower():
                rec = "Use template engines with auto-escaping or avoid passing user input to templates."
            elif "path traversal" in vuln.lower():
                rec = "Validate and sanitize file path inputs to prevent path traversal attacks."
            else:
                rec = None

            if rec and rec not in recs_seen:
                recs_seen.add(rec)
                recs_ordered.append(rec)

        if deployment.get("status") != "healthy":
            rec = "Investigate deployment health and ensure the service is running correctly."
            if rec not in recs_seen:
                recs_seen.add(rec)
                recs_ordered.append(rec)

        if deployment.get("docs_exposed"):
            rec = "Protect internal API documentation — restrict access to /docs and /swagger-ui in production."
            if rec not in recs_seen:
                recs_seen.add(rec)
                recs_ordered.append(rec)

        if deployment.get("cors_misconfigured"):
            rec = "Fix CORS configuration — do not allow all origins (*) for APIs that handle sensitive data."
            if rec not in recs_seen:
                recs_seen.add(rec)
                recs_ordered.append(rec)

        if not recs_ordered:
            recs_ordered.append("No critical risks detected.")

        # Overall risk score
        overall_risk_score = synthesis.get("overall_risk_score", "")
        if not overall_risk_score:
            risk_num = synthesis.get("security_score", 5.0)
            if risk_num >= 7:
                risk_label = "HIGH RISK"
            elif risk_num >= 4:
                risk_label = "MEDIUM RISK"
            else:
                risk_label = "LOW RISK"
            overall_risk_score = f"{risk_num}/10 — {risk_label}"

        report = {
            "summary": {
                "critical_risks": critical_count,
                "high_risks": high_count,
                "medium_risks": medium_count,
                "low_risks": low_count,
                "total_security_findings": len(correlated),
                "total_tests_run": len(all_tests),
                "failed_tests": real_failures,
                "passed_tests": passed_tests,
                "connection_errors": connection_errors,
                "deployment_status": deployment.get("status", "unknown"),
                "deployment_security_score": deployment.get("security_score", "0/6"),
                "overall_risk_score": overall_risk_score,
                "api_was_reachable": api.get("api_was_reachable", False),
                "deep_scan_performed": deep_scan.get("deep_scan_performed", False),
                "llm_generated_tests_run": api.get("llm_generated_tests_run", 0),
                "llm_generated_tests_passed": api.get("llm_generated_tests_passed", 0),
                "auth_used": api.get("auth_used", False),
            },
            "planner_assessment": planner.get("plan", {}),
            "security_findings": correlated,
            "api_test_results": api.get("results", []),
            "deployment": deployment,
            "synthesis": synthesis,
            "test_generation": {
                "llm_used": test_gen.get("llm_used", False),
                "test_cases_generated": test_gen.get("test_cases_generated", 0),
                "test_cases": test_gen.get("test_cases", []),
            },
            "executive_summary": synthesis.get("executive_summary", ""),
            "remediation_roadmap": synthesis.get("remediation_roadmap", {}),
            "security_score": synthesis.get("security_score", 5.0),
            "recommendations": recs_ordered,
        }

        return report
