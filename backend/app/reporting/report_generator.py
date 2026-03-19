class ReportGenerator:

    def generate(self, agent_output):
        security = agent_output["security"]
        api = agent_output["api_testing"]
        deployment = agent_output["deployment"]

        findings = security["findings"]

        # Count only HIGH severity risks
        high_risks = len([f for f in findings if f.get("severity") == "HIGH"])

        # FIX #1: flatten nested tests array before counting failures
        all_tests = [t for r in api["results"] for t in r.get("tests", [])]
        failed_tests = len([t for t in all_tests if t.get("passed") is False])

        report = {
            "summary": {
                "high_risks": high_risks,
                "total_security_findings": len(findings),
                "total_tests_run": len(all_tests),
                "failed_tests": failed_tests,
                "passed_tests": len(all_tests) - failed_tests,
                "deployment_status": deployment["status"]
            },
            "security_findings": findings,
            "api_test_results": api["results"],
            "deployment": deployment,
            "recommendations": self._generate_recommendations(findings, deployment)
        }

        return report

    def _generate_recommendations(self, findings, deployment):
        recs = []

        for f in findings:
            if f["risk_type"] == "Broken Object Level Authorization (BOLA)":
                recs.append(
                    "Implement object-level authorization checks to ensure users can only access their own resources."
                )

            if f["risk_type"] == "Broken Authentication":
                recs.append(
                    "Add proper authentication and authorization mechanisms (JWT, OAuth, API keys)."
                )

            if f["risk_type"] == "Excessive Data Exposure":
                recs.append(
                    "Limit sensitive fields returned in API responses and implement response filtering."
                )

            if f["risk_type"] == "Lack of Rate Limiting":
                recs.append(
                    "Implement rate limiting on sensitive endpoints to prevent brute-force and abuse attacks."
                )

        if deployment["status"] != "healthy":
            recs.append(
                "Investigate deployment health and ensure the service is running correctly."
            )

        if not recs:
            recs.append("No critical risks detected.")

        return list(set(recs))