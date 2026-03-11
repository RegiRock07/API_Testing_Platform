class ReportGenerator:

    def generate(self, agent_output):
        security = agent_output["security"]
        api = agent_output["api_testing"]
        deployment = agent_output["deployment"]

        findings = security["findings"]

        # Count only HIGH severity risks
        high_risks = len([f for f in findings if f.get("severity") == "HIGH"])

        failed_tests = len([r for r in api["results"] if not r.get("passed")])

        report = {
            "summary": {
                "high_risks": high_risks,
                "total_security_findings": len(findings),
                "failed_tests": failed_tests,
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

        if deployment["status"] != "healthy":
            recs.append(
                "Investigate deployment health and ensure the service is running correctly."
            )

        if not recs:
            recs.append("No critical risks detected.")

        return list(set(recs))  # remove duplicates