# backend/app/reporting/report_generator.py
#
# Step 5 upgrades:
#  - Handles new security finding fields (detection_type, confidence,
#    confirmed, vulnerability)
#  - Handles new deployment fields (security_score, deployment_findings,
#    docs_exposed, cors_misconfigured)
#  - Severity counts now include CRITICAL and LOW
#  - Recommendations deduplicated with ordered list (no set() shuffling)
#  - Backward compatible — old finding format (risk_type) still works

from collections import Counter


class ReportGenerator:

    def generate(self, agent_output: dict) -> dict:
        security   = agent_output.get("security", {})
        api        = agent_output.get("api_testing", {})
        deployment = agent_output.get("deployment", {})

        findings = security.get("findings", [])

        # ── Severity counts ───────────────────────────────────────
        critical_count = len([f for f in findings if f.get("severity") == "CRITICAL"])
        high_count     = len([f for f in findings if f.get("severity") == "HIGH"])
        medium_count   = len([f for f in findings if f.get("severity") == "MEDIUM"])
        low_count      = len([f for f in findings if f.get("severity") == "LOW"])

        # Back-compat: old findings used severity HIGH always
        # so high_risks = critical + high
        high_risks = critical_count + high_count

        # ── Test counts ───────────────────────────────────────────
        all_tests    = [
            t for r in api.get("results", [])
            for t in r.get("tests", [])
        ]
        failed_tests = len([t for t in all_tests if t.get("passed") is False])
        passed_tests = len([t for t in all_tests if t.get("passed") is True])

        # ── Deployment summary ────────────────────────────────────
        deployment_status       = deployment.get("status", "unknown")
        deployment_security_score = deployment.get("security_score", "N/A")
        deployment_checks_ran   = deployment_status not in ("unreachable", "unknown")

        # ── Recommendations (ordered, deduplicated) ───────────────
        recommendations = self._build_recommendations(findings, deployment)

        report = {
            "summary": {
                # Severity breakdown
                "critical_risks":          critical_count,
                "high_risks":              high_risks,
                "medium_risks":            medium_count,
                "low_risks":               low_count,
                "total_security_findings": len(findings),
                # Test counts
                "total_tests_run":         len(all_tests),
                "failed_tests":            failed_tests,
                "passed_tests":            passed_tests,
                # Deployment
                "deployment_status":          deployment_status,
                "deployment_security_score":  deployment_security_score,
                "deployment_checks_ran":      deployment_checks_ran,
            },
            "security_findings": findings,
            "api_test_results":  api.get("results", []),
            "deployment":        deployment,
            "recommendations":   recommendations,
        }

        return report

    # ── Recommendations ───────────────────────────────────────────

    @staticmethod
    def _build_recommendations(findings: list, deployment: dict) -> list:
        recs_ordered = []
        recs_seen    = set()

        # Map vulnerability keywords → recommendation text
        rec_map = {
            "bola":            "Implement object-level authorization checks to ensure users can only access their own resources.",
            "object":          "Implement object-level authorization checks to ensure users can only access their own resources.",
            "auth":            "Add proper authentication and authorization mechanisms (JWT, OAuth, API keys).",
            "excessive data":  "Limit sensitive fields returned in API responses and implement response filtering.",
            "rate limit":      "Implement rate limiting on sensitive endpoints to prevent brute-force and abuse attacks.",
            "sql injection":   "Use parameterized queries or an ORM — never interpolate user input into SQL strings.",
            "xss":             "Sanitize and escape all user-supplied input before rendering or returning it.",
            "ssrf":            "Validate and allowlist URL parameters — do not fetch arbitrary user-supplied URLs.",
            "path traversal":  "Validate and sanitize file path inputs — reject any path containing '..' sequences.",
            "data exposure":   "Limit sensitive fields returned in API responses and implement response filtering.",
        }

        # Walk findings in order (most severe first by position)
        for f in findings:
            # Support both old (risk_type) and new (vulnerability) field names
            vuln = (
                f.get("vulnerability") or f.get("risk_type") or ""
            ).lower()

            for key, rec in rec_map.items():
                if key in vuln and rec not in recs_seen:
                    recs_seen.add(rec)
                    recs_ordered.append(rec)

        # Deployment-specific recommendations
        if deployment.get("docs_exposed"):
            rec = "Restrict access to /docs and /swagger-ui in production environments."
            if rec not in recs_seen:
                recs_ordered.append(rec)

        if deployment.get("cors_misconfigured"):
            rec = "Restrict CORS allowed origins — do not use wildcard (*) in production."
            if rec not in recs_seen:
                recs_ordered.append(rec)

        missing_headers = deployment.get("security_headers", {}).get("missing", [])
        if missing_headers:
            rec = (
                f"Add missing security headers: "
                f"{', '.join(missing_headers[:3])}"
                f"{'...' if len(missing_headers) > 3 else ''}."
            )
            if rec not in recs_seen:
                recs_ordered.append(rec)

        if not recs_ordered:
            recs_ordered.append("No critical risks detected — maintain regular security reviews.")

        return recs_ordered