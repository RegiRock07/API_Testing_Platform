from collections import Counter


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

        # Correlated findings from synthesis (may have DYNAMIC promotions)
        correlated = synthesis.get("correlated_findings", final_findings)

        # Severity counts
        critical_count = len([f for f in correlated if f.get("severity") == "CRITICAL"])
        high_count = len([f for f in correlated if f.get("severity") == "HIGH"])
        medium_count = len([f for f in correlated if f.get("severity") == "MEDIUM"])
        low_count = len([f for f in correlated if f.get("severity") == "LOW"])

        # ── New 4-outcome counters from api_testing ──────────────
        security_failure_count = api.get("security_failure_count", 0)
        expected_failure_count = api.get("expected_failure_count", 0)
        pass_count = api.get("pass_count", 0)
        connection_error_count = api.get("connection_error_count", 0)

        # Back-compat flat test list
        all_tests = [t for ep in api.get("results", [])
                     for t in ep.get("tests", [])]

        # ── Pattern-based executive summary ──────────────────────
        executive_summary = self._build_executive_summary(
            correlated, api, synthesis)

        # ── Specific remediation roadmap ─────────────────────────
        remediation_roadmap = self._build_roadmap(correlated)

        # ── Recommendations (dedup) ──────────────────────────────
        recs_ordered = self._build_recommendations(correlated, deployment)

        # Overall risk score
        overall_risk_score = synthesis.get("overall_risk_score", "")
        if not overall_risk_score:
            risk_num = synthesis.get("security_score", 5.0)
            risk_label = ("HIGH RISK" if risk_num >= 7
                          else ("MEDIUM RISK" if risk_num >= 4 else "LOW RISK"))
            overall_risk_score = f"{risk_num}/10 — {risk_label}"

        report = {
            "summary": {
                "critical_risks": critical_count,
                "high_risks": high_count,
                "medium_risks": medium_count,
                "low_risks": low_count,
                "total_security_findings": len(correlated),
                "total_tests_run": len(all_tests),
                # New 4-outcome counters
                "security_failure_count": security_failure_count,
                "expected_failure_count": expected_failure_count,
                "pass_count": pass_count,
                "connection_error_count": connection_error_count,
                # Kept for back-compat
                "failed_tests": security_failure_count,
                "passed_tests": pass_count,
                "connection_errors": connection_error_count,
                "deployment_status": deployment.get("status", "unknown"),
                "deployment_security_score": deployment.get(
                    "security_score", "0/6"),
                "overall_risk_score": overall_risk_score,
                "api_was_reachable": api.get("api_was_reachable", False),
                "deep_scan_performed": deep_scan.get(
                    "deep_scan_performed", False),
                "auth_used": api.get("auth_used", False),
            },
            "planner_assessment": planner.get("plan", {}),
            "security_findings": correlated,
            "api_test_results": api.get("results", []),
            "deployment": deployment,
            "synthesis": synthesis,
            "test_generation": {
                "llm_used": test_gen.get("llm_used", False),
                "test_cases_generated": test_gen.get(
                    "test_cases_generated", 0),
                "test_cases": test_gen.get("test_cases", []),
            },
            "executive_summary": executive_summary,
            "remediation_roadmap": remediation_roadmap,
            "security_score": synthesis.get("security_score", 5.0),
            "recommendations": recs_ordered,
        }

        return report

    # ── Pattern-based executive summary (Problem 7) ───────────────

    @staticmethod
    def _build_executive_summary(correlated, api, synthesis) -> str:
        """
        Build executive_summary from actual finding patterns.
        Must produce DIFFERENT text for DIFFERENT APIs.
        """
        confirmed = [f for f in correlated if f.get("confirmed")]
        static_only = [f for f in correlated
                       if f.get("detection_type") == "STATIC"]
        api_reachable = api.get("api_was_reachable", False)

        parts = []

        # 1. Lead with confirmed count
        if confirmed:
            parts.append(
                f"{len(confirmed)} vulnerabilit{'y was' if len(confirmed) == 1 else 'ies were'} "
                f"confirmed via live testing."
            )
        elif not api_reachable:
            parts.append(
                "No vulnerabilities were confirmed via live testing "
                "(API was unreachable)."
            )
        else:
            parts.append(
                "No vulnerabilities were confirmed via live testing "
                "(all findings are static analysis only)."
            )

        # 2. Check for systemic patterns (5+ in one OWASP category)
        owasp_counter = Counter()
        for f in correlated:
            ocat = f.get("owasp_category", "")
            if ocat:
                owasp_counter[ocat] += 1
        systemic = [(cat, cnt) for cat, cnt in owasp_counter.items()
                    if cnt >= 5]
        if systemic:
            for cat, cnt in systemic:
                parts.append(
                    f"{cnt} findings fall under {cat} — this suggests "
                    f"an architectural gap, not isolated misconfigurations."
                )

        # 3. Close with static count if relevant
        if static_only and not confirmed:
            parts.append(
                f"{len(static_only)} static analysis finding(s) require "
                f"manual investigation with the API running."
            )
        elif static_only:
            parts.append(
                f"{len(static_only)} additional static finding(s) "
                f"should be reviewed."
            )

        # Fallback to synthesis LLM summary if our pattern text is too short
        if len(parts) < 2:
            synth_summary = synthesis.get("executive_summary", "")
            if synth_summary and synth_summary not in " ".join(parts):
                parts.append(synth_summary)

        return " ".join(parts)

    # ── Specific remediation roadmap (Problem 8) ──────────────────

    @staticmethod
    def _build_roadmap(correlated) -> dict:
        """
        Build roadmap items from actual finding data.
        Every item must reference a specific endpoint path or count.
        """
        immediate = []
        short_term = []
        long_term = []

        # Immediate: confirmed=True or CRITICAL severity
        for f in correlated:
            if f.get("confirmed") or f.get("severity") == "CRITICAL":
                ep = f.get("endpoint", "unknown")
                method = f.get("method", "")
                vuln = f.get("vulnerability", "unknown")
                immediate.append(f"Fix {vuln} on {method} {ep}")

        # Short term: HIGH severity STATIC — group by vuln type
        high_static = [f for f in correlated
                       if f.get("severity") == "HIGH"
                       and f.get("detection_type") == "STATIC"
                       and not f.get("confirmed")]
        vuln_groups = {}
        for f in high_static:
            vuln = f.get("vulnerability", "unknown")
            vuln_groups.setdefault(vuln, []).append(
                f"{f.get('method', '')} {f.get('endpoint', '')}")
        for vuln, eps in vuln_groups.items():
            if len(eps) <= 3:
                short_term.append(
                    f"Investigate potential {vuln} on {', '.join(eps)}")
            else:
                short_term.append(
                    f"Investigate potential {vuln} on {', '.join(eps[:3])} "
                    f"and {len(eps) - 3} more")

        # Long term: 3+ same vuln type at MEDIUM/LOW
        medium_low = [f for f in correlated
                      if f.get("severity") in ("MEDIUM", "LOW")]
        vuln_counts = Counter()
        for f in medium_low:
            vuln_counts[f.get("vulnerability", "unknown")] += 1
        for vuln, count in vuln_counts.items():
            if count >= 3:
                long_term.append(
                    f"Implement mitigation for {vuln} across {count} endpoints")

        # Ensure non-empty
        if not immediate:
            immediate.append("No confirmed or critical vulnerabilities requiring immediate action.")
        if not short_term:
            short_term.append("Review static analysis findings for false positives.")
        if not long_term:
            long_term.append("Conduct periodic full penetration testing.")

        return {
            "immediate": immediate,
            "short_term": short_term,
            "long_term": long_term,
        }

    # ── Recommendations (existing logic, cleaned up) ──────────────

    @staticmethod
    def _build_recommendations(correlated, deployment) -> list:
        recs_ordered = []
        recs_seen = set()

        rec_map = {
            "bola": "Implement object-level authorization checks.",
            "object": "Implement object-level authorization checks.",
            "auth": "Add proper authentication mechanisms (JWT, OAuth, API keys).",
            "excessive data": "Limit sensitive fields in API responses.",
            "rate limit": "Implement rate limiting on sensitive endpoints.",
            "sql injection": "Use parameterized queries.",
            "xss": "Sanitize and escape user inputs.",
            "ssrf": "Validate URL parameters against an allowlist.",
            "ssti": "Use template engines with auto-escaping.",
            "path traversal": "Validate and sanitize file path inputs.",
        }

        for f in correlated:
            vuln = (f.get("vulnerability") or "").lower()
            for key, rec in rec_map.items():
                if key in vuln and rec not in recs_seen:
                    recs_seen.add(rec)
                    recs_ordered.append(rec)

        if deployment.get("docs_exposed"):
            rec = "Restrict access to /docs and /swagger-ui in production."
            if rec not in recs_seen:
                recs_ordered.append(rec)

        if not recs_ordered:
            recs_ordered.append("No critical risks detected.")

        return recs_ordered
