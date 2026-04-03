# backend/app/agents/security_agent.py
#
# Step 4 upgrades over the original:
#
#  1. Every finding now has detection_type ("STATIC") and confidence
#     ("LOW" / "MEDIUM" / "HIGH")
#  2. STATIC findings are capped at MEDIUM severity — only live-confirmed
#     findings may be HIGH/CRITICAL (set by synthesis in a later step)
#  3. Deduplication — path-level for BOLA/auth, method-level for others
#     so the same endpoint doesn't produce 3 identical BOLA findings
#  4. Graduated BOLA detection — only fires when there is actually a
#     path parameter present
#  5. Graduated auth detection — considers whether a security scheme
#     exists in the spec before flagging
#  6. Finding names communicate certainty:
#     "Potential BOLA — Object ID in Path (Static)"  not just "BOLA"

import logging

logger = logging.getLogger(__name__)

# Keywords that suggest a path parameter is user-scoped (higher BOLA risk)
USER_SCOPED_PARAMS = [
    "user", "account", "profile", "customer", "member",
    "order", "invoice", "payment", "cart", "id",
]

# Keywords that flag rate-limiting concern
RATE_LIMIT_KEYWORDS = [
    "login", "auth", "token", "search", "password", "reset",
]

# Keywords that flag data exposure concern
SENSITIVE_KEYWORDS = [
    "users", "accounts", "orders", "profiles", "payments",
    "invoices", "customers", "members",
]


class SecurityAgent:

    def run(self, parsed_data: dict, planner_result: dict = None) -> dict:
        endpoints   = parsed_data.get("endpoints", [])
        auth_config = parsed_data.get("auth", {})
        auth_type   = auth_config.get("type", "none")

        # Collect high-risk paths from planner if available
        planner_high_risk = set()
        if planner_result:
            plan = planner_result.get("plan", {})
            for ep in plan.get("high_risk_endpoints", []):
                planner_high_risk.add(ep.get("path", ""))

        raw_findings = []

        for ep in endpoints:
            path   = ep["path"]
            method = ep["method"]
            has_param      = "{" in path and "}" in path
            has_auth_scheme = auth_type != "none"

            # ── OWASP API1: BOLA ─────────────────────────────────
            # Only fire if there is actually a path parameter
            if has_param:
                # Confidence based on param name and auth presence
                param_name = path.split("{")[1].split("}")[0].lower() \
                    if "{" in path else ""
                user_scoped = any(kw in param_name for kw in USER_SCOPED_PARAMS)

                if has_auth_scheme:
                    confidence = "LOW"
                elif user_scoped:
                    confidence = "MEDIUM"
                else:
                    confidence = "LOW"

                # Planner flagged this path → bump confidence
                if path in planner_high_risk and confidence == "LOW":
                    confidence = "MEDIUM"

                raw_findings.append({
                    "endpoint":       path,
                    "method":         method,
                    "risk_type":      "Potential BOLA — Object ID in Path (Static)",
                    "vulnerability":  "Potential BOLA — Object ID in Path (Static)",
                    "severity":       "MEDIUM",   # capped — STATIC finding
                    "confidence":     confidence,
                    "detection_type": "STATIC",
                    "confirmed":      False,
                    "description": (
                        f"Endpoint uses object identifier '{{{param_name}}}' "
                        "which may allow unauthorized access to other users' "
                        "resources if object-level authorization is not enforced."
                    ),
                    "_dedup_key": (path, "BOLA"),  # path-level dedup
                })

            # ── OWASP API2: Broken Authentication ─────────────────
            mutating_methods = ["POST", "PUT", "PATCH", "DELETE"]
            if method in mutating_methods:
                if has_auth_scheme:
                    confidence = "LOW"
                    severity   = "LOW"
                else:
                    confidence = "MEDIUM"
                    severity   = "MEDIUM"   # capped — STATIC

                raw_findings.append({
                    "endpoint":       path,
                    "method":         method,
                    "risk_type":      "Potential Missing Authentication (Static)",
                    "vulnerability":  "Potential Missing Authentication (Static)",
                    "severity":       severity,
                    "confidence":     confidence,
                    "detection_type": "STATIC",
                    "confirmed":      False,
                    "description": (
                        f"{method} endpoint may require authentication "
                        "but no authentication scheme was detected in the spec."
                    ),
                    "_dedup_key": (path, method, "AUTH"),  # method-level dedup
                })

            # ── OWASP API3: Excessive Data Exposure ───────────────
            if method == "GET":
                if any(kw in path.lower() for kw in SENSITIVE_KEYWORDS):
                    raw_findings.append({
                        "endpoint":       path,
                        "method":         method,
                        "risk_type":      "Potential Excessive Data Exposure (Static)",
                        "vulnerability":  "Potential Excessive Data Exposure (Static)",
                        "severity":       "LOW",   # capped — STATIC
                        "confidence":     "LOW",
                        "detection_type": "STATIC",
                        "confirmed":      False,
                        "description": (
                            "GET endpoint on a sensitive resource path may "
                            "return more data than necessary. Consider response "
                            "filtering and field-level access control."
                        ),
                        "_dedup_key": (path, "DATA_EXPOSURE"),
                    })

            # ── OWASP API4: Lack of Rate Limiting ─────────────────
            if any(kw in path.lower() for kw in RATE_LIMIT_KEYWORDS):
                raw_findings.append({
                    "endpoint":       path,
                    "method":         method,
                    "risk_type":      "Potential Lack of Rate Limiting (Static)",
                    "vulnerability":  "Potential Lack of Rate Limiting (Static)",
                    "severity":       "LOW",
                    "confidence":     "LOW",
                    "detection_type": "STATIC",
                    "confirmed":      False,
                    "description": (
                        "Endpoint path suggests a sensitive operation "
                        "(login, auth, search) that may be vulnerable to "
                        "brute-force or abuse without rate limiting."
                    ),
                    "_dedup_key": (path, method, "RATE_LIMIT"),
                })

        # ── Deduplication ─────────────────────────────────────────
        # Keep the finding with the highest confidence per dedup key.
        # Path-level keys (BOLA, DATA_EXPOSURE) deduplicate across methods.
        # Method-level keys (AUTH, RATE_LIMIT) deduplicate per method.
        confidence_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        seen: dict = {}

        for f in raw_findings:
            key = f.pop("_dedup_key")
            existing = seen.get(key)
            if existing is None:
                seen[key] = f
            else:
                # Keep whichever has higher confidence
                if (confidence_rank.get(f["confidence"], 0) >
                        confidence_rank.get(existing["confidence"], 0)):
                    # Carry forward affected_methods from existing
                    f["affected_methods"] = existing.get(
                        "affected_methods", [existing["method"]]
                    )
                    if f["method"] not in f["affected_methods"]:
                        f["affected_methods"].append(f["method"])
                    seen[key] = f
                else:
                    # Existing wins — just add this method to affected list
                    methods = existing.setdefault(
                        "affected_methods", [existing["method"]]
                    )
                    if f["method"] not in methods:
                        methods.append(f["method"])

        findings = list(seen.values())

        # Severity counts
        critical_count = len([f for f in findings if f.get("severity") == "CRITICAL"])
        high_count     = len([f for f in findings if f.get("severity") == "HIGH"])
        medium_count   = len([f for f in findings if f.get("severity") == "MEDIUM"])
        low_count      = len([f for f in findings if f.get("severity") == "LOW"])

        logger.info(
            f"[Security] Completed — {len(findings)} unique findings "
            f"(CRITICAL={critical_count}, HIGH={high_count}, "
            f"MEDIUM={medium_count}, LOW={low_count})"
        )

        return {
            "agent":          "security",
            "status":         "completed",
            "total_findings": len(findings),
            "critical_count": critical_count,
            "high_count":     high_count,
            "medium_count":   medium_count,
            "low_count":      low_count,
            "findings":       findings,
        }