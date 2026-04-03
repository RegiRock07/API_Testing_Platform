# backend/app/agents/deployment_agent.py
#
# Step 5 upgrade over the original:
#  - Security headers check (6 headers scored)
#  - HTTPS enforcement check
#  - CORS misconfiguration check
#  - API docs exposure check
#  - Latency measurement
#  - Security score 0-6
#  - Structured deployment_findings list
#
# Falls back cleanly on connection error / timeout — never crashes.

import requests
import time
import logging

logger = logging.getLogger(__name__)

SECURITY_HEADERS = [
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-XSS-Protection",
    "Referrer-Policy",
]

DOCS_PATHS = [
    "/docs",
    "/swagger-ui",
    "/openapi.json",
    "/redoc",
    "/api/docs",
    "/swagger",
]


class DeploymentAgent:

    def run(self, base_url: str = "http://localhost:8000") -> dict:
        base_url   = base_url.rstrip("/")
        start_time = time.time()

        # ── Connectivity check ────────────────────────────────────
        try:
            r          = requests.get(f"{base_url}/health", timeout=10)
            latency_ms = round((time.time() - start_time) * 1000, 2)
            status_code = r.status_code
            status      = "healthy" if r.status_code == 200 else "unhealthy"
        except requests.exceptions.ConnectionError:
            return self._unreachable(
                "Connection refused — service may be down or URL is incorrect"
            )
        except requests.exceptions.Timeout:
            return self._unreachable(
                "Connection timed out — service may be overloaded or unreachable"
            )
        except Exception as e:
            return self._unreachable(str(e))

        deployment_findings = []

        # ── 1. Security headers ───────────────────────────────────
        present_headers = []
        missing_headers = []
        response_header_keys = [h.lower() for h in r.headers.keys()]

        for header in SECURITY_HEADERS:
            if header.lower() in response_header_keys:
                present_headers.append(header)
            else:
                missing_headers.append(header)
                deployment_findings.append({
                    "check": f"security_header:{header}",
                    "issue": (
                        f"Missing {header} — increases XSS, "
                        "clickjacking, and MIME-type sniffing risks"
                    ),
                })

        # ── 2. HTTPS enforcement ──────────────────────────────────
        https_enforced = base_url.startswith("https://")
        if (base_url.startswith("http://") and
                not base_url.startswith("http://localhost") and
                not base_url.startswith("http://127.")):
            deployment_findings.append({
                "check": "https",
                "issue": "API is served over HTTP — data is transmitted in cleartext",
            })

        # ── 3. CORS misconfiguration ──────────────────────────────
        cors_misconfigured = False
        try:
            cors_r = requests.get(
                base_url,
                headers={"Origin": "https://evil.com"},
                timeout=5,
            )
            acao = cors_r.headers.get("Access-Control-Allow-Origin", "")
            if acao == "*":
                cors_misconfigured = True
                deployment_findings.append({
                    "check": "cors",
                    "issue": (
                        "CORS allows all origins (*) — "
                        "sensitive APIs should restrict allowed origins"
                    ),
                })
            elif "evil.com" in acao:
                cors_misconfigured = True
                deployment_findings.append({
                    "check": "cors",
                    "issue": (
                        "CORS reflects arbitrary origins — "
                        "Origin header is echoed back without validation"
                    ),
                })
        except Exception:
            pass  # CORS check is best-effort

        # ── 4. API docs exposure ──────────────────────────────────
        docs_exposed    = False
        docs_exposed_at = None
        for doc_path in DOCS_PATHS:
            try:
                doc_r = requests.get(f"{base_url}{doc_path}", timeout=3)
                if doc_r.status_code == 200:
                    docs_exposed    = True
                    docs_exposed_at = f"{base_url}{doc_path}"
                    deployment_findings.append({
                        "check": "docs_exposure",
                        "issue": (
                            f"API documentation publicly accessible at "
                            f"{base_url}{doc_path} — "
                            "consider restricting in production"
                        ),
                    })
                    break
            except Exception:
                pass

        # ── 5. Security score (0–6) ───────────────────────────────
        score = 0
        if status_code == 200:           score += 1
        if not missing_headers:          score += 1
        if https_enforced:               score += 1
        if not cors_misconfigured:       score += 1
        if not docs_exposed:             score += 1
        if latency_ms and latency_ms < 1000: score += 1

        security_score = f"{score}/6"

        logger.info(
            f"[Deployment] {base_url} — status={status}, "
            f"score={security_score}, latency={latency_ms}ms"
        )

        return {
            "agent":          "deployment",
            "status":         status,
            "status_code":    status_code,
            "latency_ms":     latency_ms,
            "security_headers": {
                "present": present_headers,
                "missing": missing_headers,
            },
            "https_enforced":     https_enforced,
            "cors_misconfigured": cors_misconfigured,
            "docs_exposed":       docs_exposed,
            "docs_exposed_at":    docs_exposed_at,
            "security_score":     security_score,
            "deployment_findings": deployment_findings,
        }

    # ── Helpers ───────────────────────────────────────────────────

    @staticmethod
    def _unreachable(reason: str) -> dict:
        logger.warning(f"[Deployment] Unreachable — {reason}")
        return {
            "agent":          "deployment",
            "status":         "unreachable",
            "status_code":    None,
            "latency_ms":     None,
            "security_headers": {
                "present": [],
                "missing": list(SECURITY_HEADERS),
            },
            "https_enforced":      None,
            "cors_misconfigured":  None,
            "docs_exposed":        None,
            "docs_exposed_at":     None,
            "security_score":      "N/A",
            "deployment_findings": [{
                "check": "connectivity",
                "issue": reason,
            }],
        }