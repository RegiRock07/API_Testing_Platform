# backend/app/services/baseline.py
#
# Runs when no OpenAPI spec is found at a scanned URL.
# Instead of returning an error, we run these baseline checks
# against the base URL alone and return a partial result.
#
# Checks:
#   1. SSL/TLS certificate validity and HTTPS enforcement
#   2. Security headers presence
#   3. CORS misconfiguration
#   4. Exposed sensitive paths
#   5. Allowed HTTP methods (OPTIONS)

import ssl
import socket
import requests
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)


def run_baseline_checks(base_url: str) -> dict:
    """
    Run baseline security checks against a base URL when no OpenAPI
    spec is available. Returns a structured dict with 5 check categories.
    """
    logger.info(f"[Baseline] Running baseline checks for {base_url}")

    result = {
        "ssl":              _check_ssl(base_url),
        "security_headers": _check_security_headers(base_url),
        "cors":             _check_cors(base_url),
        "exposed_paths":    _check_exposed_paths(base_url),
        "allowed_methods":  _check_allowed_methods(base_url),
    }

    logger.info(f"[Baseline] Completed for {base_url}")
    return result


def _check_ssl(base_url: str) -> dict:
    """Check SSL/TLS certificate validity and HTTPS enforcement."""
    parsed   = urlparse(base_url)
    hostname = parsed.hostname
    port     = parsed.port or (443 if parsed.scheme == "https" else 80)
    result   = {"valid": False, "enforced": False}

    if parsed.scheme == "https":
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    result["valid"] = cert is not None
        except ssl.SSLCertVerificationError:
            result["valid"] = False
        except Exception:
            result["valid"] = False

        # Check if HTTP redirects to HTTPS
        http_url = base_url.replace("https://", "http://", 1)
        try:
            r        = requests.get(http_url, timeout=5, allow_redirects=False)
            location = r.headers.get("location", "")
            if r.status_code in (301, 302, 307, 308) and location.startswith("https://"):
                result["enforced"] = True
        except Exception:
            result["enforced"] = True  # Can't reach HTTP — HTTPS-only is fine
    else:
        result["enforced"] = False

    return result


def _check_security_headers(base_url: str) -> dict:
    """Check presence of key security response headers."""
    required = [
        "Strict-Transport-Security",
        "X-Frame-Options",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]
    present = []
    missing = []

    try:
        r = requests.get(base_url, timeout=8, allow_redirects=True)
        for header in required:
            if r.headers.get(header):
                present.append(header)
            else:
                missing.append(header)
    except Exception:
        missing = required[:]

    return {"present": present, "missing": missing}


def _check_cors(base_url: str) -> dict:
    """Check for CORS misconfiguration using an evil origin."""
    result = {"misconfigured": False, "detail": ""}

    try:
        r    = requests.get(
            base_url,
            headers={"Origin": "https://evil.com"},
            timeout=8,
            allow_redirects=True,
        )
        acao = r.headers.get("Access-Control-Allow-Origin", "")

        if acao == "*":
            result["misconfigured"] = True
            result["detail"] = (
                "Access-Control-Allow-Origin is wildcard (*) — "
                "any origin can make cross-site requests."
            )
        elif "evil.com" in acao:
            result["misconfigured"] = True
            result["detail"] = (
                "Origin https://evil.com is reflected in "
                "Access-Control-Allow-Origin header."
            )
        else:
            result["detail"] = "CORS appears properly configured."
    except Exception as e:
        result["detail"] = f"Could not check CORS: {e}"

    return result


def _check_exposed_paths(base_url: str) -> list:
    """Probe sensitive paths and flag any that return HTTP 200."""
    sensitive_paths = [
        "/.env",
        "/admin",
        "/config",
        "/debug",
        "/.git/config",
        "/phpinfo.php",
        "/.aws/credentials",
        "/backup",
    ]

    base_url = base_url.rstrip("/")
    exposed  = []

    for path in sensitive_paths:
        try:
            r = requests.get(
                base_url + path,
                timeout=5,
                allow_redirects=False,
            )
            if r.status_code == 200:
                exposed.append(path)
        except Exception:
            pass

    return exposed


def _check_allowed_methods(base_url: str) -> list:
    """Send OPTIONS request and report allowed HTTP methods."""
    allowed = []

    try:
        r            = requests.options(base_url, timeout=8)
        allow_header = r.headers.get("Allow", "")
        if allow_header:
            allowed = [m.strip() for m in allow_header.split(",") if m.strip()]

        # Also check CORS preflight methods
        if not allowed:
            acam = r.headers.get("Access-Control-Allow-Methods", "")
            if acam:
                allowed = [m.strip() for m in acam.split(",") if m.strip()]
    except Exception:
        pass

    return allowed