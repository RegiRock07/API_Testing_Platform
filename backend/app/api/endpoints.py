# backend/app/api/endpoints.py
#
# Spec upload, discovery and blocking scan endpoints.
#
#  - /api/specs/upload and /api/specs/upload-file accept an optional
#    `base_url` that overrides the target derived from the spec's `servers`
#  - /api/scan-url/discover finds + stores a spec (or saves a baseline
#    scan when there is none) and returns its id; the frontend then streams
#    the scan with /api/run/{id}/stream
#  - /api/scan-url is the older blocking variant and shares the discovery code

from fastapi import APIRouter, Body, HTTPException, UploadFile, File, Form
from pydantic import BaseModel
from typing import Optional
from urllib.parse import urlparse
import json
import yaml
import requests

from app.schemas.api_spec import APISpecUpload, APISpecResponse, ScanOptions
from app.services.spec_parser import SpecParser
from app.services.baseline import run_baseline_checks
from app.services.compare import compare_reports
from app.orchestrator import Orchestrator
from app.database import list_scans, get_scan, delete_scan, save_report, save_scan
from app.api.firebase_auth import AuthDep

router       = APIRouter()
spec_parser  = SpecParser()
orchestrator = Orchestrator()


# ─────────────────────────────────────────
# Request models + helpers
# ─────────────────────────────────────────

class URLScanRequest(BaseModel):
    base_url:   str       # API root (https://host/api) or a spec URL (https://host/openapi.json)
    auth_token: str = ""


def _normalize_url(url: Optional[str], field: str = "base_url") -> Optional[str]:
    """'' / None -> None; otherwise must be an absolute http(s) URL."""
    url = (url or "").strip()
    if not url:
        return None
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.netloc:
        raise HTTPException(status_code=400,
                            detail=f"{field} must be an absolute http(s) URL, e.g. https://api.example.com")
    return url.rstrip("/")


def _store_uploaded(name: str, spec: dict, base_url: Optional[str]) -> APISpecResponse:
    try:
        parsed_data = spec_parser.parse_spec(spec)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if base_url:
        parsed_data["base_url"] = base_url          # explicit target wins over `servers`
    spec_id = spec_parser.store_spec(name, spec, parsed_data)
    return APISpecResponse(id=spec_id, name=name, status="parsed",
                           endpoints_count=parsed_data["total_endpoints"],
                           base_url=parsed_data.get("base_url"))


def _require_spec_scan(spec_id: str) -> dict:
    scan = spec_parser.get_spec(spec_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Spec not found")
    if (scan.get("parsed_data") or {}).get("scan_type") == "baseline":
        raise HTTPException(status_code=400,
                            detail="This is a baseline (no-spec) scan; there is no spec to run agents on.")
    return scan


# ─────────────────────────────────────────
# Scan History
# ─────────────────────────────────────────

@router.get("/api/scans", dependencies=[AuthDep])
def get_scan_history():
    return list_scans(limit=100)


# Declared before /api/scans/{scan_id}/... so "compare" is never read as an id
@router.get("/api/scans/compare", dependencies=[AuthDep])
def compare_scans(base: str, target: str):
    """
    What changed between two scans of the same API. `base` is the older
    scan, `target` the newer. Findings are matched by their `id`.
    """
    if base == target:
        raise HTTPException(status_code=400, detail="Pick two different scans to compare")

    scans = {}
    for role, scan_id in (("base", base), ("target", target)):
        scan = get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail=f"{role} scan {scan_id} not found")
        report = scan.get("report")
        if not report:
            raise HTTPException(status_code=400, detail=f"{role} scan {scan_id} has no report yet")
        if report.get("scan_type") == "baseline":
            raise HTTPException(status_code=400,
                                detail=f"{role} scan {scan_id} is a baseline (no-spec) scan; nothing to compare")
        scans[role] = scan

    def meta(scan: dict) -> dict:
        return {"id": scan["id"], "name": scan.get("name"), "api_title": scan.get("api_title"),
                "created_at": scan.get("created_at"), "endpoint_count": scan.get("endpoint_count"),
                "base_url": (scan.get("parsed_data") or {}).get("base_url")}

    return {
        "base":     meta(scans["base"]),
        "target":   meta(scans["target"]),
        "same_api": scans["base"].get("api_title") == scans["target"].get("api_title"),
        **compare_reports(scans["base"]["report"], scans["target"]["report"]),
    }


@router.get("/api/scans/{scan_id}/report", dependencies=[AuthDep])
def get_scan_report(scan_id: str):
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not scan.get("report"):
        raise HTTPException(status_code=404, detail="Report not yet generated")
    return scan["report"]


@router.delete("/api/scans/{scan_id}", dependencies=[AuthDep])
def remove_scan(scan_id: str):
    deleted = delete_scan(scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"status": "deleted", "id": scan_id}


# ─────────────────────────────────────────
# Upload OpenAPI Spec (JSON body)
# ─────────────────────────────────────────

@router.post("/api/specs/upload", response_model=APISpecResponse,
             dependencies=[AuthDep])
def upload_api_spec(upload: APISpecUpload):
    base_url = _normalize_url(upload.base_url)
    try:
        return _store_uploaded(upload.name, upload.spec, base_url)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing spec: {e}")


# ─────────────────────────────────────────
# Upload OpenAPI File (multipart: file, optional base_url)
# ─────────────────────────────────────────

@router.post("/api/specs/upload-file", response_model=APISpecResponse,
             dependencies=[AuthDep])
async def upload_spec_file(file: UploadFile = File(...),
                           base_url: Optional[str] = Form(default=None)):
    base_url = _normalize_url(base_url)
    content  = await file.read()
    name     = file.filename or "uploaded_spec"
    if not name.lower().endswith((".json", ".yaml", ".yml")):
        raise HTTPException(status_code=400, detail="Unsupported file format (use .json, .yaml or .yml)")
    try:
        spec = json.loads(content) if name.lower().endswith(".json") else yaml.safe_load(content)
    except (ValueError, yaml.YAMLError) as e:
        raise HTTPException(status_code=400, detail=f"Could not parse {name}: {e}")
    try:
        return _store_uploaded(name, spec, base_url)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing spec: {e}")


# ─────────────────────────────────────────
# Get Stored Spec
# ─────────────────────────────────────────

@router.get("/api/specs/{spec_id}", dependencies=[AuthDep])
def get_spec(spec_id: str):
    scan = spec_parser.get_spec(spec_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Spec not found")
    return scan["parsed_data"]


# ─────────────────────────────────────────
# Run Agents on Stored Spec (blocking)
# ─────────────────────────────────────────

@router.post("/api/run/{spec_id}", dependencies=[AuthDep])
def run_agents(spec_id: str, options: Optional[ScanOptions] = Body(default=None)):
    """Blocking scan. Body (optional): {"safe_mode": bool, "auth": {...}}."""
    scan   = _require_spec_scan(spec_id)
    result = orchestrator.run_all(scan["parsed_data"], (options or ScanOptions()).to_state())
    save_report(spec_id, result)
    return {"status": "completed", "result": result}


# ─────────────────────────────────────────
# OpenAPI Spec Discovery
# ─────────────────────────────────────────

SPEC_CANDIDATES = [
    # Standard
    "/openapi.json", "/openapi.yaml",
    "/swagger.json", "/swagger.yaml",
    "/api-docs", "/api-docs.json", "/api-docs.yaml",
    # Versioned
    "/v1/openapi.json", "/v2/openapi.json", "/v3/openapi.json",
    "/v1/swagger.json", "/v2/swagger.json",
    "/v1/api-docs",     "/v2/api-docs",
    # Framework-specific
    "/api/openapi.json",         # generic
    "/api/swagger.json",
    "/api/schema/",              # Django REST Framework
    "/swagger/v1/swagger.json",  # ASP.NET
    "/v3/api-docs",              # Spring Boot
    "/v3/api-docs.yaml",
    "/.well-known/openapi.json",
    "/docs/openapi.json",
    "/api/v1/openapi.json",
    "/api/v2/openapi.json",
]


class TargetUnreachable(Exception):
    pass


def _fetch_spec(url: str, headers: dict) -> Optional[dict]:
    """GET url and return it if it is an OpenAPI/Swagger document, else None.
    Raises TargetUnreachable when the host cannot be connected to at all."""
    try:
        r = requests.get(url, headers=headers, timeout=8)
    except (requests.ConnectionError, requests.Timeout) as e:
        raise TargetUnreachable(str(e)) from e
    except requests.RequestException:
        return None
    if r.status_code != 200:
        return None
    ct = r.headers.get("content-type", "").lower()
    spec = None
    if "yaml" not in ct and not url.lower().endswith((".yaml", ".yml")):
        try:
            spec = r.json()
        except ValueError:
            spec = None
    if spec is None:
        try:
            spec = yaml.safe_load(r.text)
        except yaml.YAMLError:
            return None
    if isinstance(spec, dict) and "paths" in spec and ("openapi" in spec or "swagger" in spec):
        return spec
    return None


def discover_spec(url: str, auth_token: str = ""):
    """
    Find an OpenAPI spec for `url`, which may be the API root or the spec
    itself. Returns (parsed_data, raw_spec, spec_url); all None if not found.

    The target base URL is the spec's `servers` entry (relative ones are
    resolved against spec_url). With no `servers`, it is the URL the user
    entered — or, if they entered the spec URL itself, the spec's origin.
    """
    url     = url.rstrip("/")
    headers = {"Authorization": f"Bearer {auth_token}"} if auth_token else {}

    # 1. The URL itself may be the spec (https://host/api/v3/openapi.json)
    spec = _fetch_spec(url, headers)
    if spec is not None:
        return spec_parser.parse_spec(spec, spec_url=url), spec, url

    # 2. Well-known locations under the URL
    for path in SPEC_CANDIDATES:
        spec_url = url + path
        try:
            spec = _fetch_spec(spec_url, headers)
        except TargetUnreachable:
            continue
        if spec is not None:
            parsed = spec_parser.parse_spec(spec, spec_url=spec_url)
            if not (spec.get("servers") or spec.get("host")):
                parsed["base_url"] = url        # spec doesn't say: trust the URL entered
            return parsed, spec, spec_url

    return None, None, None


def _baseline_scan(base_url: str) -> tuple[str, dict]:
    """Run baseline checks and save them as a scan. Returns (scan_id, report)."""
    host     = urlparse(base_url).netloc
    baseline = run_baseline_checks(base_url)
    report   = {
        "scan_type":  "baseline",
        "spec_found": False,
        "base_url":   base_url,
        "message":    "No OpenAPI spec discovered at this URL. Ran baseline security checks instead.",
        "tip":        ("For full endpoint testing, enter the spec URL directly "
                       "(e.g. https://host/openapi.json) or upload the spec with a target base URL."),
        "baseline":   baseline,
    }
    parsed = {"scan_type": "baseline", "title": f"Baseline: {host}", "version": "",
              "base_url": base_url, "endpoints": [], "total_endpoints": 0}
    scan_id = save_scan(base_url, {}, parsed)
    save_report(scan_id, report)
    return scan_id, report


def _discover_or_raise(url: str, auth_token: str):
    try:
        return discover_spec(url, auth_token)
    except TargetUnreachable as e:
        raise HTTPException(status_code=502, detail=f"Could not connect to {url}: {e}")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Spec found but could not be parsed: {e}")


# ─────────────────────────────────────────
# Discover (non-blocking scan flow)
# ─────────────────────────────────────────

@router.post("/api/scan-url/discover", dependencies=[AuthDep])
def discover_api_url(request: URLScanRequest):
    """
    Find and store the spec for a URL; the client then streams the scan
    via /api/run/{spec_id}/stream. With no spec, baseline checks run here
    and are saved as a scan (spec_found: false).
    """
    url = _normalize_url(request.base_url)
    if not url:
        raise HTTPException(status_code=400, detail="base_url is required")

    parsed_data, raw_spec, spec_url = _discover_or_raise(url, request.auth_token)

    if raw_spec is None:
        scan_id, report = _baseline_scan(url)
        return {
            "status":     "partial",
            "spec_found": False,
            "spec_id":    scan_id,
            "message":    report["message"],
            "report":     report,
        }

    spec_id = spec_parser.store_spec(spec_url, raw_spec, parsed_data)
    return {
        "status":             "discovered",
        "spec_found":         True,
        "spec_id":            spec_id,
        "spec_discovered_at": spec_url,
        "base_url":           parsed_data.get("base_url"),
        "endpoints_found":    parsed_data["total_endpoints"],
        "title":              parsed_data.get("title"),
    }


# ─────────────────────────────────────────
# Scan API URL (blocking — kept for API clients)
# ─────────────────────────────────────────

@router.post("/api/scan-url", dependencies=[AuthDep])
def scan_api_url(request: URLScanRequest):
    url = _normalize_url(request.base_url)
    if not url:
        raise HTTPException(status_code=400, detail="base_url is required")

    parsed_data, raw_spec, spec_url = _discover_or_raise(url, request.auth_token)

    if raw_spec is None:
        scan_id, report = _baseline_scan(url)
        return {
            "status":             "partial",
            "spec_found":         False,
            "spec_id":            scan_id,
            "spec_discovered_at": None,
            "endpoints_found":    0,
            "message":            report["message"],
            "tip":                report["tip"],
            "result":             report["baseline"],
            "report":             report,
        }

    spec_id = spec_parser.store_spec(spec_url, raw_spec, parsed_data)
    result  = orchestrator.run_all(parsed_data)
    save_report(spec_id, result)

    return {
        "status":             "completed",
        "spec_id":            spec_id,
        "spec_discovered_at": spec_url,
        "endpoints_found":    parsed_data["total_endpoints"],
        "result":             result,
    }
