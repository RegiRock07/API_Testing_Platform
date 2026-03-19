# backend/app/api/endpoints.py

from fastapi import APIRouter, HTTPException, UploadFile, File, Header, Depends
from pydantic import BaseModel
from typing import Optional
import json
import yaml
import requests
import os

from app.schemas.api_spec import APISpecUpload, APISpecResponse
from app.services.spec_parser import SpecParser
from app.orchestrator import Orchestrator
from app.database import list_scans, get_scan, delete_scan, save_report

router = APIRouter()
spec_parser = SpecParser()
orchestrator = Orchestrator()


# ─────────────────────────────────────────
# Step 5: Auth dependency
# Set SENTINEL_API_KEY env var to enable.
# If unset, skipped entirely (dev mode).
# ─────────────────────────────────────────

SENTINEL_API_KEY = os.getenv("SENTINEL_API_KEY", "")

def require_auth(x_api_key: Optional[str] = Header(default=None)):
    if not SENTINEL_API_KEY:
        return  # dev mode — no auth
    if x_api_key != SENTINEL_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key header")

AuthDep = Depends(require_auth)


# ─────────────────────────────────────────
# Models
# ─────────────────────────────────────────

class URLScanRequest(BaseModel):
    base_url: str
    auth_token: str = ""


# ─────────────────────────────────────────
# Step 3: Scan History
# ─────────────────────────────────────────

@router.get("/api/scans", dependencies=[AuthDep])
def get_scan_history():
    """Return all past scans, most recent first."""
    return list_scans(limit=100)


@router.get("/api/scans/{scan_id}/report", dependencies=[AuthDep])
def get_scan_report(scan_id: str):
    """Return the completed report for a scan."""
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

@router.post("/api/specs/upload", response_model=APISpecResponse, dependencies=[AuthDep])
def upload_api_spec(upload: APISpecUpload):
    try:
        parsed_data = spec_parser.parse_spec(upload.spec)
        spec_id = spec_parser.store_spec(upload.name, upload.spec, parsed_data)
        return APISpecResponse(
            id=spec_id, name=upload.name,
            status="parsed", endpoints_count=parsed_data["total_endpoints"]
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing spec: {str(e)}")


# ─────────────────────────────────────────
# Upload OpenAPI File
# ─────────────────────────────────────────

@router.post("/api/specs/upload-file", dependencies=[AuthDep])
async def upload_spec_file(file: UploadFile = File(...)):
    content = await file.read()
    try:
        if file.filename.endswith(".json"):
            spec = json.loads(content)
        elif file.filename.endswith((".yaml", ".yml")):
            spec = yaml.safe_load(content)
        else:
            raise HTTPException(status_code=400, detail="Unsupported file format")

        parsed_data = spec_parser.parse_spec(spec)
        spec_id = spec_parser.store_spec(file.filename, spec, parsed_data)
        return {"id": spec_id, "status": "parsed", "endpoints": parsed_data["total_endpoints"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
# Run Agents on Stored Spec
# ─────────────────────────────────────────

@router.post("/api/run/{spec_id}", dependencies=[AuthDep])
def run_agents(spec_id: str):
    scan = spec_parser.get_spec(spec_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Spec not found")

    result = orchestrator.run_all(scan["parsed_data"])
    save_report(spec_id, result)

    return {"status": "completed", "result": result}


# ─────────────────────────────────────────
# Real Endpoint Discovery
# ─────────────────────────────────────────

def discover_endpoints(base_url: str, auth_token: str = ""):
    base_url = base_url.rstrip("/")
    candidates = [
        "/openapi.json", "/swagger.json", "/openapi.yaml",
        "/swagger.yaml", "/api-docs", "/v1/openapi.json", "/v2/openapi.json",
    ]
    headers = {"Authorization": f"Bearer {auth_token}"} if auth_token else {}
    last_error = None

    for path in candidates:
        try:
            r = requests.get(base_url + path, headers=headers, timeout=8)
            if r.status_code == 200:
                ct = r.headers.get("content-type", "")
                spec = yaml.safe_load(r.text) if ("yaml" in ct or path.endswith(".yaml")) else r.json()
                if "paths" in spec and ("openapi" in spec or "swagger" in spec):
                    return spec_parser.parse_spec(spec), spec, base_url + path
        except Exception as e:
            last_error = str(e)

    raise HTTPException(
        status_code=422,
        detail=f"No OpenAPI spec found at {base_url}. "
               f"Tried: {', '.join(candidates)}. Last error: {last_error}"
    )


# ─────────────────────────────────────────
# Scan API URL
# ─────────────────────────────────────────

@router.post("/api/scan-url", dependencies=[AuthDep])
def scan_api_url(request: URLScanRequest):
    base_url = request.base_url.rstrip("/")
    parsed_data, raw_spec, spec_url = discover_endpoints(base_url, request.auth_token)

    spec_id = spec_parser.store_spec(base_url, raw_spec, parsed_data)
    parsed_data["base_url"] = base_url

    result = orchestrator.run_all(parsed_data)
    save_report(spec_id, result)

    return {
        "status": "completed",
        "spec_id": spec_id,
        "spec_discovered_at": spec_url,
        "endpoints_found": parsed_data["total_endpoints"],
        "result": result,
    }