from fastapi import APIRouter, HTTPException, UploadFile, File
from pydantic import BaseModel
import json
import yaml
import requests

from app.schemas.api_spec import APISpecUpload, APISpecResponse
from app.services.spec_parser import SpecParser
from app.orchestrator import Orchestrator

router = APIRouter()

spec_parser = SpecParser()
orchestrator = Orchestrator()


# -----------------------------
# URL Scan Request Model
# -----------------------------
class URLScanRequest(BaseModel):
    base_url: str
    auth_token: str = ""   # optional Bearer token for authenticated APIs


# -----------------------------
# Upload OpenAPI Spec (JSON body)
# -----------------------------
@router.post("/api/specs/upload", response_model=APISpecResponse)
def upload_api_spec(upload: APISpecUpload):
    """Upload and parse an OpenAPI specification"""

    try:
        parsed_data = spec_parser.parse_spec(upload.spec)
        spec_id = spec_parser.store_spec(upload.name, upload.spec, parsed_data)

        return APISpecResponse(
            id=spec_id,
            name=upload.name,
            status="parsed",
            endpoints_count=parsed_data["total_endpoints"]
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error processing spec: {str(e)}"
        )


# -----------------------------
# Upload OpenAPI File (JSON/YAML)
# -----------------------------
@router.post("/api/specs/upload-file")
async def upload_spec_file(file: UploadFile = File(...)):

    content = await file.read()

    try:
        if file.filename.endswith(".json"):
            spec = json.loads(content)

        elif file.filename.endswith(".yaml") or file.filename.endswith(".yml"):
            spec = yaml.safe_load(content)

        else:
            raise HTTPException(status_code=400, detail="Unsupported file format")

        parsed_data = spec_parser.parse_spec(spec)
        spec_id = spec_parser.store_spec(file.filename, spec, parsed_data)

        return {
            "id": spec_id,
            "status": "parsed",
            "endpoints": parsed_data["total_endpoints"]
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# -----------------------------
# Get Stored Spec
# -----------------------------
@router.get("/api/specs/{spec_id}")
def get_spec(spec_id: str):

    spec = spec_parser.get_spec(spec_id)

    if not spec:
        raise HTTPException(status_code=404, detail="Spec not found")

    return spec["parsed_data"]


# -----------------------------
# Run Agents on Stored Spec
# -----------------------------
@router.post("/api/run/{spec_id}")
def run_agents(spec_id: str):

    spec = spec_parser.get_spec(spec_id)

    if not spec:
        raise HTTPException(status_code=404, detail="Spec not found")

    result = orchestrator.run_all(spec["parsed_data"])

    return {
        "status": "completed",
        "result": result
    }


# -----------------------------
# FIX #4: Real Endpoint Discovery
# Tries /openapi.json → /swagger.json → /openapi.yaml → fallback
# -----------------------------
def discover_endpoints(base_url: str, auth_token: str = ""):
    """
    Fetch the real OpenAPI spec from the target API.
    Tries common spec paths in order.
    Returns (parsed_data, raw_spec) or raises HTTPException.
    """

    base_url = base_url.rstrip("/")

    candidate_paths = [
        "/openapi.json",
        "/swagger.json",
        "/openapi.yaml",
        "/swagger.yaml",
        "/api-docs",
        "/v1/openapi.json",
        "/v2/openapi.json",
    ]

    headers = {}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    last_error = None

    for path in candidate_paths:
        url = base_url + path
        try:
            r = requests.get(url, headers=headers, timeout=8)

            if r.status_code == 200:
                content_type = r.headers.get("content-type", "")

                # parse YAML or JSON based on content-type or path
                if "yaml" in content_type or path.endswith(".yaml"):
                    spec = yaml.safe_load(r.text)
                else:
                    spec = r.json()

                # validate it looks like an OpenAPI spec
                if "paths" in spec and ("openapi" in spec or "swagger" in spec):
                    parsed = spec_parser.parse_spec(spec)
                    return parsed, spec, url

        except Exception as e:
            last_error = str(e)
            continue

    raise HTTPException(
        status_code=422,
        detail=f"Could not find an OpenAPI spec at {base_url}. "
               f"Tried: {', '.join(candidate_paths)}. "
               f"Last error: {last_error}"
    )


# -----------------------------
# Scan API URL
# -----------------------------
@router.post("/api/scan-url")
def scan_api_url(request: URLScanRequest):

    base_url = request.base_url.rstrip("/")

    # FIX #4: actually discover real endpoints from the target API
    parsed_data, raw_spec, spec_url = discover_endpoints(base_url, request.auth_token)

    # store the discovered spec so it can be retrieved later
    spec_id = spec_parser.store_spec(base_url, raw_spec, parsed_data)

    # pass base_url into parsed_data so APITestingAgent uses the right host
    parsed_data["base_url"] = base_url

    result = orchestrator.run_all(parsed_data)

    return {
        "status": "completed",
        "spec_id": spec_id,
        "spec_discovered_at": spec_url,
        "endpoints_found": parsed_data["total_endpoints"],
        "result": result
    }