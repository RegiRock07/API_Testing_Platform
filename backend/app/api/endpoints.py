from fastapi import APIRouter, HTTPException, UploadFile, File
from pydantic import BaseModel
import json
import yaml

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
# Endpoint Discovery (Temporary)
# -----------------------------
def discover_endpoints(base_url: str):
    """
    Temporary endpoint discovery.
    Later this will:
    - detect /openapi.json
    - detect /swagger.json
    - crawl API routes
    """

    return [
        {"path": "/users", "method": "GET"},
        {"path": "/posts", "method": "GET"},
        {"path": "/todos", "method": "GET"}
    ]


# -----------------------------
# Scan API URL
# -----------------------------
@router.post("/api/scan-url")
def scan_api_url(request: URLScanRequest):

    base_url = request.base_url

    endpoints = discover_endpoints(base_url)

    parsed_data = {
        "base_url": base_url,
        "endpoints": endpoints
    }

    result = orchestrator.run_all(parsed_data)

    return {
        "status": "completed",
        "result": result
    }