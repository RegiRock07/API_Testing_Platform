# backend/app/schemas/api_spec.py

from pydantic import BaseModel, field_validator
from typing import Dict, Any, Literal, Optional

class APISpecUpload(BaseModel):
    spec: Dict[str, Any]  # OpenAPI spec as JSON
    name: str
    description: str = ""
    # Target to test. Overrides whatever the spec's `servers` say — needed
    # when the spec has no servers or only relative ones (e.g. "/api/v3").
    base_url: Optional[str] = None

class APISpecResponse(BaseModel):
    id: str
    name: str
    status: str
    endpoints_count: int
    base_url: Optional[str] = None      # target that will be scanned (None = no target)


# ── Scan options (body of /api/run/{id} and /api/run/{id}/stream) ──

class ScanAuth(BaseModel):
    """Credentials the API Testing agent sends to the target."""
    type:        Literal["bearer", "api_key", "basic"] = "bearer"
    value:       str
    header_name: Optional[str] = None   # api_key only, default X-API-Key

    # A blank credential used to run the scan unauthenticated (or, if it was
    # only whitespace, send an empty "Bearer " header while the report said
    # "authenticated"). Reject it instead; omit `auth` for no credentials.
    @field_validator("value")
    @classmethod
    def _value_not_blank(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("auth.value must not be empty; omit `auth` to scan without credentials")
        return v

class ScanOptions(BaseModel):
    safe_mode: bool = True              # never send DELETE/PUT/PATCH
    auth:      Optional[ScanAuth] = None

    def to_state(self) -> Dict[str, Any]:
        """Plain dict for ScanState["options"]."""
        return self.model_dump()
