# backend/app/schemas/api_spec.py

from pydantic import BaseModel
from typing import Dict, Any

class APISpecUpload(BaseModel):
    spec: Dict[str, Any]  # OpenAPI spec as JSON
    name: str
    description: str = ""

class APISpecResponse(BaseModel):
    id: str
    name: str
    status: str
    endpoints_count: int