# backend/app/services/spec_parser.py
#
# Now uses SQLite via database.py instead of an in-memory dict.
# Public API is identical so nothing else needs to change.

from typing import Dict, Any
from app.database import save_scan, get_scan


class SpecParser:

    def parse_spec(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        """Parse OpenAPI spec and extract key information."""

        if "openapi" not in spec and "swagger" not in spec:
            raise ValueError("Invalid OpenAPI/Swagger spec")

        endpoints = []
        paths = spec.get("paths", {})

        for path, methods in paths.items():
            is_id_based = "{" in path and "}" in path

            for method, details in methods.items():
                if method.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                    endpoints.append({
                        "path": path,
                        "method": method.upper(),
                        "summary": details.get("summary", ""),
                        "parameters": details.get("parameters", []),
                        "request_body": details.get("requestBody", {}),
                        "responses": list(details.get("responses", {}).keys()),
                        "is_id_based": is_id_based,
                    })

        return {
            "endpoints": endpoints,
            "total_endpoints": len(endpoints),
            "title": spec.get("info", {}).get("title", "Unnamed API"),
            "version": spec.get("info", {}).get("version", "1.0.0"),
        }

    def store_spec(self, name: str, spec: Dict[str, Any], parsed_data: Dict[str, Any]) -> str:
        """Persist spec to SQLite and return the scan ID."""
        return save_scan(name, spec, parsed_data)

    def get_spec(self, spec_id: str) -> Dict[str, Any] | None:
        """Retrieve a stored scan from SQLite."""
        return get_scan(spec_id)