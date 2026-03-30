# backend/app/services/spec_parser.py
#
# Now uses SQLite via database.py instead of an in-memory dict.
# Supports both JSON dict and YAML string input.

from typing import Dict, Any, Union
import yaml
from app.database import save_scan, get_scan


class SpecParser:

    def parse_spec(self, spec: Union[Dict[str, Any], str]) -> Dict[str, Any]:
        """
        Parse OpenAPI spec and extract key information.
        Accepts either a Python dict (already parsed) or a YAML string.
        """
        # Handle YAML string input
        if isinstance(spec, str):
            spec = yaml.safe_load(spec)

        if not isinstance(spec, dict):
            raise ValueError("Spec must be a dict or valid YAML string")

        if "openapi" not in spec and "swagger" not in spec:
            raise ValueError("Invalid OpenAPI/Swagger spec")

        endpoints = []
        paths = spec.get("paths", {})

        # Extract auth patterns from spec
        auth_config = self._extract_auth_pattern(spec)

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
                        "security": details.get("security", spec.get("security", [])),
                    })

        result = {
            "endpoints": endpoints,
            "total_endpoints": len(endpoints),
            "title": spec.get("info", {}).get("title", "Unnamed API"),
            "version": spec.get("info", {}).get("version", "1.0.0"),
            "auth": auth_config,
        }

        # Carry forward base_url if present
        if "base_url" in spec:
            result["base_url"] = spec["base_url"]

        return result

    def _extract_auth_pattern(self, spec: dict) -> dict:
        """Extract authentication pattern from OpenAPI spec security schemes."""
        auth = {"type": "none"}
        security_schemes = spec.get("components", {}).get("securitySchemes", {})
        global_security = spec.get("security", [])

        if not security_schemes and not global_security:
            return auth

        # Determine auth type from scheme names in use
        scheme_types = set()
        for sec in global_security:
            scheme_name = list(sec.keys())[0] if sec else None
            if scheme_name and scheme_name in security_schemes:
                scheme = security_schemes[scheme_name]
                scheme_types.add(scheme.get("type", "unknown"))

        if "http" in scheme_types:
            # Check for Bearer scheme
            for sec in global_security:
                scheme_name = list(sec.keys())[0] if sec else None
                if scheme_name and scheme_name in security_schemes:
                    scheme = security_schemes[scheme_name]
                    if scheme.get("scheme", "").lower() == "bearer":
                        auth = {"type": "bearer"}
                    elif scheme.get("scheme", "").lower() == "basic":
                        auth = {"type": "basic"}
        elif "apiKey" in scheme_types:
            auth = {"type": "api_key"}
        elif "oauth2" in scheme_types:
            auth = {"type": "oauth"}

        return auth

    def store_spec(self, name: str, spec: Union[Dict[str, Any], str],
                   parsed_data: Dict[str, Any], user_id: str = None) -> str:
        """Persist spec to SQLite and return the scan ID."""
        # Normalize spec to dict before storing
        if isinstance(spec, str):
            spec = yaml.safe_load(spec)
        return save_scan(name, spec, parsed_data, user_id=user_id)

    def get_spec(self, spec_id: str) -> Dict[str, Any] | None:
        """Retrieve a stored scan from SQLite."""
        return get_scan(spec_id)