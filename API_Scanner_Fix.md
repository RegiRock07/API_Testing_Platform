# Agent Brief — API Scanner Fix: Graceful Fallback + Expanded Discovery

## What You Are Working On

This is a **FastAPI-based API Security Testing Platform**. Users enter a base URL, the backend tries to find an OpenAPI spec at that URL, parses it, and runs security tests against the discovered endpoints.

---

## The Problem

The current `discover_endpoints` function probes only **7 hardcoded paths** for an OpenAPI spec. If none of them return a valid spec, it raises an `HTTPException(422)` and the entire scan dies. The user gets an error and nothing useful.

This means the tool is **completely broken** for any API that:
- Uses a framework-specific spec path not in the hardcoded list
- Has no public spec at all

---

## Current Code (Do Not Lose Any Existing Logic)

```python
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


@router.post("/api/scan-url", dependencies=[AuthDep])
def scan_api_url(request: URLScanRequest, current_user: dict = Depends(get_current_user)):
    base_url = request.base_url.rstrip("/")
    parsed_data, raw_spec, spec_url = discover_endpoints(base_url, request.auth_token)
    user_id = current_user.get("id") if current_user.get("id") != "super" else None

    spec_id = spec_parser.store_spec(base_url, raw_spec, parsed_data, user_id=user_id)
    # Return immediately without blocking! The frontend will call /stream
    return {
        "status": "discovered",
        "spec_id": spec_id,
        "spec_discovered_at": spec_url,
        "endpoints_found": parsed_data["total_endpoints"],
    }
```

---

## What You Need to Implement — 3 Precise Changes

### Change 1 — Expand `candidates` in `discover_endpoints`

Replace the current 7-path list with this comprehensive one covering all major frameworks:

```python
candidates = [
    # Standard
    "/openapi.json", "/openapi.yaml",
    "/swagger.json", "/swagger.yaml",
    "/api-docs", "/api-docs.json", "/api-docs.yaml",

    # Versioned
    "/v1/openapi.json", "/v2/openapi.json", "/v3/openapi.json",
    "/v1/swagger.json", "/v2/swagger.json",
    "/v1/api-docs", "/v2/api-docs",

    # Framework-specific
    "/api/openapi.json",            # generic
    "/api/swagger.json",
    "/api/schema/",                 # Django REST Framework
    "/api/schema/swagger-ui/",
    "/swagger/v1/swagger.json",     # ASP.NET
    "/v3/api-docs",                 # Spring Boot
    "/v3/api-docs.yaml",
    "/__docs",
    "/.well-known/openapi.json",
    "/docs/openapi.json",
    "/api/v1/openapi.json",
    "/api/v2/openapi.json",
]
```

**Everything else in this function stays identical** — headers logic, yaml/json detection, `spec_parser.parse_spec` call. Do not touch them.

---

### Change 2 — Replace the `raise HTTPException` with a graceful return

Current (remove this):
```python
raise HTTPException(
    status_code=422,
    detail=f"No OpenAPI spec found at {base_url}. "
           f"Tried: {', '.join(candidates)}. Last error: {last_error}"
)
```

Replace with:
```python
return None, None, None
```

---

### Change 3 — Handle the `None` case in `scan_api_url`

Add a guard block immediately after the `discover_endpoints` call. If spec is not found, run baseline checks and return a partial result instead of crashing.

```python
@router.post("/api/scan-url", dependencies=[AuthDep])
def scan_api_url(request: URLScanRequest, current_user: dict = Depends(get_current_user)):
    base_url = request.base_url.rstrip("/")
    parsed_data, raw_spec, spec_url = discover_endpoints(base_url, request.auth_token)
    user_id = current_user.get("id") if current_user.get("id") != "super" else None

    # NEW: handle no spec found
    if raw_spec is None:
        result = run_baseline_checks(base_url)
        return {
            "status": "partial",
            "spec_found": False,
            "spec_discovered_at": None,
            "endpoints_found": 0,
            "message": "No OpenAPI spec discovered. Ran baseline security checks instead.",
            "tip": "For full endpoint testing, expose your OpenAPI spec or paste it manually.",
            "result": result
        }

    # existing code below — do not change
    spec_id = spec_parser.store_spec(base_url, raw_spec, parsed_data, user_id=user_id)
    return {
        "status": "discovered",
        "spec_id": spec_id,
        "spec_discovered_at": spec_url,
        "endpoints_found": parsed_data["total_endpoints"],
    }
```

---

### Change 4 — Create `run_baseline_checks(base_url: str)` function

Create this as a new function, either in `orchestrator.py` or a new file `baseline.py`. It must work with zero endpoint knowledge — just the base URL.

It should check:

1. **SSL/TLS** — is the certificate valid, is HTTPS enforced
2. **Security headers** — check for presence of:
   - `Strict-Transport-Security` (HSTS)
   - `X-Frame-Options`
   - `Content-Security-Policy`
   - `X-Content-Type-Options`
   - `Referrer-Policy`
   - `Permissions-Policy`
3. **CORS misconfiguration** — send a request with `Origin: https://evil.com`, check if it's reflected back
4. **Exposed sensitive paths** — probe these and flag any that return 200:
   - `/.env`
   - `/admin`
   - `/config`
   - `/debug`
   - `/.git/config`
   - `/phpinfo.php`
5. **HTTP methods on base URL** — send an OPTIONS request, log what methods are allowed

Return a structured dict:
```python
{
    "ssl": { "valid": bool, "enforced": bool },
    "security_headers": {
        "present": [...],
        "missing": [...]
    },
    "cors": { "misconfigured": bool, "detail": str },
    "exposed_paths": [...],  # list of paths that returned 200
    "allowed_methods": [...]
}
```

---

## What Must NOT Change

- The `user_id` extraction logic
- The `store_spec` call and its arguments
- The streaming comment (`# Return immediately without blocking...`)
- Auth dependency (`AuthDep`, `get_current_user`)
- Any other existing routes or functions

---

## How to Verify It Works — Test These 3 Scenarios

### Scenario 1 — Spec exists (should work as before)
```
URL: https://petstore3.swagger.io
Expected: status "discovered", endpoints_found > 0
```

### Scenario 2 — Valid URL, no spec (new behaviour)
```
URL: https://github.com
Expected: status "partial", spec_found: false, baseline result populated, no crash
```

### Scenario 3 — Bad URL (should fail cleanly)
```
URL: https://doesnotexist-xyz-abc.com
Expected: clean error response, no 500, no unhandled exception
```

---

## Summary of All Files to Touch

| File | What Changes |
|---|---|
| Current scanner file | `discover_endpoints` — expand candidates, return None instead of raise |
| Current scanner file | `scan_api_url` — add None guard, call baseline checks |
| `orchestrator.py` or new `baseline.py` | Add `run_baseline_checks(base_url)` function |
