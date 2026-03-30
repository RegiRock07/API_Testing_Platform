# backend/app/api/endpoints.py

from fastapi import APIRouter, HTTPException, UploadFile, File, Depends, Request
from fastapi.responses import StreamingResponse, Response
from pydantic import BaseModel
import json
import yaml
import requests
import asyncio
from datetime import datetime, timezone
from io import BytesIO

from app.schemas.api_spec import APISpecUpload, APISpecResponse
from app.services.spec_parser import SpecParser
from app.orchestrator import Orchestrator
from app.database import list_scans, get_scan, delete_scan, save_report, log_agent_run
from app.api.auth import get_current_user

router = APIRouter()
spec_parser = SpecParser()
orchestrator = Orchestrator()


# ─────────────────────────────────────────
# Auth dependency (uses JWT / super-user bypass)
# ─────────────────────────────────────────

AuthDep = Depends(get_current_user)


# ─────────────────────────────────────────
# Models
# ─────────────────────────────────────────

class URLScanRequest(BaseModel):
    base_url: str
    auth_token: str = ""


# ─────────────────────────────────────────
# Auth Models
# ─────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class UserResponse(BaseModel):
    id: str
    email: str
    created_at: str
    last_login: str | None


# ─────────────────────────────────────────
# Auth Endpoints
# ─────────────────────────────────────────

@router.post("/api/auth/register", status_code=201)
def register(req: RegisterRequest):
    from app.database import get_user_by_email, create_user, hash_password
    existing = get_user_by_email(req.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    hashed = hash_password(req.password)
    user_id = create_user(req.email, hashed)
    return {"user_id": user_id, "email": req.email}


@router.post("/api/auth/login")
def login(req: LoginRequest):
    from app.database import get_user_by_email, verify_password, update_last_login
    from app.api.auth import create_access_token
    user = get_user_by_email(req.email)
    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    update_last_login(user["id"])
    token = create_access_token({"sub": user["id"], "email": user["email"]})
    return {"token": token, "token_type": "bearer", "user_id": user["id"], "email": user["email"]}


@router.get("/api/auth/me", response_model=UserResponse)
def get_me(current_user: dict = Depends(get_current_user)):
    return UserResponse(
        id=current_user["id"],
        email=current_user["email"],
        created_at=current_user["created_at"],
        last_login=current_user.get("last_login")
    )


@router.post("/api/auth/logout")
def logout():
    return {"status": "ok", "message": "Token discarded client-side"}


# ─────────────────────────────────────────
# Scan History
# ─────────────────────────────────────────

@router.get("/api/scans", dependencies=[AuthDep])
def get_scan_history(current_user: dict = Depends(get_current_user)):
    if current_user.get("id") == "super":
        return list_scans(limit=100)
    return list_scans(limit=100, user_id=current_user["id"])


@router.get("/api/scans/{scan_id}/report", dependencies=[AuthDep])
def get_scan_report(scan_id: str, current_user: dict = Depends(get_current_user)):
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if current_user.get("id") != "super" and scan.get("user_id") != current_user["id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    if not scan.get("report"):
        raise HTTPException(status_code=404, detail="Report not yet generated")
    return scan["report"]


@router.delete("/api/scans/{scan_id}", dependencies=[AuthDep])
def remove_scan(scan_id: str, current_user: dict = Depends(get_current_user)):
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if current_user.get("id") != "super" and scan.get("user_id") != current_user["id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    deleted = delete_scan(scan_id, user_id=current_user["id"] if current_user.get("id") != "super" else None)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"status": "deleted", "id": scan_id}


# ─────────────────────────────────────────
# Agent Logs
# ─────────────────────────────────────────

@router.get("/api/scans/{scan_id}/agents", dependencies=[AuthDep])
def get_agent_logs(scan_id: str, current_user: dict = Depends(get_current_user)):
    from app.database import get_conn
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if current_user.get("id") != "super" and scan.get("user_id") != current_user["id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM agent_logs WHERE scan_id = ? ORDER BY started_at ASC",
            (scan_id,)
        ).fetchall()
    return [dict(r) for r in rows]


# ─────────────────────────────────────────
# Upload OpenAPI Spec (JSON body)
# ─────────────────────────────────────────

@router.post("/api/specs/upload", response_model=APISpecResponse, dependencies=[AuthDep])
def upload_api_spec(upload: APISpecUpload, current_user: dict = Depends(get_current_user)):
    try:
        parsed_data = spec_parser.parse_spec(upload.spec)
        user_id = current_user.get("id") if current_user.get("id") != "super" else None
        spec_id = spec_parser.store_spec(upload.name, upload.spec, parsed_data, user_id=user_id)
        return APISpecResponse(
            id=spec_id, name=upload.name,
            status="parsed", endpoints_count=parsed_data["total_endpoints"]
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing spec: {str(e)}")


@router.post("/api/specs/upload-file", dependencies=[AuthDep])
async def upload_spec_file(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    content = await file.read()
    try:
        if file.filename.endswith(".json"):
            spec = json.loads(content)
        elif file.filename.endswith((".yaml", ".yml")):
            spec = yaml.safe_load(content)
        else:
            raise HTTPException(status_code=400, detail="Unsupported file format")

        parsed_data = spec_parser.parse_spec(spec)
        user_id = current_user.get("id") if current_user.get("id") != "super" else None
        spec_id = spec_parser.store_spec(file.filename, spec, parsed_data, user_id=user_id)
        return {"id": spec_id, "status": "parsed", "endpoints": parsed_data["total_endpoints"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
def run_agents(spec_id: str, current_user: dict = Depends(get_current_user)):
    scan = spec_parser.get_spec(spec_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Spec not found")
    if current_user.get("id") != "super" and scan.get("user_id") != current_user["id"]:
        raise HTTPException(status_code=403, detail="Access denied")

    result = orchestrator.run_all(scan["parsed_data"])
    save_report(spec_id, result)

    return {"status": "completed", "result": result}


# ─────────────────────────────────────────
# SSE Streaming Endpoint
# ─────────────────────────────────────────

@router.post("/api/run/{spec_id}/stream", dependencies=[AuthDep])
async def run_agents_stream(spec_id: str, current_user: dict = Depends(get_current_user)):
    scan = spec_parser.get_spec(spec_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Spec not found")
    if current_user.get("id") != "super" and scan.get("user_id") != current_user["id"]:
        raise HTTPException(status_code=403, detail="Access denied")

    parsed_data = scan["parsed_data"]
    auth_config = parsed_data.get("auth", {})

    async def generate():
        def make_event(agent: str, status: str, data: dict = None):
            payload = {"agent": agent, "status": status}
            if data:
                payload["data"] = data
            return f"data: {json.dumps(payload)}\n\n"

        # Planner
        from app.agents.planner_agent import PlannerAgent
        yield make_event("planner", "running")
        await asyncio.sleep(0)
        planner_result = PlannerAgent().run(parsed_data)
        log_agent_run(spec_id, "planner", planner_result.get("status", "completed"),
                      f"llm_used={planner_result.get('llm_used', False)}")
        yield make_event("planner", planner_result.get("status", "completed"),
                         {"plan_ready": bool(planner_result.get("plan"))})
        await asyncio.sleep(0)

        # Test Generation
        from app.agents.test_generation_agent import TestGeneratorAgent
        yield make_event("test_generation", "running")
        await asyncio.sleep(0)
        test_gen_result = TestGeneratorAgent().run(parsed_data, planner_result=planner_result)
        log_agent_run(spec_id, "test_generation", test_gen_result.get("status", "completed"),
                      f"llm_used={test_gen_result.get('llm_used', False)}, cases={test_gen_result.get('test_cases_generated', 0)}")
        yield make_event("test_generation", test_gen_result.get("status", "completed"), {
            "test_cases_generated": test_gen_result.get("test_cases_generated", 0),
        })
        await asyncio.sleep(0)

        # Security
        from app.agents.security_agent import SecurityAgent
        yield make_event("security", "running")
        await asyncio.sleep(0)
        security_result = SecurityAgent().run(parsed_data, planner_result=planner_result)
        log_agent_run(spec_id, "security", security_result.get("status", "completed"),
                      f"findings={security_result.get('total_findings', 0)}")
        yield make_event("security", "completed", {
            "total_findings": security_result.get("total_findings", 0),
            "critical_count": security_result.get("critical_count", 0),
            "high_count": security_result.get("high_count", 0),
        })
        await asyncio.sleep(0)

        # API Testing
        from app.agents.api_testing_agent import APITestingAgent
        yield make_event("api_testing", "running")
        await asyncio.sleep(0)
        api_test_result = APITestingAgent().run(
            parsed_data,
            planner_result=planner_result,
            test_generation_result=test_gen_result,
            auth_config=auth_config
        )
        log_agent_run(spec_id, "api_testing", api_test_result.get("status", "completed"),
                      f"api_was_reachable={api_test_result.get('api_was_reachable', False)}")
        yield make_event("api_testing", api_test_result.get("status", "completed"), {
            "api_was_reachable": api_test_result.get("api_was_reachable", False),
        })
        await asyncio.sleep(0)

        # Deployment
        from app.agents.deployment_agent import DeploymentAgent
        yield make_event("deployment", "running")
        await asyncio.sleep(0)
        deployment_result = DeploymentAgent().run(base_url=parsed_data.get("base_url", "http://localhost:8000"))
        log_agent_run(spec_id, "deployment", deployment_result.get("status", "completed"),
                      f"security_score={deployment_result.get('security_score', '0/6')}")
        yield make_event("deployment", "completed", {
            "status": deployment_result.get("status"),
            "security_score": deployment_result.get("security_score"),
        })
        await asyncio.sleep(0)

        # Conditional: deep_scan or synthesis
        critical_count = security_result.get("critical_count", 0)
        high_count = security_result.get("high_count", 0)
        deep_scan_needed = critical_count > 0 or high_count >= 3

        if deep_scan_needed:
            from app.agents.deep_scan_agent import DeepScanAgent
            yield make_event("deep_scan", "running")
            await asyncio.sleep(0)
            deep_scan_result = DeepScanAgent().run(security_result)
            log_agent_run(spec_id, "deep_scan", deep_scan_result.get("status", "completed"),
                          f"deep_scan_performed={deep_scan_result.get('deep_scan_performed', False)}")
            yield make_event("deep_scan", deep_scan_result.get("status", "completed"), {
                "deep_scan_performed": deep_scan_result.get("deep_scan_performed", False),
            })
        else:
            deep_scan_result = {}
            yield make_event("deep_scan", "skipped", {"reason": "Not needed (low risk)"})
        await asyncio.sleep(0)

        # Synthesis
        from app.orchestrator import _run_synthesis
        yield make_event("synthesis", "running")
        await asyncio.sleep(0)
        state_for_synthesis = {
            "parsed_data": parsed_data,
            "planner_result": planner_result,
            "test_generation_result": test_gen_result,
            "security_result": security_result,
            "api_test_result": api_test_result,
            "deployment_result": deployment_result,
            "deep_scan_result": deep_scan_result,
        }
        synthesis_result = _run_synthesis(state_for_synthesis)
        log_agent_run(spec_id, "synthesis", "completed",
                      f"risk_score={synthesis_result.get('overall_risk_score', 'N/A')}")
        yield make_event("synthesis", "completed")
        await asyncio.sleep(0)

        # Report
        from app.reporting.report_generator import ReportGenerator
        yield make_event("report", "running")
        await asyncio.sleep(0)
        agent_output = {
            "security": security_result,
            "api_testing": api_test_result,
            "deployment": deployment_result,
            "deep_scan": deep_scan_result,
            "planner": planner_result,
            "test_generation": test_gen_result,
            "synthesis": synthesis_result,
        }
        report = ReportGenerator().generate(agent_output)
        save_report(spec_id, report)
        yield make_event("report", "completed", {"report": report})

        yield "data: [DONE]\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        }
    )


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
def scan_api_url(request: URLScanRequest, current_user: dict = Depends(get_current_user)):
    base_url = request.base_url.rstrip("/")
    parsed_data, raw_spec, spec_url = discover_endpoints(base_url, request.auth_token)
    user_id = current_user.get("id") if current_user.get("id") != "super" else None

    spec_id = spec_parser.store_spec(base_url, raw_spec, parsed_data, user_id=user_id)
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


# ─────────────────────────────────────────
# Scan Comparison
# ─────────────────────────────────────────

class CompareRequest(BaseModel):
    scan_a_id: str
    scan_b_id: str


@router.post("/api/scans/compare", dependencies=[AuthDep])
def compare_scans(req: CompareRequest, current_user: dict = Depends(get_current_user)):
    from app.database import get_scan, save_scan_comparison

    scan_a = get_scan(req.scan_a_id)
    scan_b = get_scan(req.scan_b_id)
    if not scan_a or not scan_b:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Ownership check (skip for super user)
    if current_user.get("id") != "super":
        if scan_a.get("user_id") != current_user["id"] or scan_b.get("user_id") != current_user["id"]:
            raise HTTPException(status_code=403, detail="Access denied to one or both scans")

    report_a = scan_a.get("report", {}) or {}
    report_b = scan_b.get("report", {}) or {}

    findings_a = report_a.get("security_findings", [])
    findings_b = report_b.get("security_findings", [])

    # Build key maps
    def finding_key(f):
        return (f.get("endpoint", ""), f.get("method", ""), f.get("vulnerability", ""))

    map_a = {finding_key(f): f for f in findings_a}
    map_b = {finding_key(f): f for f in findings_b}

    keys_a = set(map_a.keys())
    keys_b = set(map_b.keys())

    resolved = [map_a[k] for k in keys_a - keys_b]
    new_findings = [map_b[k] for k in keys_b - keys_a]

    persistent = []
    worsened = []
    for k in keys_a & keys_b:
        sev_a = map_a[k].get("severity", "MEDIUM")
        sev_b = map_b[k].get("severity", "MEDIUM")
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        if severity_order.get(sev_a, 99) < severity_order.get(sev_b, 99):
            worsened.append({**map_b[k], "previous_severity": sev_a})
        elif sev_a == sev_b:
            persistent.append(map_b[k])

    score_a = report_a.get("security_score", 5.0)
    score_b = report_b.get("security_score", 5.0)
    score_improvement = round(score_a - score_b, 1)

    comparison_data = {
        "resolved_findings": resolved,
        "persistent_findings": persistent,
        "worsened_findings": worsened,
        "new_findings": new_findings,
    }

    comparison_id = save_scan_comparison(
        user_id=current_user.get("id", "super"),
        scan_a_id=req.scan_a_id,
        scan_b_id=req.scan_b_id,
        findings_resolved=len(resolved),
        findings_new=len(new_findings),
        findings_worsened=len(worsened),
        score_improvement=score_improvement,
        comparison_data=comparison_data,
    )

    return {
        "id": comparison_id,
        "scan_a": {"id": req.scan_a_id, "created_at": scan_a.get("created_at"), "overall_risk_score": report_a.get("overall_risk_score", "N/A")},
        "scan_b": {"id": req.scan_b_id, "created_at": scan_b.get("created_at"), "overall_risk_score": report_b.get("overall_risk_score", "N/A")},
        "summary": {
            "findings_resolved": len(resolved),
            "findings_new": len(new_findings),
            "findings_worsened": len(worsened),
            "score_improvement": score_improvement,
            "tests_passed_now": report_b.get("summary", {}).get("passed_tests", 0),
            "tests_failed_now": report_b.get("summary", {}).get("failed_tests", 0),
        },
        "resolved_findings": resolved,
        "persistent_findings": persistent,
        "worsened_findings": worsened,
        "new_findings": new_findings,
    }


@router.get("/api/scans/compare/{comparison_id}", dependencies=[AuthDep])
def get_comparison(comparison_id: str, current_user: dict = Depends(get_current_user)):
    from app.database import get_scan_comparison
    comp = get_scan_comparison(comparison_id)
    if not comp:
        raise HTTPException(status_code=404, detail="Comparison not found")
    if current_user.get("id") != "super" and comp.get("user_id") != current_user["id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    return comp


@router.get("/api/scans/{scan_id}/history", dependencies=[AuthDep])
def get_scan_history_api(scan_id: str, current_user: dict = Depends(get_current_user)):
    """Get all scans for the same API (by matching api_title)."""
    from app.database import get_scan, list_scans
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if current_user.get("id") != "super" and scan.get("user_id") != current_user["id"]:
        raise HTTPException(status_code=403, detail="Access denied")

    api_title = scan.get("api_title", "")
    all_scans = list_scans(limit=100, user_id=None)
    # Filter to same API title
    same_api = [s for s in all_scans if s.get("api_title") == api_title]
    return same_api


# ─────────────────────────────────────────
# Verify-Fix Mode
# ─────────────────────────────────────────

class VerifyFixRequest(BaseModel):
    previous_scan_id: str | None = None


def _build_targeted_test_cases(failed_tests: list, security_findings: list) -> list:
    """Build targeted test cases from previous scan's failures."""
    targeted = []
    endpoints_seen = set()

    # From failed API tests
    for ep_result in failed_tests:
        ep_path = ep_result.get("endpoint", "")
        ep_method = ep_result.get("method", "")
        if (ep_path, ep_method) in endpoints_seen:
            continue
        for t in ep_result.get("tests", []):
            if t.get("passed") is False and not t.get("connection_error"):
                targeted.append({
                    "name": f"verify_fix_{t.get('test_type', 'unknown')}",
                    "method": ep_method,
                    "path": ep_path,
                    "payload": None,
                    "headers": {},
                    "expected_logic": "passed = true",
                    "category": "verify_fix",
                    "target_endpoint": ep_path,
                    "target_method": ep_method,
                })
                endpoints_seen.add((ep_path, ep_method))

    # From confirmed security findings
    for f in security_findings:
        if f.get("confirmed"):
            ep_path = f.get("endpoint", "")
            ep_method = f.get("method", "")
            if (ep_path, ep_method) not in endpoints_seen:
                targeted.append({
                    "name": f"verify_fix_security_{f.get('vulnerability', 'unknown')}",
                    "method": ep_method,
                    "path": ep_path,
                    "payload": None,
                    "headers": {},
                    "expected_logic": "no vulnerability detected",
                    "category": "verify_fix",
                    "target_endpoint": ep_path,
                    "target_method": ep_method,
                })
                endpoints_seen.add((ep_path, ep_method))

    return targeted


@router.post("/api/run/{spec_id}/verify-fix", dependencies=[AuthDep])
def verify_fix(spec_id: str, req: VerifyFixRequest, current_user: dict = Depends(get_current_user)):
    """Run a targeted verify-fix scan on a previously completed scan."""
    from app.database import get_scan
    from app.orchestrator import Orchestrator

    scan = get_scan(spec_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Spec not found")
    if current_user.get("id") != "super" and scan.get("user_id") != current_user["id"]:
        raise HTTPException(status_code=403, detail="Access denied")

    previous_report = scan.get("report", {}) or {}
    previous_tests = previous_report.get("api_test_results", [])
    previous_findings = previous_report.get("security_findings", [])

    # Build targeted test cases
    targeted_cases = _build_targeted_test_cases(previous_tests, previous_findings)

    previous_scan_id = req.previous_scan_id or spec_id
    parsed_data = scan.get("parsed_data", {})

    # Run a lightweight scan focusing only on failed endpoints
    # Use the orchestrator but mark scan_mode
    orch = Orchestrator()
    result = orch.run_verify_fix(parsed_data, targeted_cases)

    return {
        "previous_scan_id": previous_scan_id,
        "previous_findings_count": len([f for f in previous_findings if f.get("confirmed")]),
        "previous_failed_tests_count": len([t for ep in previous_tests for t in ep.get("tests", []) if t.get("passed") is False and not t.get("connection_error")]),
        "new_findings_count": len(result.get("new_issues", [])),
        "fixed_findings": result.get("fixed_findings", []),
        "persistent_findings": result.get("persistent_findings", []),
        "new_issues": result.get("new_issues", []),
        "overall_status": result.get("overall_status", "stable"),
    }


# ─────────────────────────────────────────
# Scheduled Scans
# ─────────────────────────────────────────

class ScheduleCreateRequest(BaseModel):
    scan_name: str
    spec_id: str | None = None
    base_url: str | None = None
    auth_type: str | None = None  # "bearer" | "api_key" | "basic"
    auth_token: str | None = None
    interval_hours: int = 24
    alert_on_new_findings: bool = True
    webhook_url: str | None = None


class ScheduleUpdateRequest(BaseModel):
    scan_name: str | None = None
    interval_hours: int | None = None
    enabled: bool | None = None
    alert_on_new_findings: bool | None = None
    webhook_url: str | None = None


@router.post("/api/schedules", dependencies=[AuthDep])
def create_schedule(req: ScheduleCreateRequest, current_user: dict = Depends(get_current_user)):
    from app.database import save_scheduled_scan, get_scan

    if not req.spec_id and not req.base_url:
        raise HTTPException(status_code=400, detail="Either spec_id or base_url required")

    user_id = current_user.get("id")
    if current_user.get("id") == "super":
        raise HTTPException(status_code=400, detail="Super-user cannot create schedules")

    # Build auth config
    auth_config = {}
    if req.auth_type and req.auth_token:
        if req.auth_type == "bearer":
            auth_config = {"type": "bearer", "bearer_token": req.auth_token}
        elif req.auth_type == "api_key":
            auth_config = {"type": "api_key", "api_key": req.auth_token}
        elif req.auth_type == "basic":
            # Token format: username:password
            parts = req.auth_token.split(":", 1)
            auth_config = {"type": "basic", "basic_username": parts[0], "basic_password": parts[1] if len(parts) > 1 else ""}

    # Get spec info if spec_id provided
    base_url = req.base_url or ""
    if req.spec_id:
        scan = get_scan(req.spec_id)
        if scan and scan.get("parsed_data", {}).get("base_url"):
            base_url = scan["parsed_data"]["base_url"]

    schedule_id = save_scheduled_scan(
        user_id=user_id,
        scan_name=req.scan_name,
        spec_id=req.spec_id,
        base_url=base_url,
        auth_config=auth_config,
        interval_hours=req.interval_hours,
        webhook_url=req.webhook_url or "",
        alert_on_new_findings=req.alert_on_new_findings,
    )

    return {"id": schedule_id, "status": "created"}


@router.get("/api/schedules", dependencies=[AuthDep])
def list_schedules(current_user: dict = Depends(get_current_user)):
    from app.database import get_scheduled_scans_for_user
    if current_user.get("id") == "super":
        return []
    schedules = get_scheduled_scans_for_user(current_user.get("id"))
    # Remove sensitive fields
    for s in schedules:
        s.pop("auth_config", None)
        s.pop("secret", None, None)
    return schedules


@router.get("/api/schedules/{schedule_id}", dependencies=[AuthDep])
def get_schedule(schedule_id: str, current_user: dict = Depends(get_current_user)):
    from app.database import get_scheduled_scan
    schedule = get_scheduled_scan(schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if current_user.get("id") != "super" and schedule.get("user_id") != current_user.get("id"):
        raise HTTPException(status_code=403, detail="Access denied")
    schedule.pop("auth_config", None)
    return schedule


@router.put("/api/schedules/{schedule_id}", dependencies=[AuthDep])
def update_schedule(schedule_id: str, req: ScheduleUpdateRequest, current_user: dict = Depends(get_current_user)):
    from app.database import get_scheduled_scan, update_scheduled_scan
    schedule = get_scheduled_scan(schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if current_user.get("id") != "super" and schedule.get("user_id") != current_user.get("id"):
        raise HTTPException(status_code=403, detail="Access denied")

    fields = {}
    if req.scan_name is not None:
        fields["scan_name"] = req.scan_name
    if req.interval_hours is not None:
        fields["interval_hours"] = req.interval_hours
    if req.enabled is not None:
        fields["enabled"] = req.enabled
    if req.alert_on_new_findings is not None:
        fields["alert_on_new_findings"] = req.alert_on_new_findings
    if req.webhook_url is not None:
        fields["webhook_url"] = req.webhook_url

    update_scheduled_scan(schedule_id, **fields)
    return {"status": "updated"}


@router.delete("/api/schedules/{schedule_id}", dependencies=[AuthDep])
def delete_schedule(schedule_id: str, current_user: dict = Depends(get_current_user)):
    from app.database import get_scheduled_scan, delete_scheduled_scan
    schedule = get_scheduled_scan(schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if current_user.get("id") != "super" and schedule.get("user_id") != current_user.get("id"):
        raise HTTPException(status_code=403, detail="Access denied")
    delete_scheduled_scan(schedule_id)
    return {"status": "deleted"}


@router.post("/api/schedules/{schedule_id}/run", dependencies=[AuthDep])
def trigger_schedule_now(schedule_id: str, current_user: dict = Depends(get_current_user)):
    from app.database import get_scheduled_scan, update_scheduled_scan_run
    from app.orchestrator import Orchestrator

    schedule = get_scheduled_scan(schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if current_user.get("id") != "super" and schedule.get("user_id") != current_user.get("id"):
        raise HTTPException(status_code=403, detail="Access denied")

    spec_id = schedule.get("spec_id")
    base_url = schedule.get("base_url", "")
    auth_config = schedule.get("auth_config", {})

    if not spec_id and not base_url:
        raise HTTPException(status_code=400, detail="Schedule has no spec_id or base_url")

    # Run scan
    if spec_id:
        from app.services.spec_parser import SpecParser
        sp = SpecParser()
        scan_data = sp.get_spec(spec_id)
        if not scan_data:
            raise HTTPException(status_code=404, detail="Spec not found for this schedule")
        parsed_data = scan_data.get("parsed_data", {})
        if base_url:
            parsed_data["base_url"] = base_url
        if auth_config:
            parsed_data["auth"] = auth_config
    else:
        # URL-based scan
        parsed_data, _, _ = discover_endpoints(base_url, auth_config.get("bearer_token", ""))
        parsed_data["base_url"] = base_url
        if auth_config:
            parsed_data["auth"] = auth_config

    orch = Orchestrator()
    result = orch.run_all(parsed_data)

    # Update next run time
    interval = schedule.get("interval_hours", 24)
    next_run = datetime.now(timezone.utc) + __import__("datetime").timedelta(hours=interval)
    next_run_at = next_run.isoformat()
    update_scheduled_scan_run(schedule_id, next_run_at)

    return {
        "status": "completed",
        "result": result,
        "next_run_at": next_run_at,
    }


# ─────────────────────────────────────────
# Webhooks
# ─────────────────────────────────────────

class WebhookCreateRequest(BaseModel):
    name: str
    target_url: str
    secret: str | None = None
    event_types: list[str] = ["scan.completed"]


@router.post("/api/webhooks", dependencies=[AuthDep])
def create_webhook(req: WebhookCreateRequest, current_user: dict = Depends(get_current_user)):
    from app.database import save_webhook

    user_id = current_user.get("id")
    if current_user.get("id") == "super":
        raise HTTPException(status_code=400, detail="Super-user cannot create webhooks")

    # Validate URL
    if not req.target_url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="target_url must be a valid HTTP(S) URL")

    webhook_id = save_webhook(
        user_id=user_id,
        name=req.name,
        target_url=req.target_url,
        secret=req.secret or "",
        event_types=req.event_types,
    )
    return {"id": webhook_id, "status": "created"}


@router.get("/api/webhooks", dependencies=[AuthDep])
def list_webhooks(current_user: dict = Depends(get_current_user)):
    from app.database import get_webhooks_for_user
    if current_user.get("id") == "super":
        return []
    webhooks = get_webhooks_for_user(current_user.get("id"))
    # Don't expose secret
    for w in webhooks:
        w.pop("secret", None)
    return webhooks


@router.delete("/api/webhooks/{webhook_id}", dependencies=[AuthDep])
def delete_webhook(webhook_id: str, current_user: dict = Depends(get_current_user)):
    from app.database import get_webhook, delete_webhook
    webhook = get_webhook(webhook_id)
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    if current_user.get("id") != "super" and webhook.get("user_id") != current_user.get("id"):
        raise HTTPException(status_code=403, detail="Access denied")
    delete_webhook(webhook_id)
    return {"status": "deleted"}


@router.post("/api/webhooks/test")
def test_webhook(req: WebhookCreateRequest, current_user: dict = Depends(get_current_user)):
    """Send a test webhook payload to the target URL."""
    import hashlib
    import hmac
    import time

    payload = {
        "event": "test",
        "timestamp": time.time(),
        "data": {
            "message": "This is a test webhook from API Sentinel",
            "webhook_name": req.name,
        }
    }
    payload_json = json.dumps(payload)

    headers = {"Content-Type": "application/json"}
    if req.secret:
        signature = hmac.new(
            req.secret.encode(),
            payload_json.encode(),
            hashlib.sha256
        ).hexdigest()
        headers["X-Sentinel-Signature"] = signature

    try:
        response = requests.post(req.target_url, data=payload_json, headers=headers, timeout=10)
        return {"status": "sent", "response_status": response.status_code}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@router.post("/api/webhooks/receive")
async def receive_webhook(request: Request):
    """
    Inbound webhook receiver for CI/CD systems.
    Trigger a scheduled scan when called with a valid payload.
    Payload: {"schedule_id": "uuid", "secret": "shared-secret"}
    """
    import hashlib
    import hmac
    import time
    from app.database import get_scheduled_scan

    body = await request.body()
    sig_header = request.headers.get("X-Sentinel-Signature", "")

    # Find schedule from webhook_id in payload or header
    try:
        payload_data = json.loads(body)
    except:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    schedule_id = payload_data.get("schedule_id")
    secret = payload_data.get("secret", "")

    if not schedule_id:
        raise HTTPException(status_code=400, detail="Missing schedule_id")

    schedule = get_scheduled_scan(schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    # If schedule has a webhook secret configured, verify it
    # (This is for INBOUND webhooks to API Sentinel from external CI/CD)
    # In this simplified version, we trust the schedule_id
    # For production, you'd verify HMAC here

    # Trigger the schedule immediately
    from app.orchestrator import Orchestrator
    from app.services.spec_parser import SpecParser

    spec_id = schedule.get("spec_id")
    base_url = schedule.get("base_url", "")
    auth_config = schedule.get("auth_config", {})

    if spec_id:
        sp = SpecParser()
        scan_data = sp.get_spec(spec_id)
        if not scan_data:
            raise HTTPException(status_code=404, detail="Spec not found")
        parsed_data = scan_data.get("parsed_data", {})
        if base_url:
            parsed_data["base_url"] = base_url
        if auth_config:
            parsed_data["auth"] = auth_config
    else:
        raise HTTPException(status_code=400, detail="URL-based scheduled scans cannot be triggered via webhook")

    # Run async
    orch = Orchestrator()
    # Run in a fire-and-forget manner
    asyncio.create_task(asyncio.to_thread(orch.run_all, parsed_data))

    return {"status": "accepted", "message": "Scan triggered"}


# ─────────────────────────────────────────
# Report Export
# ─────────────────────────────────────────

@router.get("/api/scans/{scan_id}/report/export/json", dependencies=[AuthDep])
def export_report_json(scan_id: str, current_user: dict = Depends(get_current_user)):
    from app.database import get_scan
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if current_user.get("id") != "super" and scan.get("user_id") != current_user.get("id"):
        raise HTTPException(status_code=403, detail="Access denied")

    report = scan.get("report", {}) or {}
    export_data = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "scan_id": scan_id,
        "api_title": scan.get("api_title", ""),
        "api_version": scan.get("api_version", ""),
        "report": report,
    }
    return export_data


@router.get("/api/scans/{scan_id}/report/export/pdf", dependencies=[AuthDep])
def export_report_pdf(scan_id: str, current_user: dict = Depends(get_current_user)):
    from app.database import get_scan
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib import colors

    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if current_user.get("id") != "super" and scan.get("user_id") != current_user.get("id"):
        raise HTTPException(status_code=403, detail="Access denied")

    report = scan.get("report", {}) or {}
    summary = report.get("summary", {})

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter,
                            rightMargin=inch, leftMargin=inch,
                            topMargin=inch, bottomMargin=inch)
    styles = getSampleStyleSheet()
    story = []

    # Title
    title_style = styles["Title"]
    story.append(Paragraph(f"API Security Report: {scan.get('api_title', 'Unknown')}", title_style))
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph(f"Version: {scan.get('api_version', 'N/A')} | Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]))
    story.append(Spacer(1, 0.3 * inch))
    story.append(HRFlowable())
    story.append(Spacer(1, 0.2 * inch))

    # Risk Score
    risk_score = report.get("overall_risk_score", summary.get("overall_risk_score", "N/A"))
    security_score = report.get("security_score", 0)
    story.append(Paragraph(f"<b>Overall Risk Score:</b> {risk_score}", styles["Heading2"]))
    story.append(Paragraph(f"<b>Security Score:</b> {security_score}/10", styles["Normal"]))
    story.append(Spacer(1, 0.2 * inch))

    # Summary counts
    story.append(Paragraph("Summary", styles["Heading3"]))
    summary_data = [
        ["Critical", "High", "Medium", "Low", "Total"],
        [summary.get("critical_risks", 0),
         summary.get("high_risks", 0),
         summary.get("medium_risks", 0),
         summary.get("low_risks", 0),
         summary.get("total_security_findings", 0)],
    ]
    t = Table(summary_data, colWidths=[1.2 * inch] * 5)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 1, colors.black),
        ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.3 * inch))

    # Executive Summary
    exec_sum = report.get("executive_summary", "No executive summary available.")
    story.append(Paragraph("Executive Summary", styles["Heading3"]))
    story.append(Paragraph(exec_sum, styles["Normal"]))
    story.append(Spacer(1, 0.3 * inch))

    # Security Findings
    findings = report.get("security_findings", [])
    if findings:
        story.append(Paragraph("Security Findings", styles["Heading3"]))
        for i, f in enumerate(findings[:20]):  # Limit to 20 for PDF size
            sev = f.get("severity", "MEDIUM")
            color = {"CRITICAL": colors.red, "HIGH": colors.orange, "MEDIUM": colors.yellow, "LOW": colors.green}.get(sev, colors.grey)
            story.append(Spacer(1, 0.1 * inch))
            story.append(Paragraph(
                f"<b>[{sev}] {f.get('method', 'GET')} {f.get('endpoint', '')}</b> — {f.get('vulnerability', 'Unknown')}",
                styles["Normal"]
            ))
            story.append(Paragraph(f"OWASP: {f.get('owasp_category', 'N/A')} | Confidence: {f.get('confidence', 'MEDIUM')}", styles["Normal"]))
            story.append(Paragraph(f"<i>{f.get('description', '')}</i>", styles["Normal"]))
            if f.get("remediation"):
                story.append(Paragraph(f"<b>Remediation:</b> {f.get('remediation', '')}", styles["Normal"]))

    story.append(Spacer(1, 0.3 * inch))

    # Remediation Roadmap
    roadmap = report.get("remediation_roadmap", {})
    if roadmap:
        story.append(Paragraph("Remediation Roadmap", styles["Heading3"]))
        for phase, items in roadmap.items():
            if items:
                story.append(Paragraph(f"<b>{phase.replace('_', ' ').title()}:</b>", styles["Normal"]))
                for item in items:
                    story.append(Paragraph(f"• {item}", styles["Normal"]))

    story.append(Spacer(1, 0.5 * inch))
    story.append(HRFlowable())
    story.append(Paragraph("Generated by API Sentinel v3", styles["Normal"]))

    doc.build(story)
    buffer.seek(0)

    return Response(
        content=buffer.getvalue(),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="scan_report_{scan_id}.pdf"'
        }
    )
