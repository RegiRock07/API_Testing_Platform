# backend/app/api/streaming.py
#
# Server-Sent Events (SSE) streaming endpoint.
# Emits one event per agent as the scan progresses so the frontend
# can show a live progress bar instead of a frozen UI.
#
# Add this router to main.py:
#   from app.api.streaming import stream_router
#   app.include_router(stream_router)

import json
import asyncio
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from app.services.spec_parser import SpecParser
from app.database import save_report

stream_router = APIRouter()
spec_parser   = SpecParser()


def sse(agent: str, status: str, data: dict = None) -> str:
    """Format a single SSE event."""
    payload = {"agent": agent, "status": status}
    if data:
        payload["data"] = data
    return f"data: {json.dumps(payload)}\n\n"


@stream_router.post("/api/run/{spec_id}/stream")
async def run_agents_stream(spec_id: str):
    """
    Run all agents and stream progress as SSE events.
    Each agent emits a 'running' event when it starts and a
    'completed' event when it finishes. Final event contains
    the full report.
    """
    scan = spec_parser.get_spec(spec_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Spec not found")

    parsed_data = scan["parsed_data"]

    async def generate():
        # Import agents here to avoid circular imports at module level
        from app.agents.planner_agent          import PlannerAgent
        from app.agents.test_generation_agent  import TestGeneratorAgent
        from app.agents.security_agent         import SecurityAgent
        from app.agents.api_testing_agent      import APITestingAgent
        from app.agents.deployment_agent       import DeploymentAgent
        from app.agents.deep_scan_agent        import DeepScanAgent
        from app.reporting.report_generator    import ReportGenerator
        from app.services.llm_service          import call_llm, LLMError
        import json as _json

        try:
            # ── Planner ───────────────────────────────────────────
            yield sse("planner", "running")
            await asyncio.sleep(0)
            try:
                loop = asyncio.get_event_loop()
                planner_result = await asyncio.wait_for(
                    loop.run_in_executor(None, PlannerAgent().run, parsed_data),
                    timeout=60.0
                )
            except (asyncio.TimeoutError, Exception) as e:
                planner_result = {"agent": "planner", "status": "error", "plan": {}}
                print(f"[Stream] Planner error: {e}")
            yield sse("planner", "completed", {
                "high_risk_count": len(
                    planner_result.get("plan", {}).get("high_risk_endpoints", [])
                )
            })
            await asyncio.sleep(0)

            # ── Test Generation ───────────────────────────────────
            yield sse("test_generation", "running")
            await asyncio.sleep(0)
            try:
                loop = asyncio.get_event_loop()
                test_gen_result = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda: TestGeneratorAgent().run(parsed_data, planner_result=planner_result)
                    ),
                    timeout=60.0
                )
            except (asyncio.TimeoutError, Exception) as e:
                test_gen_result = {
                    "agent": "test_generation", "status": "error",
                    "llm_used": False, "test_cases_generated": 0,
                    "test_cases": [],
                }
                print(f"[Stream] TestGen error: {e}")
            yield sse("test_generation", "completed", {
                "test_cases_generated": test_gen_result.get("test_cases_generated", 0)
            })
            await asyncio.sleep(0)

            # ── Security ──────────────────────────────────────────
            yield sse("security", "running")
            await asyncio.sleep(0)
            try:
                security_result = SecurityAgent().run(
                    parsed_data,
                    planner_result=planner_result,
                )
            except Exception as e:
                security_result = {
                    "agent": "security", "status": "error",
                    "findings": [], "total_findings": 0,
                    "critical_count": 0, "high_count": 0,
                    "medium_count": 0, "low_count": 0,
                }
                print(f"[Stream] Security error: {e}")
            yield sse("security", "completed", {
                "total_findings": security_result.get("total_findings", 0),
                "medium_count":   security_result.get("medium_count", 0),
            })
            await asyncio.sleep(0)

            # ── API Testing ───────────────────────────────────────
            yield sse("api_testing", "running")
            await asyncio.sleep(0)
            try:
                loop = asyncio.get_event_loop()
                api_test_result = await asyncio.wait_for(
                    loop.run_in_executor(None, APITestingAgent().run, parsed_data),
                    timeout=30.0
                )
            except asyncio.TimeoutError:
                api_test_result = {
                    "agent": "api_testing", "status": "timeout",
                    "results": [], "note": "API testing timed out after 30s"
                }
                print("[Stream] APITesting timed out")
            except Exception as e:
                api_test_result = {
                    "agent": "api_testing", "status": "error", "results": []
                }
                print(f"[Stream] APITesting error: {e}")
            all_tests    = [
                t for r in api_test_result.get("results", [])
                for t in r.get("tests", [])
            ]
            passed_count = len([t for t in all_tests if t.get("passed") is True])
            failed_count = len([t for t in all_tests if t.get("passed") is False])
            yield sse("api_testing", "completed", {
                "passed": passed_count,
                "failed": failed_count,
            })
            await asyncio.sleep(0)

            # ── Deployment ────────────────────────────────────────
            yield sse("deployment", "running")
            await asyncio.sleep(0)
            base_url = parsed_data.get("base_url", "http://localhost:8000")
            try:
                deployment_result = DeploymentAgent().run(base_url=base_url)
            except Exception as e:
                deployment_result = {"agent": "deployment", "status": "error"}
                print(f"[Stream] Deployment error: {e}")
            yield sse("deployment", "completed", {
                "status":         deployment_result.get("status"),
                "security_score": deployment_result.get("security_score", "N/A"),
            })
            await asyncio.sleep(0)

            # ── Deep Scan (conditional) ───────────────────────────
            deep_scan_result = {}
            medium_count     = security_result.get("medium_count", 0)
            critical_count   = security_result.get("critical_count", 0)
            high_count       = security_result.get("high_count", 0)

            if critical_count > 0 or high_count >= 2 or medium_count >= 3:
                yield sse("deep_scan", "running")
                await asyncio.sleep(0)
                try:
                    deep_scan_result = DeepScanAgent().run(security_result)
                except Exception as e:
                    deep_scan_result = {
                        "agent": "deep_scan", "status": "error",
                        "deep_scan_performed": False, "findings_enriched": [],
                    }
                    print(f"[Stream] DeepScan error: {e}")
                yield sse("deep_scan", "completed", {
                    "findings_enriched": len(
                        deep_scan_result.get("findings_enriched", [])
                    )
                })
                await asyncio.sleep(0)
            else:
                yield sse("deep_scan", "skipped")
                await asyncio.sleep(0)

            # ── LLM Analysis ──────────────────────────────────────
            yield sse("llm_analysis", "running")
            await asyncio.sleep(0)

            security_findings = security_result.get("findings", [])
            endpoints         = parsed_data.get("endpoints", [])
            deployment_status = deployment_result.get("status", "unknown")
            planner_summary   = ""
            plan = planner_result.get("plan", {})
            if plan:
                planner_summary = (
                    f"\nPlanner Risk Summary: {plan.get('risk_summary', '')}"
                    f"\nAuth Pattern: {plan.get('auth_pattern_detected', 'unknown')}"
                )
            deep_note = ""
            if deep_scan_result.get("deep_scan_performed"):
                n = len(deep_scan_result.get("findings_enriched", []))
                deep_note = f"\nDeep scan: {n} findings enriched with PoC exploits."

            prompt = f"""You are an expert API security analyst.
Review the following scan results and provide:
1. A brief executive summary (2-3 sentences)
2. The top 3 most critical findings with reasoning
3. Prioritised remediation steps

API: {parsed_data.get("title", "Unknown")} — {len(endpoints)} endpoints
Deployment: {deployment_status}
{planner_summary}
{deep_note}

Findings ({len(security_findings)} total):
{_json.dumps(security_findings[:10], indent=2)}

Respond in plain English. Be specific and actionable."""

            llm_analysis = ""
            try:
                llm_analysis = call_llm([{"role": "user", "content": prompt}])
            except LLMError as e:
                llm_analysis = (
                    f"LLM analysis unavailable ({e}). "
                    f"Scan found {len(security_findings)} findings across "
                    f"{len(endpoints)} endpoints."
                )
            except Exception as e:
                llm_analysis = f"LLM analysis failed: {e}"

            yield sse("llm_analysis", "completed")
            await asyncio.sleep(0)

            # ── Report ────────────────────────────────────────────
            yield sse("report", "running")
            await asyncio.sleep(0)

            agent_output = {
                "security":    security_result,
                "api_testing": api_test_result,
                "deployment":  deployment_result,
            }
            report = ReportGenerator().generate(agent_output)

            # Attach extras
            report["llm_analysis"]      = llm_analysis
            report["planner_assessment"] = planner_result.get("plan", {})
            report["test_generation"]   = {
                "llm_used":             test_gen_result.get("llm_used", False),
                "test_cases_generated": test_gen_result.get("test_cases_generated", 0),
            }

            # Merge deep scan enriched findings
            if deep_scan_result.get("deep_scan_performed"):
                enriched_map = {
                    (f.get("endpoint"), f.get("risk_type")): f
                    for f in deep_scan_result.get("findings_enriched", [])
                }
                merged = []
                for f in report.get("security_findings", []):
                    key = (f.get("endpoint"), f.get("risk_type"))
                    merged.append(enriched_map.get(key, f))
                report["security_findings"]   = merged
                report["deep_scan_performed"] = True
                report["deep_scan_summary"]   = {
                    "findings_enriched": len(
                        deep_scan_result.get("findings_enriched", [])
                    )
                }
            else:
                report["deep_scan_performed"] = False

            # Persist to DB
            save_report(spec_id, report)

            yield sse("report", "completed", {"report": report})
            await asyncio.sleep(0)

            yield "data: [DONE]\n\n"

        except Exception as e:
            yield sse("error", "failed", {"message": str(e)})
            yield "data: [DONE]\n\n"

    async def safe_generate():
        try:
            async for chunk in generate():
                yield chunk
        except Exception as e:
            yield sse("error", "failed", {"message": str(e)})
            yield "data: [DONE]\n\n"

    return StreamingResponse(
        safe_generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":    "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":       "keep-alive",
        },
    )