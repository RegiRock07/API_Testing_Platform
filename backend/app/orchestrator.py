# backend/app/orchestrator.py
#
# The LangGraph scan pipeline. Both the blocking endpoints (/api/run,
# /api/scan-url) and the SSE stream (/api/run/{id}/stream) run THIS graph —
# there is no second hand-written copy of the pipeline.
#
#   planner -> test_generation -> security -> api_testing -> deployment
#           -> [deep_scan if serious findings] -> llm_analysis -> report
#
# Progress reporting: pass a callback as config["configurable"]["progress"].
# Every node calls it with (agent, status, data) — status is "running",
# "completed", "skipped" or "error". The callback runs on the graph's
# worker thread, so it must be thread-safe (streaming.py hands events to
# the event loop with loop.call_soon_threadsafe).
#
# The report node only emits "running": the caller emits "report
# completed" once the report has been persisted.

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Callable, Optional, TypedDict

from langchain_core.runnables import RunnableConfig
from langgraph.graph import StateGraph, END

from app.agents.planner_agent         import PlannerAgent
from app.agents.test_generation_agent import TestGeneratorAgent
from app.agents.security_agent        import SecurityAgent
from app.agents.api_testing_agent     import APITestingAgent
from app.agents.deployment_agent      import DeploymentAgent
from app.agents.deep_scan_agent       import DeepScanAgent
from app.reporting.report_generator   import ReportGenerator

logger = logging.getLogger(__name__)

ProgressFn = Callable[[str, str, Optional[dict]], None]

DEFAULT_OPTIONS: dict[str, Any] = {
    "safe_mode": True,   # API testing never sends DELETE/PUT/PATCH
    "auth":      None,   # {"type": "bearer"|"api_key"|"basic", "value", "header_name"}
}


# ─────────────────────────────────────────
# Shared state
# ─────────────────────────────────────────

class ScanState(TypedDict):
    parsed_data:            dict[str, Any]
    options:                dict[str, Any]
    planner_result:         dict[str, Any]
    test_generation_result: dict[str, Any]
    security_result:        dict[str, Any]
    api_test_result:        dict[str, Any]
    deployment_result:      dict[str, Any]
    deep_scan_result:       dict[str, Any]
    llm_analysis:           str
    llm_analysis_llm_used:  bool
    final_report:           dict[str, Any]


def make_initial_state(parsed_data: dict, options: Optional[dict] = None) -> ScanState:
    return {
        "parsed_data":            parsed_data,
        "options":                {**DEFAULT_OPTIONS, **(options or {})},
        "planner_result":         {},
        "test_generation_result": {},
        "security_result":        {},
        "api_test_result":        {},
        "deployment_result":      {},
        "deep_scan_result":       {},
        "llm_analysis":           "",
        "llm_analysis_llm_used":  False,
        "final_report":           {},
    }


def _base_url(state: ScanState) -> str:
    # parsed_data["base_url"] can be present but None (spec without servers)
    return state["parsed_data"].get("base_url") or ""


# ─────────────────────────────────────────
# Progress plumbing
# ─────────────────────────────────────────

def _emit(config: Optional[RunnableConfig], agent: str, status: str,
          data: Optional[dict] = None) -> None:
    progress = ((config or {}).get("configurable") or {}).get("progress")
    if progress is None:
        return
    try:
        progress(agent, status, data)
    except Exception as e:          # a broken listener must not break the scan
        logger.warning(f"[Orchestrator] progress callback failed: {e}")


def tracked(agent: str,
            summarize: Optional[Callable[[dict], Optional[dict]]] = None,
            fallback: Optional[Callable[[Exception], dict]] = None,
            emit_completed: bool = True):
    """
    Wrap a node: emit running -> completed/error around it.
    On an exception the node's `fallback(e)` state update is used so the
    rest of the pipeline still runs; with no fallback the error propagates.
    """
    def decorate(fn: Callable[[ScanState], dict]):
        # Deliberately no functools.wraps: LangGraph inspects the wrapper's
        # own signature to decide whether to pass `config`.
        def node(state: ScanState, config: RunnableConfig) -> dict:
            _emit(config, agent, "running")
            try:
                update = fn(state)
            except Exception as e:
                logger.exception(f"[{agent}_node] failed")
                _emit(config, agent, "error", {"message": str(e)})
                if fallback is None:
                    raise
                return fallback(e)
            if emit_completed:
                _emit(config, agent, "completed", summarize(update) if summarize else None)
            return update
        node.__name__ = f"{agent}_node"
        return node
    return decorate


def _count_tests(api_result: dict) -> tuple[int, int]:
    tests = [t for r in api_result.get("results", []) for t in r.get("tests", [])]
    return (sum(1 for t in tests if t.get("passed") is True),
            sum(1 for t in tests if t.get("passed") is False))


# ─────────────────────────────────────────
# Nodes
# ─────────────────────────────────────────

@tracked(
    "planner",
    summarize=lambda u: {
        "high_risk_count": len(u["planner_result"].get("plan", {}).get("high_risk_endpoints", [])),
        "llm_used":        u["planner_result"].get("llm_used", False),
    },
    fallback=lambda e: {"planner_result": {
        "agent": "planner", "status": "error", "llm_used": False, "plan": {}, "error": str(e)}},
)
def planner_node(state: ScanState) -> dict:
    return {"planner_result": PlannerAgent().run(state["parsed_data"])}


@tracked(
    "test_generation",
    summarize=lambda u: {
        "test_cases_generated": u["test_generation_result"].get("test_cases_generated", 0),
        "llm_used":             u["test_generation_result"].get("llm_used", False),
    },
    fallback=lambda e: {"test_generation_result": {
        "agent": "test_generation", "status": "error",
        "llm_used": False, "test_cases_generated": 0, "test_cases": [], "error": str(e)}},
)
def test_generation_node(state: ScanState) -> dict:
    return {"test_generation_result": TestGeneratorAgent().run(
        state["parsed_data"], planner_result=state.get("planner_result", {}))}


@tracked(
    "security",
    summarize=lambda u: {
        "total_findings": u["security_result"].get("total_findings", 0),
        "critical_count": u["security_result"].get("critical_count", 0),
        "high_count":     u["security_result"].get("high_count", 0),
        "medium_count":   u["security_result"].get("medium_count", 0),
    },
    fallback=lambda e: {"security_result": {
        "agent": "security", "status": "error", "findings": [], "total_findings": 0,
        "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0,
        "error": str(e)}},
)
def security_node(state: ScanState) -> dict:
    return {"security_result": SecurityAgent().run(
        state["parsed_data"], planner_result=state.get("planner_result", {}))}


def _api_summary(u: dict) -> dict:
    passed, failed = _count_tests(u["api_test_result"])
    return {"passed": passed, "failed": failed,
            "status": u["api_test_result"].get("status")}


@tracked(
    "api_testing",
    summarize=_api_summary,
    fallback=lambda e: {"api_test_result": {
        "agent": "api_testing", "status": "error", "results": [], "note": str(e)}},
)
def api_testing_node(state: ScanState) -> dict:
    options = state.get("options") or DEFAULT_OPTIONS
    return {"api_test_result": APITestingAgent().run(state["parsed_data"], options)}


@tracked(
    "deployment",
    summarize=lambda u: {
        "status":         u["deployment_result"].get("status"),
        "security_score": u["deployment_result"].get("security_score", "N/A"),
    },
    fallback=lambda e: {"deployment_result": {
        "agent": "deployment", "status": "error", "error": str(e)}},
)
def deployment_node(state: ScanState) -> dict:
    # No base URL -> the agent reports "unreachable" itself. Never default
    # to localhost:8000: that is this scanner, not the target.
    return {"deployment_result": DeploymentAgent().run(base_url=_base_url(state))}


# ─────────────────────────────────────────
# Conditional edge: deep scan when there are serious findings
# ─────────────────────────────────────────

def should_deep_scan(state: ScanState, config: RunnableConfig) -> str:
    security       = state.get("security_result", {})
    critical_count = security.get("critical_count", 0)
    high_count     = security.get("high_count", 0)
    medium_count   = security.get("medium_count", 0)

    if critical_count > 0 or high_count >= 2 or medium_count >= 3:
        logger.info(
            f"[Orchestrator] Deep scan triggered "
            f"(CRITICAL={critical_count}, HIGH={high_count}, MEDIUM={medium_count})"
        )
        return "deep_scan"

    logger.info("[Orchestrator] Deep scan skipped")
    _emit(config, "deep_scan", "skipped")
    return "llm_analysis"


@tracked(
    "deep_scan",
    summarize=lambda u: {
        "findings_enriched": len(u["deep_scan_result"].get("findings_enriched", [])),
        "llm_used":          u["deep_scan_result"].get("llm_used", False),
    },
    fallback=lambda e: {"deep_scan_result": {
        "agent": "deep_scan", "status": "error", "deep_scan_performed": False,
        "llm_used": False, "findings_enriched": [], "error": str(e)}},
)
def deep_scan_node(state: ScanState) -> dict:
    return {"deep_scan_result": DeepScanAgent().run(
        state.get("security_result", {}), base_url=_base_url(state))}


# ─────────────────────────────────────────
# Node: LLM Analysis (includes deep scan context)
# ─────────────────────────────────────────

@tracked(
    "llm_analysis",
    fallback=lambda e: {"llm_analysis": f"LLM analysis failed: {e}",
                        "llm_analysis_llm_used": False},
)
def llm_analysis_node(state: ScanState) -> dict:
    from app.services.llm_service import call_llm, LLMError

    security_findings = state["security_result"].get("findings", [])
    endpoints         = state["parsed_data"].get("endpoints", [])
    deployment_status = state["deployment_result"].get("status", "unknown")
    deep_scan         = state.get("deep_scan_result", {})

    planner_summary = ""
    plan = state.get("planner_result", {}).get("plan", {})
    if plan:
        planner_summary = (
            f"\nPlanner Risk Summary: {plan.get('risk_summary', '')}"
            f"\nAuth Pattern: {plan.get('auth_pattern_detected', 'unknown')}"
            f"\nHigh Risk Endpoints: {len(plan.get('high_risk_endpoints', []))}"
        )

    deep_scan_note = ""
    if deep_scan.get("deep_scan_performed"):
        enriched = deep_scan.get("findings_enriched", [])
        deep_scan_note = (
            f"\nDeep scan performed — {len(enriched)} findings enriched with PoC exploits."
        )

    prompt = f"""You are an expert API security analyst.
Review the following automated scan results and provide:
1. A brief executive summary (2-3 sentences)
2. The top 3 most critical findings with reasoning
3. Prioritised remediation steps

API Info:
- Title: {state["parsed_data"].get("title", "Unknown")}
- Total endpoints: {len(endpoints)}
- Deployment status: {deployment_status}
{planner_summary}
{deep_scan_note}

Security Findings ({len(security_findings)} total):
{json.dumps(security_findings[:10], indent=2)}

Respond in plain English. Be specific and actionable.
"""

    try:
        analysis = call_llm([{"role": "user", "content": prompt}])
        return {"llm_analysis": analysis, "llm_analysis_llm_used": True}
    except LLMError as e:
        fallback = (
            f"LLM analysis unavailable ({e}). "
            f"Scan found {len(security_findings)} security findings across "
            f"{len(endpoints)} endpoints. "
            f"Deployment status: {deployment_status}."
        )
        return {"llm_analysis": fallback, "llm_analysis_llm_used": False}


# ─────────────────────────────────────────
# Node: Report (merges deep scan enrichment)
# ─────────────────────────────────────────

def finding_key(f: dict):
    """Security findings carry a unique `id`; fall back for old reports."""
    return f.get("id") or (f.get("endpoint"), f.get("method"), f.get("risk_type"))


@tracked("report", emit_completed=False)   # caller emits "completed" after saving
def report_node(state: ScanState) -> dict:
    agent_output = {
        "security":    state["security_result"],
        "api_testing": state["api_test_result"],
        "deployment":  state["deployment_result"],
    }

    report = ReportGenerator().generate(agent_output)
    # Re-scans replace the report inside the same scan row, so the row's
    # created_at is not the date of this report; record it here.
    report["generated_at"] = datetime.now(timezone.utc).isoformat()

    planner_result  = state.get("planner_result", {})
    test_gen_result = state.get("test_generation_result", {})
    deep_scan       = state.get("deep_scan_result", {})
    options         = state.get("options") or DEFAULT_OPTIONS
    auth            = options.get("auth") or {}

    report["llm_analysis"]       = state.get("llm_analysis", "")
    report["planner_assessment"] = planner_result.get("plan", {})
    report["test_generation"]    = {
        "llm_used":             test_gen_result.get("llm_used", False),
        "test_cases_generated": test_gen_result.get("test_cases_generated", 0),
    }
    report["llm_usage"] = {
        "planner":         planner_result.get("llm_used", False),
        "test_generation": test_gen_result.get("llm_used", False),
        "deep_scan":       deep_scan.get("llm_used", False),
        "llm_analysis":    state.get("llm_analysis_llm_used", False),
    }
    # Never persist the credential itself — only that one was used
    report["scan_options"] = {
        "safe_mode":     options.get("safe_mode", True),
        "authenticated": bool(auth.get("value")),
        "auth_type":     auth.get("type") if auth.get("value") else None,
    }

    if deep_scan.get("deep_scan_performed"):
        enriched_map = {finding_key(f): f for f in deep_scan.get("findings_enriched", [])}
        report["security_findings"] = [
            enriched_map.get(finding_key(f), f) for f in report.get("security_findings", [])
        ]
        report["deep_scan_performed"] = True
        report["deep_scan_summary"]   = {
            "findings_enriched": len(deep_scan.get("findings_enriched", [])),
        }
    else:
        report["deep_scan_performed"] = False

    return {"final_report": report}


# ─────────────────────────────────────────
# Build the LangGraph StateGraph
# ─────────────────────────────────────────

def build_graph() -> Any:
    graph = StateGraph(ScanState)

    graph.add_node("planner",         planner_node)
    graph.add_node("test_generation", test_generation_node)
    graph.add_node("security",        security_node)
    graph.add_node("api_testing",     api_testing_node)
    graph.add_node("deployment",      deployment_node)
    graph.add_node("deep_scan",       deep_scan_node)
    graph.add_node("llm_analysis",    llm_analysis_node)
    graph.add_node("report",          report_node)

    graph.set_entry_point("planner")
    graph.add_edge("planner",         "test_generation")
    graph.add_edge("test_generation", "security")
    graph.add_edge("security",        "api_testing")
    graph.add_edge("api_testing",     "deployment")

    graph.add_conditional_edges(
        "deployment",
        should_deep_scan,
        {"deep_scan": "deep_scan", "llm_analysis": "llm_analysis"},
    )

    graph.add_edge("deep_scan",    "llm_analysis")
    graph.add_edge("llm_analysis", "report")
    graph.add_edge("report",       END)

    return graph.compile()


_graph = None

def get_graph():
    global _graph
    if _graph is None:
        _graph = build_graph()
    return _graph


# ─────────────────────────────────────────
# Public interface
# ─────────────────────────────────────────

class Orchestrator:

    def run_all(self, parsed_data: dict, options: Optional[dict] = None,
                progress: Optional[ProgressFn] = None) -> dict:
        """
        Run the full graph synchronously and return the final report.
        Blocking — call it from a worker thread when inside an event loop.
        """
        config: RunnableConfig = {"configurable": {"progress": progress}} if progress else {}
        final_state = get_graph().invoke(make_initial_state(parsed_data, options), config=config)
        return final_state["final_report"]
