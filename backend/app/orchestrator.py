# backend/app/orchestrator.py
#
# Step 3+4 changes:
#  - deep_scan_node added with conditional edge after deployment
#  - security_node now passes planner_result to SecurityAgent
#  - report_node merges deep_scan enriched findings into report
#  - All other nodes unchanged

from __future__ import annotations

import json
from typing import TypedDict, Any

from langgraph.graph import StateGraph, END

from app.agents.planner_agent         import PlannerAgent
from app.agents.test_generation_agent import TestGeneratorAgent
from app.agents.security_agent        import SecurityAgent
from app.agents.api_testing_agent     import APITestingAgent
from app.agents.deployment_agent      import DeploymentAgent
from app.agents.deep_scan_agent       import DeepScanAgent
from app.reporting.report_generator   import ReportGenerator


# ─────────────────────────────────────────
# Shared state
# ─────────────────────────────────────────

class ScanState(TypedDict):
    parsed_data:            dict[str, Any]
    planner_result:         dict[str, Any]
    test_generation_result: dict[str, Any]
    security_result:        dict[str, Any]
    api_test_result:        dict[str, Any]
    deployment_result:      dict[str, Any]
    deep_scan_result:       dict[str, Any]   # NEW
    llm_analysis:           str
    final_report:           dict[str, Any]


# ─────────────────────────────────────────
# Node: Planner (unchanged)
# ─────────────────────────────────────────

def planner_node(state: ScanState) -> ScanState:
    try:
        result = PlannerAgent().run(state["parsed_data"])
    except Exception as e:
        print(f"[planner_node] Error: {e}")
        result = {"agent": "planner", "status": "error", "plan": {}}
    return {**state, "planner_result": result}


# ─────────────────────────────────────────
# Node: Test Generation (unchanged)
# ─────────────────────────────────────────

def test_generation_node(state: ScanState) -> ScanState:
    try:
        result = TestGeneratorAgent().run(
            state["parsed_data"],
            planner_result=state.get("planner_result", {}),
        )
    except Exception as e:
        print(f"[test_generation_node] Error: {e}")
        result = {
            "agent": "test_generation", "status": "error",
            "llm_used": False, "test_cases_generated": 0, "test_cases": [],
        }
    return {**state, "test_generation_result": result}


# ─────────────────────────────────────────
# Node: Security (now passes planner context)
# ─────────────────────────────────────────

def security_node(state: ScanState) -> ScanState:
    result = SecurityAgent().run(
        state["parsed_data"],
        planner_result=state.get("planner_result", {}),
    )
    return {**state, "security_result": result}


# ─────────────────────────────────────────
# Node: API Testing (unchanged)
# ─────────────────────────────────────────

def api_testing_node(state: ScanState) -> ScanState:
    result = APITestingAgent().run(state["parsed_data"])
    return {**state, "api_test_result": result}


# ─────────────────────────────────────────
# Node: Deployment (unchanged)
# ─────────────────────────────────────────

def deployment_node(state: ScanState) -> ScanState:
    base_url = state["parsed_data"].get("base_url", "http://localhost:8000")
    result   = DeploymentAgent().run(base_url=base_url)
    return {**state, "deployment_result": result}


# ─────────────────────────────────────────
# Conditional edge: should we run deep scan?
# Triggers when there are 3+ HIGH or any CRITICAL findings.
# ─────────────────────────────────────────

def should_deep_scan(state: ScanState) -> str:
    security     = state.get("security_result", {})
    critical_count = security.get("critical_count", 0)
    high_count     = security.get("high_count", 0)
    medium_count   = security.get("medium_count", 0)

    if critical_count > 0 or high_count >= 2 or medium_count >= 3:
        print(
            f"[Orchestrator] Deep scan triggered "
            f"(CRITICAL={critical_count}, HIGH={high_count}, MEDIUM={medium_count})"
        )
        return "deep_scan"

    print(
        f"[Orchestrator] Deep scan skipped "
    )
    return "llm_analysis"


# ─────────────────────────────────────────
# NEW Node: Deep Scan
# ─────────────────────────────────────────

def deep_scan_node(state: ScanState) -> ScanState:
    try:
        result = DeepScanAgent().run(state.get("security_result", {}))
    except Exception as e:
        print(f"[deep_scan_node] Error: {e}")
        result = {
            "agent": "deep_scan", "status": "error",
            "deep_scan_performed": False, "findings_enriched": [],
        }
    return {**state, "deep_scan_result": result}


# ─────────────────────────────────────────
# Node: LLM Analysis (includes deep scan context)
# ─────────────────────────────────────────

def llm_analysis_node(state: ScanState) -> ScanState:
    from app.services.llm_service import call_llm, LLMError

    security_findings = state["security_result"].get("findings", [])
    endpoints         = state["parsed_data"].get("endpoints", [])
    deployment_status = state["deployment_result"].get("status", "unknown")
    deep_scan         = state.get("deep_scan_result", {})

    # Build planner context string
    planner_summary = ""
    plan = state.get("planner_result", {}).get("plan", {})
    if plan:
        planner_summary = (
            f"\nPlanner Risk Summary: {plan.get('risk_summary', '')}"
            f"\nAuth Pattern: {plan.get('auth_pattern_detected', 'unknown')}"
            f"\nHigh Risk Endpoints: {len(plan.get('high_risk_endpoints', []))}"
        )

    # Note if deep scan ran
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
        return {**state, "llm_analysis": analysis}
    except LLMError as e:
        fallback = (
            f"LLM analysis unavailable ({e}). "
            f"Scan found {len(security_findings)} security findings across "
            f"{len(endpoints)} endpoints. "
            f"Deployment status: {deployment_status}."
        )
        return {**state, "llm_analysis": fallback}
    except Exception as e:
        return {**state, "llm_analysis": f"LLM analysis failed: {e}"}


# ─────────────────────────────────────────
# Node: Report (merges deep scan enrichment)
# ─────────────────────────────────────────

def report_node(state: ScanState) -> ScanState:
    agent_output = {
        "security":    state["security_result"],
        "api_testing": state["api_test_result"],
        "deployment":  state["deployment_result"],
    }

    report = ReportGenerator().generate(agent_output)

    # Attach extras
    report["llm_analysis"]       = state.get("llm_analysis", "")
    report["planner_assessment"]  = state.get("planner_result", {}).get("plan", {})
    report["test_generation"]    = {
        "llm_used":             state.get("test_generation_result", {}).get("llm_used", False),
        "test_cases_generated": state.get("test_generation_result", {}).get("test_cases_generated", 0),
    }

    # Merge deep scan enriched findings into security_findings
    deep_scan = state.get("deep_scan_result", {})
    if deep_scan.get("deep_scan_performed"):
        enriched_map = {
            (f.get("endpoint"), f.get("risk_type")): f
            for f in deep_scan.get("findings_enriched", [])
        }
        merged = []
        for f in report.get("security_findings", []):
            key = (f.get("endpoint"), f.get("risk_type"))
            merged.append(enriched_map.get(key, f))
        report["security_findings"]    = merged
        report["deep_scan_performed"]  = True
        report["deep_scan_summary"]    = {
            "findings_enriched": len(deep_scan.get("findings_enriched", [])),
        }
    else:
        report["deep_scan_performed"] = False

    return {**state, "final_report": report}


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
    graph.add_node("deep_scan",       deep_scan_node)       # NEW
    graph.add_node("llm_analysis",    llm_analysis_node)
    graph.add_node("report",          report_node)

    graph.set_entry_point("planner")
    graph.add_edge("planner",         "test_generation")
    graph.add_edge("test_generation", "security")
    graph.add_edge("security",        "api_testing")
    graph.add_edge("api_testing",     "deployment")

    # Conditional edge — deep_scan or straight to llm_analysis
    graph.add_conditional_edges(
        "deployment",
        should_deep_scan,
        {
            "deep_scan":    "deep_scan",
            "llm_analysis": "llm_analysis",
        }
    )

    graph.add_edge("deep_scan",    "llm_analysis")  # deep_scan feeds into llm
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
# Public interface — unchanged
# ─────────────────────────────────────────

class Orchestrator:

    def run_all(self, parsed_data: dict) -> dict:
        initial_state: ScanState = {
            "parsed_data":            parsed_data,
            "planner_result":         {},
            "test_generation_result": {},
            "security_result":        {},
            "api_test_result":        {},
            "deployment_result":      {},
            "deep_scan_result":       {},
            "llm_analysis":           "",
            "final_report":           {},
        }

        graph       = get_graph()
        final_state = graph.invoke(initial_state)
        return final_state["final_report"]