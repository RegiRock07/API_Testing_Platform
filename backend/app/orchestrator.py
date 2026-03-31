import os
import json
import requests
from typing import TypedDict, Any

from langgraph.graph import StateGraph, END

from app.agents.planner_agent import PlannerAgent
from app.agents.test_generation_agent import TestGeneratorAgent
from app.agents.security_agent import SecurityAgent
from app.agents.api_testing_agent import APITestingAgent
from app.agents.deployment_agent import DeploymentAgent
from app.agents.deep_scan_agent import DeepScanAgent
from app.reporting.report_generator import ReportGenerator


# ─────────────────────────────────────────
# Shared state that flows through the graph
# ─────────────────────────────────────────

class ScanState(TypedDict):
    parsed_data: dict[str, Any]
    planner_result: dict[str, Any]
    test_generation_result: dict[str, Any]  # NEW
    security_result: dict[str, Any]
    api_test_result: dict[str, Any]
    deployment_result: dict[str, Any]
    deep_scan_result: dict[str, Any]
    synthesis: dict[str, Any]
    final_report: dict[str, Any]
    deep_scan_needed: bool
    auth_config: dict[str, Any]  # NEW
    scan_mode: str  # "full" | "verify_fix" | "comparison"
    previous_scan_id: str | None  # for verify_fix mode


# ─────────────────────────────────────────
# Helper: parse LLM JSON safely
# ─────────────────────────────────────────

def parse_llm_json(raw_text: str, fallback=None):
    try:
        text = raw_text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        text = text.strip()
        return json.loads(text)
    except Exception as e:
        print(f"[Synthesis] LLM JSON parse failed: {e}")
        return fallback


# ─────────────────────────────────────────
# Node: Planner Agent
# ─────────────────────────────────────────

def planner_node(state: ScanState) -> ScanState:
    result = PlannerAgent().run(state["parsed_data"])
    return {**state, "planner_result": result}


def test_generation_node(state: ScanState) -> ScanState:
    result = TestGeneratorAgent().run(
        state["parsed_data"],
        planner_result=state.get("planner_result", {})
    )
    return {**state, "test_generation_result": result}


# ─────────────────────────────────────────
# Node: Security Agent
# ─────────────────────────────────────────

def security_node(state: ScanState) -> ScanState:
    result = SecurityAgent().run(
        state["parsed_data"],
        planner_result=state.get("planner_result", {})
    )
    return {**state, "security_result": result}


# ─────────────────────────────────────────
# Node: API Testing Agent
# ─────────────────────────────────────────

def api_testing_node(state: ScanState) -> ScanState:
    result = APITestingAgent().run(
        state["parsed_data"],
        planner_result=state.get("planner_result", {}),
        test_generation_result=state.get("test_generation_result", {}),
        auth_config=state.get("auth_config", {})
    )
    return {**state, "api_test_result": result}


# ─────────────────────────────────────────
# Node: Deployment Agent
# ─────────────────────────────────────────

def deployment_node(state: ScanState) -> ScanState:
    base_url = state["parsed_data"].get("base_url", "http://localhost:8000")
    result = DeploymentAgent().run(base_url=base_url)
    return {**state, "deployment_result": result}


# ─────────────────────────────────────────
# Conditional edge: should we run deep scan?
# ─────────────────────────────────────────

def should_deep_scan(state: ScanState) -> str:
    security = state.get("security_result", {})
    critical_count = security.get("critical_count", 0)
    high_count = security.get("high_count", 0)
    if critical_count > 0 or high_count >= 3:
        return "deep_scan"
    return "synthesis"


# ─────────────────────────────────────────
# Node: Deep Scan Agent
# ─────────────────────────────────────────

def deep_scan_node(state: ScanState) -> ScanState:
    result = DeepScanAgent().run(state.get("security_result", {}))
    return {**state, "deep_scan_result": result}


# ─────────────────────────────────────────
# Node: Synthesis Agent
# ─────────────────────────────────────────

def synthesis_node(state: ScanState) -> ScanState:
    synthesis = _run_synthesis(state)
    return {**state, "synthesis": synthesis}


def _run_synthesis(state: ScanState) -> dict:
    security = state.get("security_result", {})
    api_testing = state.get("api_test_result", {})
    deployment = state.get("deployment_result", {})
    deep_scan = state.get("deep_scan_result", {})

    findings = security.get("findings", [])
    test_results = api_testing.get("results", [])

    # Correlate findings + test failures on same endpoint
    correlated_findings = []
    failed_endpoints = set()
    for ep_result in test_results:
        for t in ep_result.get("tests", []):
            if t.get("passed") is False and not t.get("connection_error"):
                failed_endpoints.add(ep_result["endpoint"])

    for f in findings:
        if f.get("endpoint") in failed_endpoints:
            f["confirmed"] = True
        correlated_findings.append(f)

    # Cross-cutting concerns
    cross_cutting = []
    auth_issues = [f for f in correlated_findings if "auth" in f.get("vulnerability", "").lower()]
    if len(auth_issues) >= 3:
        cross_cutting.append({
            "pattern": "widespread_auth_failure",
            "description": f"{len(auth_issues)} endpoints have authentication issues — this may be an architectural gap, not just individual misconfigurations."
        })

    bola_issues = [f for f in correlated_findings if "bola" in f.get("vulnerability", "").lower() or "object level" in f.get("vulnerability", "").lower()]
    if len(bola_issues) >= 3:
        cross_cutting.append({
            "pattern": "widespread_bola",
            "description": f"{len(bola_issues)} endpoints expose object-level access risks — a unified authorization layer may be needed."
        })

    # Try LLM for executive summary
    executive_summary = None
    remediation_roadmap = None
    overall_risk_score = None

    from app.services.llm_service import call_llm, parse_llm_json, LLMError

    try:
        system_prompt = (
            "You are an expert API security analyst.\n"
            "Provide a brief executive summary and remediation roadmap.\n"
            "Respond ONLY in valid JSON."
        )
        user_prompt = f"""Summarize this API security scan for a non-technical executive.

API Title: {state['parsed_data'].get('title', 'Unknown')}
Endpoints scanned: {len(state['parsed_data'].get('endpoints', []))}
Critical findings: {security.get('critical_count', 0)}
High findings: {security.get('high_count', 0)}
Medium findings: {len([f for f in findings if f.get('severity') == 'MEDIUM'])}
Low findings: {len([f for f in findings if f.get('severity') == 'LOW'])}
Deployment health: {deployment.get('status', 'unknown')}
API reachable: {api_testing.get('api_was_reachable', False)}
Deep scan performed: {deep_scan.get('deep_scan_performed', False)}

Top findings:
{json.dumps(findings[:5], indent=2)}

Respond ONLY with valid JSON:
{{
  "executive_summary": "3 sentences, non-technical overview of the risk",
  "remediation_roadmap": {{
    "immediate": ["action item", "action item"],
    "short_term": ["action item"],
    "long_term": ["action item"]
  }},
  "overall_risk_score": "e.g. 7.5/10 — HIGH RISK"
}}"""

        try:
            raw = call_llm([
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ])
            parsed = parse_llm_json(raw, fallback=None)
            if parsed:
                executive_summary = parsed.get("executive_summary")
                remediation_roadmap = parsed.get("remediation_roadmap")
                overall_risk_score = parsed.get("overall_risk_score")
        except LLMError as e:
            print(f"[Synthesis] LLM Error: {e}")

    except Exception as e:
        print(f"[Synthesis] Unexpected Synthesis error: {e}")

    # Fallback if LLM failed
    if not executive_summary:
        total = len(findings)
        critical = security.get("critical_count", 0)
        high = security.get("high_count", 0)
        risk_score = (critical * 10 + high * 7 + (total - critical - high) * 3) / max(total, 1)
        risk_score = min(10, round(risk_score, 1))
        if risk_score >= 7:
            risk_label = "HIGH RISK"
        elif risk_score >= 4:
            risk_label = "MEDIUM RISK"
        else:
            risk_label = "LOW RISK"
        executive_summary = f"This API has {total} security findings including {critical} critical and {high} high severity issues. The deployment is {deployment.get('status', 'unknown')}. Recommend addressing critical findings immediately."
        overall_risk_score = f"{risk_score}/10 — {risk_label}"
        remediation_roadmap = {
            "immediate": ["Fix critical severity findings immediately"],
            "short_term": ["Address high severity findings", "Implement rate limiting"],
            "long_term": ["Conduct full penetration test", "Implement security headers"]
        }

    return {
        "correlated_findings": correlated_findings,
        "cross_cutting_concerns": cross_cutting,
        "executive_summary": executive_summary,
        "remediation_roadmap": remediation_roadmap,
        "overall_risk_score": overall_risk_score,
        "security_score": float(overall_risk_score.split("/")[0]) if overall_risk_score else 5.0
    }


# ─────────────────────────────────────────
# Node: Report Generator
# ─────────────────────────────────────────

def report_node(state: ScanState) -> ScanState:
    agent_output = {
        "security": state["security_result"],
        "api_testing": state["api_test_result"],
        "deployment": state["deployment_result"],
        "deep_scan": state.get("deep_scan_result", {}),
        "planner": state.get("planner_result", {}),
        "test_generation": state.get("test_generation_result", {}),
        "synthesis": state.get("synthesis", {}),
    }

    report = ReportGenerator().generate(agent_output)
    return {**state, "final_report": report}


# ─────────────────────────────────────────
# Build the LangGraph StateGraph
# ─────────────────────────────────────────

def build_graph() -> Any:
    graph = StateGraph(ScanState)

    # register nodes
    graph.add_node("planner", planner_node)
    graph.add_node("test_generation", test_generation_node)
    graph.add_node("security", security_node)
    graph.add_node("api_testing", api_testing_node)
    graph.add_node("deployment", deployment_node)
    graph.add_node("deep_scan", deep_scan_node)
    graph.add_node("synthesis", synthesis_node)
    graph.add_node("report", report_node)

    # entry point
    graph.set_entry_point("planner")

    # linear edges through main pipeline
    graph.add_edge("planner", "test_generation")
    graph.add_edge("test_generation", "security")
    graph.add_edge("security", "api_testing")
    graph.add_edge("api_testing", "deployment")

    # conditional edge: deep_scan or synthesis
    graph.add_conditional_edges(
        "deployment",
        should_deep_scan,
        {
            "deep_scan": "deep_scan",
            "synthesis": "synthesis"
        }
    )

    # both deep_scan and synthesis lead to report
    graph.add_edge("deep_scan", "synthesis")
    graph.add_edge("synthesis", "report")
    graph.add_edge("report", END)

    return graph.compile()


# module-level compiled graph
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

    def run_all(self, parsed_data: dict, auth_config: dict = None) -> dict:
        initial_state: ScanState = {
            "parsed_data": parsed_data,
            "planner_result": {},
            "test_generation_result": {},
            "security_result": {},
            "api_test_result": {},
            "deployment_result": {},
            "deep_scan_result": {},
            "synthesis": {},
            "final_report": {},
            "deep_scan_needed": False,
            "auth_config": auth_config or {},
            "scan_mode": "full",
            "previous_scan_id": None,
        }

        graph = get_graph()
        final_state = graph.invoke(initial_state)
        return final_state["final_report"]

    def run_verify_fix(self, parsed_data: dict, targeted_test_cases: list) -> dict:
        """
        Run a lightweight verify-fix scan using only targeted test cases.

        Pipeline:
        - planner: skipped (too expensive for verify-fix mode, use empty result)
        - api_testing: runs targeted test cases only
        - synthesis: correlates new results against targeted cases

        Skipped: security agent (full scan), deep_scan, deployment
        """
        auth_config = parsed_data.get("auth", {})

        # Planner - skip for performance, use empty result
        planner_result = {"status": "skipped", "plan": None}

        # Test Generation - use targeted cases directly instead of generating new ones
        test_generation_result = {
            "status": "completed",
            "test_cases_generated": len(targeted_test_cases),
            "test_cases": targeted_test_cases,
        }

        # API Testing - run only targeted cases
        api_test_result = APITestingAgent().run(
            parsed_data,
            planner_result=planner_result,
            test_generation_result=test_generation_result,
            auth_config=auth_config,
        )

        # Security - skipped (lightweight mode)
        security_result = {
            "status": "skipped",
            "findings": [],
            "total_findings": 0,
            "critical_count": 0,
            "high_count": 0,
        }

        # Deployment - skipped
        deployment_result = {"status": "skipped"}

        # Deep scan - skipped
        deep_scan_result = {"status": "skipped"}

        # Synthesis - correlate results
        synthesis_result = self._run_verify_fix_synthesis(
            parsed_data=parsed_data,
            api_test_result=api_test_result,
            security_result=security_result,
            targeted_cases=targeted_test_cases,
        )

        return {
            "fixed_findings": synthesis_result.get("fixed_findings", []),
            "persistent_findings": synthesis_result.get("persistent_findings", []),
            "new_issues": synthesis_result.get("new_issues", []),
            "overall_status": synthesis_result.get("overall_status", "stable"),
        }

    def _run_verify_fix_synthesis(
        self,
        parsed_data: dict,
        api_test_result: dict,
        security_result: dict,
        targeted_cases: list,
    ) -> dict:
        """
        Correlate new test results against targeted cases to determine
        which issues are fixed, persistent, or new.
        """
        fixed_findings = []
        persistent_findings = []
        new_issues = []

        test_results = api_test_result.get("results", [])

        # Build a map of targeted cases by (endpoint, method)
        targeted_map = {}
        for tc in targeted_cases:
            key = (tc.get("target_endpoint", ""), tc.get("target_method", ""))
            targeted_map[key] = tc

        # Correlate test results against targeted cases
        failed_endpoints_now = set()
        passed_endpoints_now = set()

        for ep_result in test_results:
            ep_path = ep_result.get("endpoint", "")
            ep_method = ep_result.get("method", "")
            key = (ep_path, ep_method)

            for t in ep_result.get("tests", []):
                if t.get("connection_error"):
                    continue
                if t.get("passed") is False:
                    failed_endpoints_now.add(key)
                else:
                    passed_endpoints_now.add(key)

        # For each targeted case, determine if it's fixed or persistent
        for tc in targeted_cases:
            key = (tc.get("target_endpoint", ""), tc.get("target_method", ""))

            if key in passed_endpoints_now:
                # Test now passes → this issue is fixed
                fixed_findings.append({
                    "endpoint": tc.get("target_endpoint"),
                    "method": tc.get("target_method"),
                    "vulnerability": tc.get("name"),
                    "previously": "failed",
                    "now": "passed",
                })
            elif key in failed_endpoints_now:
                # Test still fails → persistent
                persistent_findings.append({
                    "endpoint": tc.get("target_endpoint"),
                    "method": tc.get("target_method"),
                    "vulnerability": tc.get("name"),
                    "previously": "failed",
                    "now": "still failing",
                })
            # If key not in either (endpoint wasn't tested), leave it out

        # Determine overall status
        total_targeted = len(targeted_cases)
        if total_targeted == 0:
            overall_status = "no_targeted_cases"
        elif len(fixed_findings) == total_targeted:
            overall_status = "all_fixed"
        elif len(fixed_findings) > 0:
            overall_status = "improving"
        elif len(persistent_findings) == total_targeted:
            overall_status = "no_improvement"
        else:
            overall_status = "stable"

        return {
            "fixed_findings": fixed_findings,
            "persistent_findings": persistent_findings,
            "new_issues": new_issues,
            "overall_status": overall_status,
        }

