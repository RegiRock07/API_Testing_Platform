# backend/app/orchestrator.py
#
# Replaces the old sequential Orchestrator with a LangGraph StateGraph.
# Each agent is a node. An LLM router node decides per-endpoint risk level.
# Falls back to rule-based mode if ANTHROPIC_API_KEY is not set.

from __future__ import annotations

import os
import json
from typing import TypedDict, Any

from langgraph.graph import StateGraph, END

from app.agents.security_agent import SecurityAgent
from app.agents.api_testing_agent import APITestingAgent
from app.agents.deployment_agent import DeploymentAgent
from app.reporting.report_generator import ReportGenerator


# ─────────────────────────────────────────
# Shared state that flows through the graph
# ─────────────────────────────────────────

class ScanState(TypedDict):
    parsed_data: dict[str, Any]
    security_result: dict[str, Any]
    api_test_result: dict[str, Any]
    deployment_result: dict[str, Any]
    llm_analysis: str          # narrative from LLM router
    final_report: dict[str, Any]


# ─────────────────────────────────────────
# Node: Security Agent
# ─────────────────────────────────────────

def security_node(state: ScanState) -> ScanState:
    result = SecurityAgent().run(state["parsed_data"])
    return {**state, "security_result": result}


# ─────────────────────────────────────────
# Node: API Testing Agent
# ─────────────────────────────────────────

def api_testing_node(state: ScanState) -> ScanState:
    result = APITestingAgent().run(state["parsed_data"])
    return {**state, "api_test_result": result}


# ─────────────────────────────────────────
# Node: Deployment Agent
# ─────────────────────────────────────────

def deployment_node(state: ScanState) -> ScanState:
    base_url = state["parsed_data"].get("base_url", "http://localhost:8000")
    result = DeploymentAgent().run(base_url=base_url)
    return {**state, "deployment_result": result}


# ─────────────────────────────────────────
# Node: LLM Router + Analyst
# Reads all agent outputs and produces an
# enriched narrative analysis using Claude.
# Gracefully skips if no API key is set.
# ─────────────────────────────────────────

def llm_analysis_node(state: ScanState) -> ScanState:
    api_key = os.getenv("ANTHROPIC_API_KEY", "")

    if not api_key:
        return {**state, "llm_analysis": "LLM analysis skipped (ANTHROPIC_API_KEY not set)."}

    try:
        import anthropic

        client = anthropic.Anthropic(api_key=api_key)

        security_findings = state["security_result"].get("findings", [])
        endpoints = state["parsed_data"].get("endpoints", [])
        deployment_status = state["deployment_result"].get("status", "unknown")

        prompt = f"""You are an expert API security analyst. 
Review the following automated scan results and provide:
1. A brief executive summary (2-3 sentences)
2. The top 3 most critical findings with reasoning
3. Prioritized remediation steps

API Info:
- Title: {state["parsed_data"].get("title", "Unknown")}
- Total endpoints: {len(endpoints)}
- Deployment status: {deployment_status}

Security Findings ({len(security_findings)} total):
{json.dumps(security_findings[:10], indent=2)}

Respond in plain English. Be specific and actionable.
"""

        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}]
        )

        analysis = message.content[0].text
        return {**state, "llm_analysis": analysis}

    except Exception as e:
        return {**state, "llm_analysis": f"LLM analysis failed: {str(e)}"}


# ─────────────────────────────────────────
# Node: Report Generator
# ─────────────────────────────────────────

def report_node(state: ScanState) -> ScanState:
    agent_output = {
        "security": state["security_result"],
        "api_testing": state["api_test_result"],
        "deployment": state["deployment_result"],
    }

    report = ReportGenerator().generate(agent_output)

    # attach LLM narrative to the report
    report["llm_analysis"] = state.get("llm_analysis", "")

    return {**state, "final_report": report}


# ─────────────────────────────────────────
# Build the LangGraph StateGraph
# ─────────────────────────────────────────

def build_graph() -> Any:
    graph = StateGraph(ScanState)

    # register nodes
    graph.add_node("security", security_node)
    graph.add_node("api_testing", api_testing_node)
    graph.add_node("deployment", deployment_node)
    graph.add_node("llm_analysis", llm_analysis_node)
    graph.add_node("report", report_node)

    # edges — security and api_testing run first (could be parallelised later)
    graph.set_entry_point("security")
    graph.add_edge("security", "api_testing")
    graph.add_edge("api_testing", "deployment")
    graph.add_edge("deployment", "llm_analysis")
    graph.add_edge("llm_analysis", "report")
    graph.add_edge("report", END)

    return graph.compile()


# module-level compiled graph (created once, reused)
_graph = None

def get_graph():
    global _graph
    if _graph is None:
        _graph = build_graph()
    return _graph


# ─────────────────────────────────────────
# Public interface — drop-in replacement
# for the old Orchestrator class
# ─────────────────────────────────────────

class Orchestrator:
    """
    Drop-in replacement for the old Orchestrator.
    Internally uses a LangGraph StateGraph.
    """

    def run_all(self, parsed_data: dict) -> dict:
        initial_state: ScanState = {
            "parsed_data": parsed_data,
            "security_result": {},
            "api_test_result": {},
            "deployment_result": {},
            "llm_analysis": "",
            "final_report": {},
        }

        graph = get_graph()
        final_state = graph.invoke(initial_state)

        return final_state["final_report"]