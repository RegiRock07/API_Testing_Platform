# MASTER_CONTEXT.md
## API Sentinel — Complete Project Context + Product Requirements
**Feed this to Claude Code at the start of every session.**

---

## PART 1: WHAT THIS PROJECT IS

API Sentinel is an automated API security testing platform. Users upload an OpenAPI specification or enter a live API URL. The system automatically analyzes it for security vulnerabilities using a multi-agent AI architecture, then displays a prioritized security report on a React dashboard.

**Version 1 (current)**: Rule-based agents, linear LangGraph pipeline, Anthropic API for a summary-only LLM call.

**Version 2 (building now)**: LLM-driven agents using Ollama (open-source, local, no paid API keys), real conditional branching in LangGraph, agents that communicate context to each other, streaming progress, and a richer report structure.

---

## PART 2: TECH STACK

| Layer | Technology | Notes |
|---|---|---|
| Frontend | React 19 | Single App.js file, no router, no CSS framework |
| Styling | Inline styles with design token object `C` | Never use Tailwind, never add external CSS libs |
| Backend | FastAPI + Python 3.11 | Uvicorn ASGI server |
| Database | SQLite via Python built-in sqlite3 | No ORM |
| Agent Orchestration | LangGraph StateGraph | Conditional edges, shared state TypedDict |
| LLM Runtime | Ollama | Local open-source models, REST API |
| Containerization | Docker + docker-compose | Backend on 8000, Frontend on 3000→80 |

---

## PART 3: OLLAMA INTEGRATION

**This project uses Ollama exclusively. No Anthropic API. No OpenAI. No paid keys.**

### How Ollama Works
- Ollama runs locally and exposes a REST API
- Base URL: `http://localhost:11434` (configurable via `OLLAMA_BASE_URL` env var)
- Chat endpoint: `POST /api/chat`
- Request: `{ "model": "llama3.1:8b", "messages": [...], "stream": false }`
- Response: `{ "message": { "role": "assistant", "content": "..." } }`

### Environment Variables for LLM
```
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_DEFAULT_MODEL=llama3.1:8b
PLANNER_MODEL=llama3.1:8b
SECURITY_MODEL=llama3.1:8b
DEEP_SCAN_MODEL=llama3.1:8b
SYNTHESIS_MODEL=llama3.1:8b
OLLAMA_TIMEOUT=60
```

### Rules for Prompting Open-Source Models
These rules are mandatory for every LLM call in every agent:
1. Start every prompt with a clear system role: "You are an expert API security analyst..."
2. Explicitly instruct: "Respond ONLY in valid JSON. Do not add any explanation, markdown, or text outside the JSON."
3. Always include a concrete JSON schema example inside the prompt showing the exact structure expected
4. Always wrap parsing in try/except — strip markdown fences (` ```json ``` `) before calling json.loads()
5. Never let a failed LLM call crash the scan — always fall back to rule-based logic
6. Set timeout on every Ollama HTTP request (use `OLLAMA_TIMEOUT` env var, default 60s)

### Fallback Rule
If Ollama is unreachable OR the LLM call fails OR JSON parsing fails:
- Log the error
- Run the existing rule-based logic instead
- Mark result with `"llm_used": false` so the report can show the difference
- The scan must complete successfully regardless

---

## PART 4: AGENT ARCHITECTURE

### v2 Agent Execution Order (LangGraph graph)
```
planner → security → api_testing → deployment
                                        │
                              [conditional edge]
                    critical_count > 0 OR high_count >= 3
                             /                   \
                       deep_scan             (skip)
                             \                   /
                              → synthesis → report → END
```

### Agent: Planner (NEW — does not exist yet)
**File**: `backend/app/agents/planner_agent.py`
**Runs**: First, before all other agents
**Purpose**: Uses LLM to read the full spec and create a structured testing plan that all other agents use

Input: full `parsed_data` dict (endpoints, title, version)

LLM task: Act as API security architect, analyze the spec and output:
- `risk_summary`: 2-3 sentence overview of the API's overall risk posture
- `auth_pattern_detected`: none / api_key / bearer / basic / oauth / unknown
- `high_risk_endpoints`: list of objects with path, method, risk_level (CRITICAL/HIGH/MEDIUM), risk_reasons[], recommended_tests[], attack_vectors[]
- `testing_priorities`: ordered list of endpoints to test first with reason
- `business_logic_risks`: list of inferred business logic vulnerabilities from endpoint names/structure
- `suggested_fuzz_categories`: map of endpoint path → list of payload category names to use

Fallback (no Ollama): Return empty plan `{}` — all other agents proceed with their default logic.

Output structure returned by agent:
```python
{
  "agent": "planner",
  "status": "completed" | "skipped",
  "llm_used": bool,
  "plan": { ...the JSON above... }
}
```

---

### Agent: Security (FULL REWRITE of existing security_agent.py)
**File**: `backend/app/agents/security_agent.py`
**Current state**: Pure if/else rules. No LLM. Flags every parameterized endpoint as BOLA.

New behavior:
- Receives both `parsed_data` AND `planner_result` as inputs
- For each endpoint: build a prompt with the endpoint's full details + planner's context for that endpoint
- LLM reasons about what vulnerabilities exist and why — not hardcoded rules
- LLM must provide evidence, exploit_scenario, and remediation specific to that endpoint
- Deduplicate findings by endpoint + vulnerability combination before returning

Finding structure (v2 — note field name change from `risk_type` to `vulnerability`):
```python
{
  "endpoint": path,
  "method": method,
  "vulnerability": "specific name",     # ← NEW field name (was risk_type)
  "owasp_category": "OWASP API1:2023...",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": "HIGH|MEDIUM|LOW",      # ← no longer always "POTENTIAL"
  "description": "specific to this endpoint",
  "evidence": "what in spec suggests this",
  "exploit_scenario": "how attacker exploits",
  "remediation": "specific fix for this endpoint"
}
```

Fallback (no Ollama): Use the existing rule-based logic from v1 AS-IS. The old rules become the fallback.

Returns:
```python
{
  "agent": "security",
  "status": "completed",
  "llm_used": bool,
  "total_findings": int,
  "critical_count": int,
  "high_count": int,
  "findings": [...]
}
```

---

### Agent: API Testing (FULL REWRITE of existing api_testing_agent.py)
**File**: `backend/app/agents/api_testing_agent.py`
**Current bugs**: Connection errors = failures. Static fuzz payloads. No connectivity pre-check.

New behavior:

**Step 1 — Connectivity check**: Before running ANY tests, check if target API is reachable. If not → return status "skipped" with clear message. Do NOT mark tests as failed.

**Step 2 — Context-aware fuzzing**: Use planner's `suggested_fuzz_categories` for each endpoint to pick relevant payloads. Payload library organized by category: sql_injection, xss, path_traversal, integer_overflow, null_byte, ssti, auth_bypass.

**Step 3 — Response interpretation**: Use LLM to interpret ambiguous 500 responses — is it a real vulnerability or a benign crash? Prevents false positives.

**Step 4 — Test types** (same as v1 but with fixed error handling):
1. valid_request, 2. invalid_parameter, 3. nonexistent_resource, 4. wrong_method, 5. context_aware_fuzz

Test result must distinguish:
- `passed: true` → test passed
- `passed: false, connection_error: true, note: "not a security finding"` → unreachable
- `passed: false, connection_error: false` → real test failure

Returns:
```python
{
  "agent": "api_testing",
  "status": "completed" | "skipped",
  "api_was_reachable": bool,
  "base_url_tested": str,
  "results": [...]
}
```

---

### Agent: Deployment (EXPAND existing deployment_agent.py)
**File**: `backend/app/agents/deployment_agent.py`
**Current state**: Only pings /health, checks status code.

New checks to add:
1. Health endpoint + response latency (ms)
2. Security headers: check for X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security, Content-Security-Policy, X-XSS-Protection, Referrer-Policy — list missing ones
3. HTTPS: flag if URL starts with http:// and looks like a production URL
4. CORS: OPTIONS request with evil origin, check if Access-Control-Allow-Origin: * returned
5. API docs exposure: check /docs, /swagger-ui, /openapi.json, /redoc — flag if publicly accessible

Returns:
```python
{
  "agent": "deployment",
  "status": "healthy" | "unhealthy" | "unreachable",
  "status_code": int,
  "latency_ms": float,
  "security_headers": { "present": [...], "missing": [...] },
  "https_enforced": bool,
  "cors_misconfigured": bool,
  "docs_exposed": bool,
  "docs_exposed_at": str | None,
  "security_score": "X/6",
  "deployment_findings": [ { "check": str, "issue": str } ]
}
```

---

### Agent: Deep Scan (NEW — does not exist yet)
**File**: `backend/app/agents/deep_scan_agent.py`
**Triggered**: ONLY via LangGraph conditional edge when `critical_count > 0 OR high_count >= 3`

Purpose: Takes top 5 critical/high findings, uses LLM to generate proof-of-concept exploit scenarios.

For each finding, LLM generates:
- Step-by-step exploit instructions
- Sample HTTP request in curl format
- Expected vulnerable response
- Verification test (how to confirm fix worked)

Merges `exploit_poc` and `verification_test` fields back into the security findings.

Fallback: If Ollama unavailable, skip silently. Report marks `deep_scan_performed: false`.

---

### Agent: Synthesis (NEW — does not exist yet)
**Logic location**: Can be a node in orchestrator.py or a separate file
**Purpose**: Cross-agent correlation after all other agents complete

Tasks:
1. Find security findings AND test failures on the SAME endpoint → mark as `confirmed: true`
2. Find systemic patterns (e.g., auth missing on 5+ endpoints = architectural issue not just individual findings)
3. Use LLM for executive summary, cross-cutting concerns, remediation roadmap, security score

Returns:
```python
{
  "correlated_findings": [...],
  "cross_cutting_concerns": [...],
  "executive_summary": "3 sentences, non-technical",
  "remediation_roadmap": {
    "immediate": [...],
    "short_term": [...],
    "long_term": [...]
  },
  "overall_risk_score": "7.5/10 — HIGH RISK",
  "security_score": 7.5
}
```

---

## PART 5: LANGGRAPH STATE OBJECT (v2)

```python
class ScanState(TypedDict):
    parsed_data: dict         # spec parser output
    planner_result: dict      # planner agent output
    security_result: dict     # security agent output
    api_test_result: dict     # api testing agent output
    deployment_result: dict   # deployment agent output
    deep_scan_result: dict    # deep scan output (empty if not triggered)
    synthesis: dict           # synthesis agent output
    final_report: dict        # assembled report
    deep_scan_needed: bool    # set by conditional edge
```

### Conditional Edge Logic
After `deployment` node completes, evaluate:
- If `security_result["critical_count"] > 0` OR `security_result["high_count"] >= 3` → route to `deep_scan`
- Otherwise → route to `synthesis`

---

## PART 6: DATABASE SCHEMA

### Existing table: scans (DO NOT MODIFY)
```sql
CREATE TABLE scans (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'parsed',
    api_title       TEXT,
    api_version     TEXT,
    endpoint_count  INTEGER DEFAULT 0,
    original_spec   TEXT,   -- JSON blob
    parsed_data     TEXT,   -- JSON blob
    report          TEXT    -- JSON blob, NULL until scan completes
);
```

### New table: agent_logs (ADD in v2)
```sql
CREATE TABLE IF NOT EXISTS agent_logs (
    id              TEXT PRIMARY KEY,
    scan_id         TEXT NOT NULL,
    agent_name      TEXT NOT NULL,
    status          TEXT NOT NULL,
    started_at      TEXT,
    completed_at    TEXT,
    duration_ms     INTEGER,
    result_summary  TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
```

Helper function to add: `log_agent_run(scan_id, agent_name, status, summary="")` → inserts a log row.

---

## PART 7: BACKEND API ENDPOINTS

### Existing (keep all of these exactly as-is)
| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Root, returns version info |
| GET | `/health` | Health check |
| GET | `/api/scans` | List scan history |
| GET | `/api/scans/{id}/report` | Get report for a scan |
| DELETE | `/api/scans/{id}` | Delete a scan |
| POST | `/api/specs/upload` | Upload OpenAPI JSON body |
| POST | `/api/specs/upload-file` | Upload .json or .yaml file |
| GET | `/api/specs/{id}` | Get parsed spec |
| POST | `/api/run/{id}` | Run all agents (blocking, LangGraph) |
| POST | `/api/scan-url` | Discover spec from URL + run scan |

### New endpoints to add (v2)
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/run/{id}/stream` | Run agents with SSE streaming |
| GET | `/api/scans/{id}/agents` | Get agent logs for a scan |

### Streaming Endpoint `/api/run/{id}/stream`
Returns Server-Sent Events. Each event:
```
data: {"agent": "planner", "status": "running"}\n\n
data: {"agent": "planner", "status": "completed", "data": {"plan_ready": true}}\n\n
...
data: {"agent": "report", "status": "completed", "data": {"report": {...full report...}}}\n\n
data: [DONE]\n\n
```

Status values: `"running"` | `"completed"` | `"skipped"` | `"error"`

Event sequence: planner → security → api_testing → deployment → deep_scan (or skipped) → synthesis → report → [DONE]

---

## PART 8: REPORT OBJECT STRUCTURE (v2)

The full report object stored in SQLite and returned to frontend:

```
report:
  summary:
    critical_risks          int
    high_risks              int
    medium_risks            int
    low_risks               int
    total_security_findings int
    total_tests_run         int
    failed_tests            int   ← real failures only, NOT connection errors
    passed_tests            int
    connection_errors       int   ← clearly separated
    deployment_status       str
    deployment_security_score  str   "X/6"
    overall_risk_score      str   "7.5/10 — HIGH RISK"
    api_was_reachable       bool
    deep_scan_performed     bool

  planner_assessment        dict   ← planner plan object
  security_findings         list   ← findings (with exploit_poc if deep scan ran)
  api_test_results          list   ← per-endpoint test results
  deployment                dict   ← full deployment agent output
  synthesis                 dict   ← cross-agent correlation
  executive_summary         str    ← 3 sentences, non-technical
  remediation_roadmap       dict   ← {immediate, short_term, long_term}
  security_score            float  ← 0-10
  recommendations           list   ← deduplicated action list
```

---

## PART 9: FRONTEND ARCHITECTURE

### Non-negotiable rules for App.js
- **Single file only** — never split into multiple files, never add a router
- **No new npm packages** — use only what's in current package.json
- **Preserve all existing color tokens in object `C`** — do not rename or change values
- **Preserve existing component names** — Pill, StatCard, Btn, Input, LoginScreen, HistorySidebar, SecurityTable, TestResults, ReportView
- **Preserve existing state variable names** in App() — specText, specId, file, apiUrl, report, activeScanId, loading, error, sidebarKey

### New components to add (in App.js)
**`AgentProgress({ events })`**:
- Shows during active scan, disappears when report renders
- Lists 6 agents: Planner, Security, API Testing, Deployment, Deep Scan, Synthesis
- Each agent row: icon (○=waiting, ⟳=running, ✓=completed, —=skipped) + name + key metric
- State driven by `streamEvents` array

**New state variable**: `streamEvents` = array of SSE event objects, cleared at start of each scan

### Updated `runScan` function (use streaming)
When "Run Security Scan" is clicked:
1. Call `POST /api/run/{specId}/stream` (SSE endpoint)
2. Read stream events using `response.body.getReader()`
3. Parse each `data: {...}` line as JSON
4. Push to `streamEvents` state → drives AgentProgress display
5. When event `{ agent: "report", status: "completed" }` arrives → extract `event.data.report` → set as `report` state

### New tabs in ReportView
Add to existing tabs array:
- **"Planner" tab**: Shows `report.planner_assessment.risk_summary` paragraph, table of `high_risk_endpoints` with risk reasons, list of `business_logic_risks`, auth pattern badge
- **"Roadmap" tab**: Three sections Immediate/Short-term/Long-term from `report.remediation_roadmap`

### Updated existing UI
- **Summary cards**: Add Critical Risks card (separate from High), Security Score card (0-10)
- **SecurityTable**: Column name stays the same but reads `f.vulnerability` OR `f.risk_type` (support both for backward compat). Show "DEEP SCAN" badge if `f.exploit_poc` present. Expand panel shows evidence, exploit_scenario, remediation, and exploit_poc if available.
- **TestResults**: Connection errors display differently — gray color + "unreachable" note instead of red FAIL. Show banner if API was not reachable.
- **AI Analysis tab**: Show `report.executive_summary` prominently + cross_cutting_concerns list. Update placeholder message to say "Start Ollama and pull a model" instead of ANTHROPIC_API_KEY message.

---

## PART 10: ENVIRONMENT VARIABLES (complete list)

| Variable | Default | Purpose |
|---|---|---|
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server URL |
| `OLLAMA_DEFAULT_MODEL` | `llama3.1:8b` | Fallback model |
| `PLANNER_MODEL` | `llama3.1:8b` | Planner Agent model |
| `SECURITY_MODEL` | `llama3.1:8b` | Security Agent model |
| `DEEP_SCAN_MODEL` | `llama3.1:8b` | Deep Scan Agent model |
| `SYNTHESIS_MODEL` | `llama3.1:8b` | Synthesis Agent model |
| `OLLAMA_TIMEOUT` | `60` | LLM call timeout in seconds |
| `SENTINEL_API_KEY` | `` | Auth key (blank = dev mode) |
| `ALLOWED_ORIGINS` | `*` | CORS allowed origins |
| `SENTINEL_DB_PATH` | `/data/sentinel.db` | SQLite path |
| `REACT_APP_API_URL` | `http://localhost:8000` | Backend URL (baked into React at build time) |
| `REACT_APP_APP_NAME` | `API Sentinel` | App name shown in UI |

---

## PART 11: EXECUTION ORDER FOR CLAUDE CODE

Work through in this exact order. Complete each before moving to next.

```
Step 1: Update requirements.txt
  - Remove: anthropic
  - Add: httpx (for Ollama HTTP calls)

Step 2: Update database.py
  - Add agent_logs table to init_db()
  - Add log_agent_run() helper function
  - Do NOT modify scans table

Step 3: Update .env.example
  - Remove ANTHROPIC_API_KEY
  - Add all OLLAMA_* variables

Step 4: Create planner_agent.py (new file)
  - Ollama call with JSON output
  - Full fallback to empty plan

Step 5: Rewrite security_agent.py
  - Ollama per-endpoint analysis
  - Keep v1 rules as fallback
  - New finding field: vulnerability (not risk_type)
  - Add critical_count, high_count to output

Step 6: Rewrite api_testing_agent.py
  - Add connectivity pre-check
  - Add payload category library
  - Add connection_error distinction
  - Context-aware fuzzing from planner

Step 7: Expand deployment_agent.py
  - Add security headers check
  - Add CORS check
  - Add docs exposure check
  - Add latency measurement

Step 8: Create deep_scan_agent.py (new file)
  - Ollama exploit PoC generation
  - Graceful skip if Ollama unavailable

Step 9: Rewrite orchestrator.py
  - New ScanState with all new fields
  - Add planner_node
  - Pass planner context to security and api_testing nodes
  - Add conditional edge after deployment
  - Add deep_scan_node
  - Add synthesis_node

Step 10: Update report_generator.py
  - Handle new finding fields
  - Handle planner_assessment
  - Handle synthesis output
  - New summary fields (critical, connection_errors, etc.)

Step 11: Add streaming endpoint to endpoints.py
  - POST /api/run/{id}/stream
  - SSE response
  - GET /api/scans/{id}/agents

Step 12: Update docker-compose.yml
  - Replace ANTHROPIC_API_KEY with OLLAMA_* vars

Step 13: Update App.js frontend
  - Add streamEvents state
  - Add AgentProgress component
  - Update runScan to use streaming
  - Add Planner and Roadmap tabs
  - Update SecurityTable for new fields
  - Update TestResults for connection error distinction
  - Update AI Analysis tab message
  - Add Critical card + Security Score card
```

---

## PART 12: CRITICAL INVARIANTS

These must remain true at all times. Never violate these:

1. **System works with no Ollama** — every LLM call must have a rule-based fallback. A scan with no Ollama must complete successfully.
2. **Connection errors are never security failures** — if the target API is unreachable, tests are "skipped", not "failed".
3. **Never crash on LLM response** — always try/except, always strip markdown fences, always have fallback.
4. **Never modify the scans table schema** — only add new tables.
5. **App.js stays one file** — no splitting, no router.
6. **All design tokens in `C` object preserved** — colors and fonts unchanged.
7. **All existing API routes preserved** — `/api/run/{id}` blocking endpoint must still work.
8. **Backward compatibility** — `SecurityTable` must handle both `f.risk_type` (v1) and `f.vulnerability` (v2) field names.

---

## PART 13: TESTING CHECKLIST

Run these tests to verify the implementation:

**Backend (no Ollama)**:
- Upload sample-api/openapi.json → should parse 3 endpoints
- Run scan → should complete using rule-based fallback, report should generate
- Verify `llm_used: false` in results

**Backend (with Ollama)**:
- Pull model: `ollama pull llama3.1:8b`
- Run scan → planner should return structured plan with high_risk_endpoints
- Security findings should have evidence + exploit_scenario fields
- Verify `llm_used: true` in results

**Sample API testing**:
- Run `sample-api/main.py` on port 8001
- Run full scan with base_url set to `http://localhost:8001`
- API Testing Agent should mark tests as completed (not skipped)
- Should detect BOLA on `/users/{user_id}` and auth issues

**Connection error behavior**:
- Point scan at a non-existent URL
- API Testing Agent should return `status: "skipped"`, NOT a list of failed tests
- Failed_tests count in summary should be 0

**Streaming**:
- Test with curl: `curl -N -X POST http://localhost:8000/api/run/{spec_id}/stream`
- Should see SSE events appear one by one as agents complete
- Final event should contain full report

**Frontend**:
- AgentProgress panel should show during scan
- Should update in real-time as each agent completes
- Planner tab should show risk_summary and high_risk_endpoints
- Roadmap tab should show three sections
- Connection errors in TestResults should be gray, not red
