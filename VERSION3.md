# VERSION3.md
## API Sentinel — Complete Project Context + Product Requirements
**Feed this to Claude Code at the start of every session.**
**v2 (MASTER_CONTEXT.md) is implemented. This file covers v3.**

---

## PART 1: WHAT THIS PROJECT IS

API Sentinel is an automated API security testing platform. Users upload an OpenAPI specification or enter a live API URL. The system automatically analyzes it for security vulnerabilities using a multi-agent AI architecture, then displays a prioritized security report on a React dashboard.

**Version 1**: Rule-based agents, linear LangGraph pipeline, Anthropic API for a summary-only LLM call.

**Version 2 (implemented)**: LLM-driven agents using Ollama, real conditional branching in LangGraph, agents that communicate context to each other, streaming progress, richer report structure. Planner, Security, API Testing, Deployment, Deep Scan, Synthesis agents. SSE streaming. agent_logs table.

**Version 3 (this file)**: Multi-user authentication, scan comparison, verify-fix mode, CI/CD webhooks, report export (PDF/JSON), scheduled scans, YAML spec support (already in endpoints but not parser), full OWASP Top 10 coverage (API5–API10), auth-aware API testing, LLM-generated test case runner.

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
| Auth | JWT (PyJWT) | Self-contained, no external IdP |
| Scheduled Jobs | APScheduler (in-process) | Lightweight, no Redis needed |
| PDF Export | ReportLab or WeasyPrint | For report PDF generation |

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
TEST_GENERATION_MODEL=llama3.1:8b
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

### v3 Agent Execution Order (LangGraph graph)
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

**v3 adds**: Test Generation Agent (runs before api_testing, feeds custom test cases into api_testing), and Scheduler/Webhook handler (runs outside the graph via APScheduler).

### Agent: Planner
**File**: `backend/app/agents/planner_agent.py`
**Status**: Implemented in v2. Minor v3 update: add `auth_pattern_detected` extraction from spec security schemes.

### Agent: Security — v3 OWASP Top 10 Expansion
**File**: `backend/app/agents/security_agent.py`
**Status**: Implemented in v2. v3 additions:

OWASP Top 10 coverage must be complete (API1–API10). Existing coverage: API1 (BOLA), API2 (Broken Auth), API3 (Excessive Data), API4 (Lack of Resources). New coverage needed:

**API5: Broken Function Level Authorization (BFLA)**
- Detect admin-only endpoints that lack explicit authorization checks
- Look for paths containing: `/admin`, `/manage`, `/configure`, `/system`, `/internal`, `/debug`, `/elevate`
- Look for methods: `DELETE` on sensitive resources, `PATCH`/`PUT` on admin endpoints
- LLM prompt: analyze each endpoint for function-level auth gaps

**API6: Unrestricted Resource Consumption**
- Detect missing rate limiting declarations in spec
- Flag endpoints with no `throttling` or `rateLimit` settings
- Identify endpoints processing large payloads without size limits
- Check for missing `maxItems`, `maxLength` on array/string fields

**API7: Server-Side Request Forgery (SSRF)**
- Identify endpoints accepting URLs/URIs as input parameters
- Look for: `url`, `uri`, `href`, `src`, `path`, `redirect`, `forward`, `callback`, `next` parameters
- Flag if the parameter type is `string` with `format: uri` or plain `string` near URL-like names
- LLM assesses if the API appears to fetch or process external resources

**API8: Security Misconfiguration**
- Already covered by Deployment agent (security headers, CORS, docs exposure)
- Add: debug mode detection, default credentials patterns, missing TLS enforcement
- Cross-reference deployment findings with security agent

**API9: Improper Inventory Management**
- Detect undocumented endpoints: endpoints in spec vs. live responses differ
- Versioning gaps: `/v1/` present but no `/v2/`, deprecated endpoints still active
- Shadow APIs: live responses contain routes not in the spec
- Flag `servers` array in spec — if multiple, check for configuration drift

**API10: Unsafe Consumption of APIs**
- Detect Third-Party API integrations from spec `servers` and `components/securitySchemes`
- If spec references external APIs (webhooks, callback URLs, OAuth provider URLs):
  - Flag as "external API trust chain" risk
  - LLM assesses what happens if the third-party is compromised
- Missing integration security: API keys passed as query params rather than headers

Finding structure (v3 — enriched):
```python
{
  "endpoint": path,
  "method": method,
  "vulnerability": "specific name",
  "owasp_category": "OWASP API1:2023..." / "OWASP API5:2023" / etc.,
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": "HIGH|MEDIUM|LOW",
  "description": "specific to this endpoint",
  "evidence": "what in spec suggests this",
  "exploit_scenario": "how attacker exploits",
  "remediation": "specific fix for this endpoint"
}
```

### Agent: Test Generation (NEW — v3)
**File**: `backend/app/agents/test_generation_agent.py`
**Runs**: Before api_testing agent, after planner
**Purpose**: Uses LLM to generate custom test cases based on the spec + planner context + OWASP Top 10 coverage gaps

Input: `parsed_data`, `planner_result`, `security_result` (to avoid redundant tests)
Output: List of structured test cases to run

LLM task: Generate specific test cases including:
- `test_name`: descriptive name
- `target_endpoint`: which endpoint
- `target_method`: HTTP method
- `test_type`: auth_bypass / bfla / rate_limit / ssrf / injection / etc.
- `payload`: the actual request payload or parameter values
- `expected_behavior`: pass | fail | error
- `assertion`: what to check in the response (status code, body contains, header present, etc.)
- `owasp_category`: which OWASP category this tests

Payload library categories (same as v2): sql_injection, xss, path_traversal, integer_overflow, null_byte, ssti, auth_bypass, bfla, ssrf, rate_limit

Returns:
```python
{
  "agent": "test_generation",
  "status": "completed" | "skipped",
  "llm_used": bool,
  "test_cases_generated": int,
  "test_cases": [
    {
      "test_name": str,
      "target_endpoint": str,
      "target_method": str,
      "test_type": str,
      "payload": dict | None,
      "headers": dict | None,
      "expected_behavior": str,
      "assertion": dict,
      "owasp_category": str
    }
  ]
}
```

Fallback (no Ollama): Return empty test_cases list — api_testing proceeds with its default test suite.

### Agent: API Testing — v3 Auth-Aware + LLM Test Cases
**File**: `backend/app/agents/api_testing_agent.py`
**Status**: Implemented in v2. v3 additions:

**Step 0 — Auth configuration (NEW)**: Read auth credentials from scan metadata:
- Check `parsed_data["auth"]` for `bearer_token`, `api_key`, `basic_username`, `basic_password`
- If `Authorization` header needed, attach it to ALL requests (testing endpoints WITH auth context)
- Additionally test endpoints WITHOUT auth to detect auth requirement gaps

**Step 1 — Connectivity check**: Same as v2. If unreachable → skip.

**Step 2 — Auth-aware fuzzing**: For each endpoint:
- First test WITH provided auth — does the endpoint work correctly with valid credentials?
- Then test WITHOUT auth (remove headers) — does it properly reject unauthorized requests?
- Detect: auth bypass (endpoint works without auth when it shouldn't), auth requirement (endpoint fails without auth)

**Step 3 — Run LLM-generated test cases**: Execute test_cases from test_generation_agent:
- For each test case, make the actual HTTP request
- Apply assertion logic
- Record: passed, failed, error, connection_error

**Step 4 — Response interpretation**: Same as v2 (LLM interprets 500 responses)

**Step 5 — Test types**:
1. valid_request
2. invalid_parameter
3. nonexistent_resource
4. wrong_method
5. context_aware_fuzz
6. auth_aware_test (v3 new: tests with and without credentials)
7. llm_generated_test (v3 new: runs test cases from test_generation_agent)

Test result structure (v3 — adds auth context fields):
```python
{
  "endpoint": str,
  "method": str,
  "tests": [
    {
      "test_type": str,
      "passed": bool,
      "connection_error": bool,
      "auth_used": bool,
      "status_code": int | None,
      "response_time_ms": float | None,
      "note": str | None,
      "assertion_matched": bool | None
    }
  ]
}
```

Returns:
```python
{
  "agent": "api_testing",
  "status": "completed" | "skipped",
  "api_was_reachable": bool,
  "base_url_tested": str,
  "auth_used": bool,
  "results": [...],
  "llm_generated_tests_run": int,
  "llm_generated_tests_passed": int
}
```

### Agent: Deployment — v3 (same as v2, no changes)
**File**: `backend/app/agents/deployment_agent.py`
**Status**: Implemented in v2. No v3 changes needed.

### Agent: Deep Scan — v3 (same as v2, no changes)
**File**: `backend/app/agents/deep_scan_agent.py`
**Status**: Implemented in v2. No v3 changes needed.

### Agent: Synthesis — v3 (same as v2, no changes)
**File**: `backend/app/orchestrator.py` (_run_synthesis function)
**Status**: Implemented in v2. No v3 changes needed.

---

## PART 5: LANGGRAPH STATE OBJECT (v3)

```python
class ScanState(TypedDict):
    parsed_data: dict         # spec parser output
    planner_result: dict      # planner agent output
    test_generation_result: dict  # NEW: test generation output
    security_result: dict     # security agent output
    api_test_result: dict     # api testing agent output
    deployment_result: dict   # deployment agent output
    deep_scan_result: dict    # deep scan output (empty if not triggered)
    synthesis: dict           # synthesis agent output
    final_report: dict        # assembled report
    deep_scan_needed: bool    # set by conditional edge
    auth_config: dict         # NEW: auth credentials for this scan
    scan_mode: str            # NEW: "full" | "verify_fix" | "comparison"
    previous_scan_id: str | None  # NEW: for verify_fix mode
```

### Conditional Edge Logic (same as v2)
After `deployment` node completes, evaluate:
- If `security_result["critical_count"] > 0` OR `security_result["high_count"] >= 3` → route to `deep_scan`
- Otherwise → route to `synthesis`

### Test Generation Node Position
`planner → test_generation → security → api_testing → deployment`
(test_generation runs after planner, feeds into api_testing)

---

## PART 6: DATABASE SCHEMA (v3)

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
    original_spec   TEXT,
    parsed_data     TEXT,
    report          TEXT,
    user_id         TEXT    -- NEW: owner of this scan
);
```

### Existing table: agent_logs (DO NOT MODIFY)
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

### New table: users (ADD in v3)
```sql
CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,
    email           TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    last_login      TEXT,
    is_active       INTEGER DEFAULT 1
);
```

### New table: scheduled_scans (ADD in v3)
```sql
CREATE TABLE IF NOT EXISTS scheduled_scans (
    id                  TEXT PRIMARY KEY,
    user_id             TEXT NOT NULL,
    scan_name           TEXT NOT NULL,
    spec_id             TEXT,    -- NULL if URL-based
    base_url            TEXT,
    auth_config         TEXT,    -- JSON: {bearer_token, api_key, etc.}
    interval_hours      INTEGER,
    enabled             INTEGER DEFAULT 1,
    last_run_at         TEXT,
    next_run_at         TEXT,
    alert_on_new_findings  INTEGER DEFAULT 1,
    webhook_url         TEXT,
    created_at          TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### New table: webhooks (ADD in v3)
```sql
CREATE TABLE IF NOT EXISTS webhooks (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    name            TEXT NOT NULL,
    target_url      TEXT NOT NULL,
    secret          TEXT,    -- for HMAC signature verification
    event_types     TEXT,    -- JSON array: ["scan.completed", "scan.failed", "scan.new_critical"]
    active          INTEGER DEFAULT 1,
    created_at      TEXT NOT NULL,
    last_triggered  TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### New table: scan_comparison (ADD in v3)
```sql
CREATE TABLE IF NOT EXISTS scan_comparison (
    id                  TEXT PRIMARY KEY,
    user_id             TEXT NOT NULL,
    scan_a_id           TEXT NOT NULL,   -- older scan
    scan_b_id           TEXT NOT NULL,   -- newer scan
    created_at          TEXT NOT NULL,
    findings_resolved   INTEGER DEFAULT 0,
    findings_new        INTEGER DEFAULT 0,
    findings_worsened   INTEGER DEFAULT 0,
    score_improvement   REAL,
    comparison_data     TEXT,   -- JSON blob
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (scan_a_id) REFERENCES scans(id),
    FOREIGN KEY (scan_b_id) REFERENCES scans(id)
);
```

Helper functions to add:
- `create_user(email, password_hash) -> str user_id`
- `get_user_by_email(email) -> Optional[dict]`
- `verify_password(plain, hashed) -> bool`
- `hash_password(plain) -> str`
- `save_scheduled_scan(...) -> str`
- `get_scheduled_scans_for_user(user_id) -> list`
- `update_scheduled_scan_run(scan_id, next_run_at)`
- `save_webhook(...) -> str`
- `save_scan_comparison(...) -> str`

---

## PART 7: BACKEND API ENDPOINTS (v3)

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
| POST | `/api/run/{id}/stream` | Run agents with SSE streaming |
| GET | `/api/scans/{id}/agents` | Get agent logs for a scan |

### New endpoints to add (v3)

#### Auth endpoints
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/auth/register` | Register new user |
| POST | `/api/auth/login` | Login, returns JWT |
| GET | `/api/auth/me` | Get current user profile |
| POST | `/api/auth/logout` | Invalidate token (client-side discard) |

#### User management
| Method | Path | Purpose |
|---|---|---|
| GET | `/api/users/scans` | List user's scans (per-user isolation) |
| DELETE | `/api/users/scans/{id}` | Delete user's own scan |
| GET | `/api/users/settings` | Get user settings |
| PUT | `/api/users/settings` | Update user settings |

#### Scan comparison
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/scans/compare` | Compare two scans, returns diff |
| GET | `/api/scans/compare/{comparison_id}` | Get comparison result |
| GET | `/api/scans/{id}/history` | Get all scans for same spec+user |

#### Verify-fix mode
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/run/{id}/verify-fix` | Re-run only failed checks from scan {id} |
| POST | `/api/run/{id}/verify-fix/stream` | SSE stream for verify-fix mode |

#### Scheduled scans
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/schedules` | Create a scheduled scan |
| GET | `/api/schedules` | List user's scheduled scans |
| GET | `/api/schedules/{id}` | Get schedule details |
| PUT | `/api/schedules/{id}` | Update schedule |
| DELETE | `/api/schedules/{id}` | Delete schedule |
| POST | `/api/schedules/{id}/run` | Trigger a schedule immediately |

#### Webhooks
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/webhooks` | Create a webhook |
| GET | `/api/webhooks` | List user's webhooks |
| DELETE | `/api/webhooks/{id}` | Delete a webhook |
| POST | `/api/webhooks/test` | Send test webhook payload |

#### Report export
| Method | Path | Purpose |
|---|---|---|
| GET | `/api/scans/{id}/report/export/json` | Download report as JSON |
| GET | `/api/scans/{id}/report/export/pdf` | Download report as PDF |

### Auth Flow (JWT)
1. User registers with email + password
2. Password hashed with bcrypt (via `passlib` + `bcrypt`)
3. On login, verify password, return JWT token (expires in 7 days)
4. All subsequent requests include `Authorization: Bearer <token>` header
5. Backend dependency `get_current_user` decodes JWT, injects `user_id` into request state
6. All scan operations scope to `user_id` — users can only see/manage their own scans
7. API key auth (existing `X-API-Key` header) still works for programmatic access (treated as super-user, no user isolation)

### JWT Implementation Details
- Algorithm: HS256
- Secret: `JWT_SECRET` env var (default to a fixed dev secret if unset)
- Payload: `{ "sub": user_id, "email": email, "exp": expiry_timestamp }`
- Use `PyJWT` library (no external deps)
- Token passed via `Authorization: Bearer <token>` header

### Auth Config in Scans
When creating a scan, client can include:
```json
{
  "name": "My API Scan",
  "spec": { ... },
  "auth": {
    "type": "bearer" | "api_key" | "basic" | "oauth",
    "bearer_token": "...",
    "api_key": "...",
    "api_key_header": "X-API-Key",
    "basic_username": "...",
    "basic_password": "..."
  }
}
```
Auth config stored in `parsed_data["auth"]` and passed to agents.

### Verify-Fix Mode Logic
When `/api/run/{id}/verify-fix` is called:
1. Load previous scan's report
2. Extract all `security_findings` where `confirmed: true` (correlated with test failures)
3. Extract all `api_test_results` where `passed: false AND connection_error: false`
4. Build a targeted test plan: only re-test those specific endpoints + methods
5. Run a minimal agent pipeline: security (skip or lightweight) + api_testing (targeted) + synthesis
6. Return comparison: which findings are now fixed, which persist
7. Do NOT run deep_scan in verify-fix mode

Output structure for verify-fix:
```python
{
  "previous_scan_id": str,
  "previous_findings_count": int,
  "previous_failed_tests_count": int,
  "new_findings_count": int,
  "fixed_findings": [...],   # were failing, now passing
  "persistent_findings": [...],  # still failing
  "new_issues": [...],       # new issues found
  "overall_status": "improved" | "regressed" | "stable"
}
```

### Scan Comparison Logic
When `/api/scans/compare` is called with `scan_a_id` and `scan_b_id`:
1. Load both reports
2. Compare `security_findings` arrays by (endpoint, method, vulnerability) key
3. Categorize each finding from scan_a:
   - **resolved**: in scan_a but NOT in scan_b
   - **persistent**: in both scan_a and scan_b with same or worse severity
   - **worsened**: severity increased
   - **new**: in scan_b but NOT in scan_a
4. Compare `security_score` numeric values
5. Compare `summary` counts (critical, high, medium, low)
6. Return structured comparison object

Comparison output:
```python
{
  "scan_a": { "id": str, "created_at": str, "overall_risk_score": str },
  "scan_b": { "id": str, "created_at": str, "overall_risk_score": str },
  "summary": {
    "findings_resolved": int,
    "findings_new": int,
    "findings_worsened": int,
    "score_improvement": float,   # positive = improved
    "tests_passed_now": int,
    "tests_failed_now": int
  },
  "resolved_findings": [...],
  "persistent_findings": [...],
  "worsened_findings": [...],
  "new_findings": [...]
}
```

---

## PART 8: REPORT OBJECT STRUCTURE (v3)

```python
report: {
  summary: {
    critical_risks: int,
    high_risks: int,
    medium_risks: int,
    low_risks: int,
    total_security_findings: int,
    total_tests_run: int,
    failed_tests: int,
    passed_tests: int,
    connection_errors: int,
    deployment_status: str,
    deployment_security_score: str,
    overall_risk_score: str,
    api_was_reachable: bool,
    deep_scan_performed: bool,
    scan_mode: str,           # NEW: "full" | "verify_fix" | "comparison_base"
    scan_id: str,
    created_at: str,
    previous_scan_id: str | None,  # NEW: for verify_fix comparisons
    llm_generated_tests_run: int,  # NEW
    auth_used: bool           # NEW
  },
  planner_assessment: dict,
  security_findings: [
    {
      endpoint: str,
      method: str,
      vulnerability: str,
      owasp_category: str,    # e.g. "OWASP API5:2023"
      severity: str,
      confidence: str,
      description: str,
      evidence: str,
      exploit_scenario: str,
      remediation: str,
      exploit_poc: str | None,  # from deep scan
      confirmed: bool         # correlated with test failure
    }
  ],
  api_test_results: [
    {
      endpoint: str,
      method: str,
      tests: [
        {
          test_type: str,
          passed: bool,
          connection_error: bool,
          auth_used: bool,
          status_code: int | None,
          response_time_ms: float | None,
          note: str | None,
          assertion_matched: bool | None
        }
      ]
    }
  ],
  deployment: dict,
  synthesis: dict,
  executive_summary: str,
  remediation_roadmap: dict,
  security_score: float,
  recommendations: list,
  llm_generated_test_cases: list | None  # NEW: what LLM generated
}
```

### PDF Export
- Use ReportLab to generate a PDF report
- Structure: Cover page (API title, scan date, risk score), Executive Summary, Security Findings (sorted by severity), Test Results, Deployment Analysis, Remediation Roadmap
- Footer: "Generated by API Sentinel v3"
- Endpoint: `GET /api/scans/{id}/report/export/pdf`

### JSON Export
- Same structure as report object, wrapped with metadata
- Endpoint: `GET /api/scans/{id}/report/export/json`

---

## PART 9: SCHEDULED SCANS + ALERTS (v3)

### Scheduler Implementation
- Use `APScheduler` (in-process, no Redis needed)
- Run as a background task within the FastAPI app
- On startup: load all `scheduled_scans` where `enabled=1` and `next_run_at <= now`, run them
- Each scheduled scan runs the full agent pipeline (or verify-fix if previous scan exists)
- After scan completes:
  - Update `last_run_at` and compute `next_run_at`
  - If `alert_on_new_findings=1`: compare with last scan, if new critical/high → trigger webhook
  - Trigger associated webhooks for `scan.completed` event

### Alert Logic
After scheduled scan completes:
1. Load previous scan for same schedule
2. Compare: `new_critical = current.critical - previous.critical`
3. If `new_critical > 0` AND `alert_on_new_findings=1`:
   - Send webhook to all webhooks associated with this user/schedule
   - Payload: `{ "event": "scan.new_critical", "scan_id": str, "new_critical_count": int, "risk_score": str }`

### Webhook Delivery
- HTTP POST to `webhook.target_url`
- Headers: `Content-Type: application/json`, `X-Sentinel-Signature: <HMAC-SHA256(secret, payload)>`
- Body: JSON with event type, scan_id, timestamp, and event-specific data
- Timeout: 10 seconds per webhook
- On failure: log error, do not retry (fire-and-forget)

---

## PART 10: CI/CD WEBHOOK INTEGRATION (v3)

### Webhook Registration
- Users register webhooks via `POST /api/webhooks`
- Specify: `target_url`, `secret` (for HMAC), `event_types`
- Supported event types:
  - `scan.completed`: any scan finishes
  - `scan.failed`: scan errored
  - `scan.new_critical`: new critical severity found
  - `scheduled.scan.run`: a scheduled scan triggered

### Receiving Webhooks (Inbound)
- Add endpoint `POST /api/webhooks/receive` — for external CI/CD systems to notify API Sentinel of deployments
- On receiving a webhook:
  - Verify HMAC signature if secret is configured
  - Look up the registered schedule by `webhook_id` in payload
  - Trigger that schedule immediately
  - Return 202 Accepted

### Outbound Webhook Payload Examples

**scan.completed:**
```json
{
  "event": "scan.completed",
  "scan_id": "abc123",
  "user_id": "user456",
  "timestamp": "2026-03-24T10:00:00Z",
  "data": {
    "api_title": "My API",
    "overall_risk_score": "7.5/10 — HIGH RISK",
    "critical_risks": 2,
    "high_risks": 4,
    "report_url": "http://localhost:8000/api/scans/abc123/report"
  }
}
```

**scan.new_critical:**
```json
{
  "event": "scan.new_critical",
  "scan_id": "abc123",
  "user_id": "user456",
  "timestamp": "2026-03-24T10:00:00Z",
  "data": {
    "api_title": "My API",
    "new_critical_count": 1,
    "new_high_count": 2,
    "current_risk_score": "8.5/10",
    "report_url": "http://localhost:8000/api/scans/abc123/report"
  }
}
```

---

## PART 11: YAML SPEC SUPPORT (v3)

### Current State
The `upload-file` endpoint already handles YAML (line 117 in endpoints.py: `spec = yaml.safe_load(content)`). However, the `SpecParser.parse_spec()` method does NOT call `yaml.safe_load()` — it only parses the already-parsed Python dict. This means:
- JSON upload: works
- JSON file upload: works
- YAML file upload: works (yaml.safe_load done in endpoint)
- **YAML URL-based spec discovery**: NOT tested

### v3 Fix: Make SpecParser YAML-aware
`SpecParser` should accept both dict and also handle YAML string input:
```python
def parse_spec(self, spec: Dict[str, Any] | str) -> Dict[str, Any]:
    if isinstance(spec, str):
        spec = yaml.safe_load(spec)
    ...
```

### Verify-fix mode uses YAML spec discovery
No special handling needed — YAML vs JSON handled at upload/discovery layer.

---

## PART 12: FRONTEND ARCHITECTURE (v3)

### Non-negotiable rules for App.js
- **Single file only** — never split into multiple files, never add a router
- **No new npm packages** — use only what's in package.json
- **Preserve all existing color tokens in object `C`** — do not rename or change values
- **Preserve existing component names** — Pill, StatCard, Btn, Input, LoginScreen, HistorySidebar, SecurityTable, TestResults, ReportView, AgentProgress

### New state variables for v3
```javascript
const [user, setUser] = useState(null);           // NEW: logged-in user
const [token, setToken] = useState(null);          // NEW: JWT token
const [schedules, setSchedules] = useState([]);    // NEW: scheduled scans
const [webhooks, setWebhooks] = useState([]);      // NEW: webhooks
const [scanHistory, setScanHistory] = useState([]); // per-user history
const [activeTab2, setActiveTab2] = useState("summary"); // NEW: second-level tab
const [compareMode, setCompareMode] = useState(false); // NEW
const [comparisonResult, setComparisonResult] = useState(null); // NEW
```

### New components to add (in App.js)
**`LoginScreen({ onLogin })`**
- Replace current auth bypass with real login/register form
- Fields: email, password
- On success: store token in state, call onLogin(token)
- Show "Register" tab alongside "Login"

**`ScheduleManager({ schedules, onCreate, onDelete, onRunNow })`**
- List of user's scheduled scans with interval, last run, next run, enabled toggle
- "Add Schedule" button → modal with: name, spec selection, interval (hours), alert toggle
- Trigger immediately button per row

**`WebhookManager({ webhooks, onCreate, onDelete, onTest })`**
- List of registered webhooks
- "Add Webhook" → modal: name, target URL, event types checkboxes
- Test button → sends test payload

**`ScanComparison({ scanA, scanB, result })`**
- Side-by-side diff view of two scans
- Columns: Finding | Scan A Severity | Scan B Severity | Change
- Color coding: green (resolved), red (new/worsened), yellow (persistent)
- Score comparison card

**`VerifyFixView({ previousScan, result })`**
- Shows what was fixed vs what persists
- Before/after cards per finding

**`ExportMenu({ scanId })`**
- Dropdown/button group: "Export JSON" | "Export PDF"
- Calls respective endpoints

### New UI panels
**Auth header**: Show user email + logout button in top-right corner when logged in. Show login button when not.

**Schedule column in HistorySidebar**: Add "Schedule" icon button next to scan history items.

### Updated tabs in ReportView
Existing tabs: Summary, Security, API Tests, Deployment, AI Analysis, Planner, Roadmap
**Add:**
- **"Compare" tab**: Shows comparison with previous scan of same spec (if available)
- **"Export" tab**: PDF/JSON download buttons

### Updated runScan function for auth
```javascript
async function runScan(specId, scanMode = "full", previousScanId = null) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  let endpoint = `/api/run/${specId}/stream`;
  if (scanMode === "verify_fix") {
    endpoint = `/api/run/${specId}/verify-fix/stream`;
  }

  const response = await fetch(`${API_URL}${endpoint}`, {
    method: "POST",
    headers,
    body: JSON.stringify({ previous_scan_id: previousScanId })
  });
  // ... rest of SSE handling
}
```

### Updated API helper with auth
```javascript
const API_URL = process.env.REACT_APP_API_URL || "http://localhost:8000";

async function apiFetch(path, options = {}) {
  const headers = { ...options.headers };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const response = await fetch(`${API_URL}${path}`, { ...options, headers });
  if (response.status === 401) {
    setUser(null);
    setToken(null);
    throw new Error("Unauthorized");
  }
  return response;
}
```

---

## PART 13: ENVIRONMENT VARIABLES (v3 — complete list)

| Variable | Default | Purpose |
|---|---|---|
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server URL |
| `OLLAMA_DEFAULT_MODEL` | `llama3.1:8b` | Fallback model |
| `PLANNER_MODEL` | `llama3.1:8b` | Planner Agent model |
| `SECURITY_MODEL` | `llama3.1:8b` | Security Agent model |
| `DEEP_SCAN_MODEL` | `llama3.1:8b` | Deep Scan Agent model |
| `SYNTHESIS_MODEL` | `llama3.1:8b` | Synthesis Agent model |
| `TEST_GENERATION_MODEL` | `llama3.1:8b` | Test Generation Agent model |
| `OLLAMA_TIMEOUT` | `60` | LLM call timeout in seconds |
| `SENTINEL_API_KEY` | `` | Legacy auth key (super-user mode) |
| `JWT_SECRET` | `dev-secret-change-in-prod` | JWT signing secret |
| `JWT_EXPIRY_DAYS` | `7` | JWT token lifetime |
| `ALLOWED_ORIGINS` | `*` | CORS allowed origins |
| `SENTINEL_DB_PATH` | `/data/sentinel.db` | SQLite path |
| `REACT_APP_API_URL` | `http://localhost:8000` | Backend URL |
| `REACT_APP_APP_NAME` | `API Sentinel` | App name shown in UI |

---

## PART 14: EXECUTION ORDER FOR CLAUDE CODE

Work through in this exact order. Complete each before moving to next.

```
Step 1: Update requirements.txt
  - Remove: anthropic
  - Add: PyJWT, passlib[bcrypt], apscheduler, reportlab

Step 2: Update database.py
  - Add users table
  - Add scheduled_scans table
  - Add webhooks table
  - Add scan_comparison table
  - Add user/auth helper functions (create_user, get_user_by_email, hash_password, verify_password)
  - Add schedule helper functions
  - Add webhook helper functions
  - Add comparison helper functions
  - Add user_id to scans table INSERT (from request state)

Step 3: Update .env.example
  - Remove ANTHROPIC_API_KEY
  - Add JWT_SECRET, JWT_EXPIRY_DAYS
  - Add all OLLAMA_* vars including TEST_GENERATION_MODEL

Step 4: Auth endpoints
  - POST /api/auth/register
  - POST /api/auth/login (returns JWT)
  - GET /api/auth/me
  - Add get_current_user dependency for JWT verification
  - Update all existing endpoints to use get_current_user (for user isolation)

Step 5: Update spec_parser.py
  - Handle YAML string input in parse_spec()

Step 6: Create test_generation_agent.py (new file)
  - Ollama call to generate test cases
  - Full fallback to empty test_cases list

Step 7: Update security_agent.py
  - Add OWASP API5 (BFLA) detection
  - Add OWASP API6 (Resource Consumption) detection
  - Add OWASP API7 (SSRF) detection
  - Add OWASP API8 (Security Misconfiguration) cross-reference
  - Add OWASP API9 (Improper Inventory) detection
  - Add OWASP API10 (Unsafe Consumption) detection
  - Update all finding.vulnerability field names consistently

Step 8: Update api_testing_agent.py
  - Add auth config handling (Step 0)
  - Add auth_aware_test test type (Step 2)
  - Add llm_generated_test execution (Step 3)
  - Add auth_used field to test results
  - Add llm_generated_tests_run counter

Step 9: Update orchestrator.py
  - Add test_generation_result to ScanState
  - Add auth_config to ScanState
  - Add scan_mode to ScanState
  - Add previous_scan_id to ScanState
  - Add test_generation_node between planner and security
  - Pass test_generation_result to api_testing_node
  - Handle verify_fix scan_mode (skip certain agents)

Step 10: Update report_generator.py
  - Add llm_generated_test_cases to report
  - Add scan_mode to summary
  - Add previous_scan_id to summary
  - Add llm_generated_tests_run to summary
  - Add auth_used to summary

Step 11: Add auth-aware endpoints
  - GET /api/users/scans (per-user scan list)
  - DELETE /api/users/scans/{id} (user isolation)
  - Update /api/scans to require auth (or filter by user)

Step 12: Add comparison endpoints
  - POST /api/scans/compare
  - GET /api/scans/compare/{comparison_id}
  - GET /api/scans/{id}/history

Step 13: Add verify-fix endpoints
  - POST /api/run/{id}/verify-fix (blocking)
  - POST /api/run/{id}/verify-fix/stream (SSE)
  - Implement verify-fix logic

Step 14: Add scheduled scan endpoints
  - POST /api/schedules
  - GET /api/schedules
  - GET /api/schedules/{id}
  - PUT /api/schedules/{id}
  - DELETE /api/schedules/{id}
  - POST /api/schedules/{id}/run

Step 15: Add webhook endpoints
  - POST /api/webhooks
  - GET /api/webhooks
  - DELETE /api/webhooks/{id}
  - POST /api/webhooks/test
  - POST /api/webhooks/receive (inbound)

Step 16: Add report export endpoints
  - GET /api/scans/{id}/report/export/json
  - GET /api/scans/{id}/report/export/pdf (use ReportLab)

Step 17: Implement APScheduler integration
  - On app startup: init_db() then load and register all enabled scheduled scans
  - Implement job function that runs full scan pipeline + alert logic
  - Store scheduler instance in app state

Step 18: Update App.js frontend
  - Add LoginScreen component (replace dev auth)
  - Add user state, token state
  - Update apiFetch to include Authorization header
  - Add AgentProgress component (already in v2)
  - Add ScheduleManager component
  - Add WebhookManager component
  - Add ScanComparison component
  - Add VerifyFixView component
  - Add ExportMenu component
  - Update runScan for verify_fix mode
  - Update HistorySidebar to show per-user scans
  - Add Compare tab, Export tab to ReportView
  - Add Critical card + Security Score card (already in v2)
  - Add auth header in top-right corner

Step 19: Update docker-compose.yml
  - Replace ANTHROPIC_API_KEY with JWT_SECRET
  - Add OLLAMA_* vars
  - Add TEST_GENERATION_MODEL
```

---

## PART 15: CRITICAL INVARIANTS (v3)

These must remain true at all times. Never violate these:

1. **System works with no Ollama** — every LLM call must have a rule-based fallback. A scan with no Ollama must complete successfully.
2. **Connection errors are never security failures** — if the target API is unreachable, tests are "skipped", not "failed".
3. **Never crash on LLM response** — always try/except, always strip markdown fences, always have fallback.
4. **Never modify the scans table schema** — only add new columns/tables. Existing rows must remain valid.
5. **App.js stays one file** — no splitting, no router.
6. **All design tokens in `C` object preserved** — colors and fonts unchanged.
7. **All existing API routes preserved** — `/api/run/{id}` blocking endpoint must still work.
8. **Backward compatibility** — `SecurityTable` must handle both `f.risk_type` (v1) and `f.vulnerability` (v2/v3) field names.
9. **Per-user scan isolation** — users can NEVER see or modify other users' scans. Super-user (API key auth) bypasses this.
10. **JWT secret must be configurable** — dev default is not suitable for production.

---

## PART 16: TESTING CHECKLIST (v3)

Run these tests to verify the implementation:

**Backend (no Ollama, no auth):**
- Upload sample-api/openapi.json → should parse 3 endpoints
- Run scan → should complete using rule-based fallback, report should generate
- Verify `llm_used: false` in results

**Backend (with Ollama, no auth):**
- Pull model: `ollama pull llama3.1:8b`
- Run scan → planner should return structured plan
- Security findings should have all 10 OWASP categories
- Verify `llm_used: true` in results

**Auth flow:**
- POST /api/auth/register → returns 200, stores user
- POST /api/auth/login → returns JWT token
- GET /api/auth/me → returns user profile with valid token
- GET /api/users/scans → returns only current user's scans
- Try accessing another user's scan → returns 403

**YAML support:**
- Upload .yaml spec file → parses correctly
- Upload .yml spec file → parses correctly

**Verify-fix mode:**
- Run a scan that has failed tests
- POST /api/run/{id}/verify-fix → returns targeted results
- Verify only failed endpoints are re-tested
- Verify fixed findings marked as resolved

**Scan comparison:**
- Run same spec twice
- POST /api/scans/compare → returns diff
- Verify resolved/new/worsened categorization

**Scheduled scans:**
- Create schedule → appears in list
- Trigger immediately → scan runs
- Verify next_run_at updates after run

**Webhooks:**
- Create webhook with secret
- POST /api/webhooks/test → sends signed payload
- Verify HMAC signature matches

**Report export:**
- GET /api/scans/{id}/report/export/json → valid JSON downloads
- GET /api/scans/{id}/report/export/pdf → PDF downloads and opens correctly

**Auth-aware API testing:**
- Create scan with bearer token auth
- API Testing Agent sends Authorization header
- Detect auth bypass when endpoint shouldn't allow it

**LLM-generated test cases:**
- With Ollama running, verify test_generation agent returns test_cases
- Verify those test_cases are executed in api_testing phase
- Verify llm_generated_tests_run counter in report

**Sample API testing (with auth):**
- Run `sample-api/main.py` on port 8001 with valid auth
- Run full scan with base_url set to `http://localhost:8001`
- API Testing Agent should detect BOLA on `/users/{user_id}`
- Should detect auth issues on protected endpoints
