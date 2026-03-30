# CURRENT_STATE.md
## API Sentinel — Exact Current Codebase Documentation
**Read this to understand what exists RIGHT NOW before making any changes.**

---

## REPOSITORY STRUCTURE (current)

```
api-sentinel/
├── frontend/
│   ├── src/
│   │   ├── App.js              ← Entire React app (~703 lines, single file)
│   │   ├── App.css             ← Default CRA styles (unused, app uses inline styles)
│   │   ├── App.test.js         ← BROKEN — still has default CRA test, will fail
│   │   ├── index.js            ← React root, renders <App /> in StrictMode
│   │   ├── index.css           ← Body/code font resets only
│   │   ├── setupTests.js       ← jest-dom import
│   │   └── reportWebVitals.js  ← CRA perf utility
│   ├── public/
│   │   ├── index.html          ← Title still says "React App" (not updated)
│   │   └── manifest.json       ← Still says "Create React App Sample"
│   ├── .env.development        ← REACT_APP_API_URL=http://localhost:8000
│   ├── .env.production         ← REACT_APP_API_URL=https://your-backend-url-here.com (placeholder)
│   ├── nginx.conf              ← Serves SPA, caches static assets, gzip enabled
│   ├── Dockerfile              ← Multi-stage: node:20-alpine build → nginx:alpine serve
│   └── package.json            ← React 19, no extra deps beyond CRA defaults
│
├── backend/
│   └── app/
│       ├── __init__.py         ← Empty
│       ├── main.py             ← FastAPI app init
│       ├── database.py         ← SQLite CRUD layer
│       ├── orchestrator.py     ← LangGraph StateGraph
│       ├── agents/
│       │   ├── security_agent.py       ← Rule-based if/else only
│       │   ├── api_testing_agent.py    ← Live HTTP tests + static fuzz
│       │   └── deployment_agent.py     ← Health check only
│       ├── services/
│       │   └── spec_parser.py          ← OpenAPI parser
│       ├── api/
│       │   └── endpoints.py            ← All FastAPI routes
│       ├── reporting/
│       │   └── report_generator.py     ← Report assembler
│       └── schemas/
│           └── api_spec.py             ← Pydantic models
│
├── sample-api/
│   ├── main.py                 ← Intentionally vulnerable FastAPI app (port 8001)
│   └── openapi.json            ← Spec for sample API (3 endpoints)
│
├── .env.example                ← Template with SENTINEL_API_KEY, ANTHROPIC_API_KEY
├── docker-compose.yml          ← backend:8000, frontend:3000→80
└── README.md                   ← Architecture diagram + feature list
```

---

## BACKEND — FILE BY FILE

### `backend/app/main.py`
- Creates FastAPI app titled "API Sentinel", version "0.2.0"
- Reads `ALLOWED_ORIGINS` env var (default `*`), applies CORSMiddleware
- Includes `router` from `endpoints.py`
- On startup: calls `init_db()` to create SQLite tables
- Routes defined here: `GET /` returns version info, `GET /health` returns `{"status": "healthy"}`
- Nothing else — all API routes are in `endpoints.py`

---

### `backend/app/database.py`
SQLite persistence. Uses Python's built-in `sqlite3`. No ORM.

**DB path**: reads `SENTINEL_DB_PATH` env var, defaults to `sentinel.db` next to the backend directory.

**`init_db()`**: Creates one table if not exists:
```
scans table:
  id             TEXT PRIMARY KEY  (UUID)
  name           TEXT NOT NULL
  created_at     TEXT NOT NULL     (ISO format)
  status         TEXT NOT NULL     DEFAULT 'parsed'
  api_title      TEXT
  api_version    TEXT
  endpoint_count INTEGER           DEFAULT 0
  original_spec  TEXT              (JSON blob)
  parsed_data    TEXT              (JSON blob)
  report         TEXT              (JSON blob, NULL until scan runs)

Index: idx_scans_created ON scans(created_at DESC)
```

**Functions**:
- `get_conn()` → sqlite3.Connection with `row_factory = sqlite3.Row`
- `save_scan(name, original_spec, parsed_data)` → inserts row, returns UUID string
- `get_scan(scan_id)` → returns dict or None, deserializes JSON blobs
- `save_report(scan_id, report)` → UPDATE sets report JSON + status='completed'
- `list_scans(limit=50)` → SELECT without JSON blobs, ordered by created_at DESC
- `delete_scan(scan_id)` → DELETE, returns bool
- `_deserialise(row)` → internal, parses JSON fields: original_spec, parsed_data, report

---

### `backend/app/services/spec_parser.py`
**`SpecParser` class**:

`parse_spec(spec)`:
- Validates: raises ValueError if neither "openapi" nor "swagger" key present
- Iterates `spec["paths"]`, for each path + method combo:
  - Only processes: GET, POST, PUT, DELETE, PATCH
  - Extracts: path, method (uppercased), summary, parameters, request_body (from requestBody), responses (list of status code keys), is_id_based (bool: `{` in path)
- Returns dict: `{ endpoints: [...], total_endpoints: int, title: str, version: str }`

`store_spec(name, spec, parsed_data)` → calls `save_scan()`, returns scan_id

`get_spec(spec_id)` → calls `get_scan()`, returns full scan dict or None

---

### `backend/app/agents/security_agent.py`
**`SecurityAgent` class** — pure rule-based, NO LLM.

`run(parsed_data)`:
- Iterates every endpoint
- Rule 1 — BOLA: if `{` and `}` in path → HIGH finding
- Rule 2 — Broken Auth: if method in POST/PUT/PATCH/DELETE → HIGH finding
- Rule 3 — Excessive Data Exposure: if method==GET AND path contains any of `["users","accounts","orders","profiles"]` → MEDIUM finding
- Rule 4 — Rate Limiting: if path contains any of `["login","auth","token","search","password"]` → MEDIUM finding

Finding structure:
```python
{
  "endpoint": path,
  "risk_type": "...",    # ← field is risk_type NOT vulnerability
  "severity": "HIGH" | "MEDIUM",
  "confidence": "POTENTIAL",   # always POTENTIAL
  "description": "..."
}
```

Returns: `{ agent, status, total_findings, findings }`

**Known issues**: No deduplication. Every endpoint with `{` gets BOLA. Every POST gets auth flag. All confidence is "POTENTIAL". No LLM reasoning.

---

### `backend/app/agents/api_testing_agent.py`
**`APITestingAgent` class**

`__init__(base_url=None)`:
- `self.base_url` = provided or `"http://localhost:8001"` (hardcoded default)
- `self.fuzz_payloads` = static list of 12 payloads (SQL injection, XSS, path traversal, SSTI, null, -1, 0)

`fuzz_test(path, method)`:
- Finds `{param}` patterns in path via regex
- For each payload: replaces all params with payload string, makes request
- If status >= 500 → flags as possible_vulnerability
- **BUG**: if request throws exception → sets `possible_vulnerability: True` (connection error = vulnerability)

`run(parsed_data)`:
- Picks up `base_url` from parsed_data if present
- For each endpoint runs 5 tests:
  1. **valid_request**: GET/method to real URL, pass if status < 400
  2. **invalid_parameter**: replaces `{id}` with "abc", pass if status >= 400
  3. **nonexistent_resource**: replaces `{id}` with "999999", pass if status == 404
  4. **wrong_method**: sends POST if GET (or GET if POST), pass if 400 or 405
  5. **dynamic_fuzz_testing**: calls fuzz_test(), counts vulnerable payloads
- **BUG**: connection errors recorded as `passed: False` with no distinction from real failures
- **BUG**: fuzz exception sets possible_vulnerability=True

Endpoint result structure:
```python
{
  "endpoint": path,
  "method": method,
  "base_url": self.base_url,
  "tests": [ { test, status_code, passed, error? } ]
}
```
Returns: `{ agent, status, base_url_tested, results }`

---

### `backend/app/agents/deployment_agent.py`
**`DeploymentAgent` class** — minimal.

`run(base_url="http://localhost:8000")`:
- Makes single `GET {base_url}/health` request
- Returns: `{ agent, status: "healthy"|"unhealthy"|"unreachable", status_code }`
- Only checks: HTTP status == 200 → healthy
- No latency, no headers, no CORS, no HTTPS check

---

### `backend/app/reporting/report_generator.py`
**`ReportGenerator` class**

`generate(agent_output)`:
- Reads: `agent_output["security"]`, `agent_output["api_testing"]`, `agent_output["deployment"]`
- Counts HIGH severity findings only (ignores MEDIUM/LOW for `high_risks`)
- Flattens nested tests arrays to count failures
- Returns report dict:
```python
{
  "summary": {
    "high_risks": int,
    "total_security_findings": int,
    "total_tests_run": int,
    "failed_tests": int,       # BUG: includes connection errors
    "passed_tests": int,
    "deployment_status": str
  },
  "security_findings": [...],
  "api_test_results": [...],
  "deployment": {...},
  "recommendations": [...]     # deduplicated via set()
}
```

`_generate_recommendations(findings, deployment)`:
- Checks `f["risk_type"]` field (exact string match) for 4 known types
- If deployment not healthy → adds recommendation
- Returns `list(set(recs))` — deduplication but loses ordering

---

### `backend/app/orchestrator.py`
**LangGraph StateGraph** — linear pipeline, no conditional edges.

**`ScanState` TypedDict**:
```python
{
  parsed_data: dict,
  security_result: dict,
  api_test_result: dict,
  deployment_result: dict,
  llm_analysis: str,      # narrative string, not structured
  final_report: dict
}
```

**Graph nodes** (in execution order):
1. `security_node` → calls `SecurityAgent().run(parsed_data)`
2. `api_testing_node` → calls `APITestingAgent().run(parsed_data)`
3. `deployment_node` → calls `DeploymentAgent().run(base_url)`, reads base_url from parsed_data
4. `llm_analysis_node` → calls Anthropic API if `ANTHROPIC_API_KEY` set, else returns skip message
5. `report_node` → calls `ReportGenerator().generate()`, attaches llm_analysis string to report

**Graph topology**: `security → api_testing → deployment → llm_analysis → report → END`
No conditional edges. No branching. Strictly linear.

**LLM node** (current):
- Checks `ANTHROPIC_API_KEY` env var
- Uses `anthropic` library, model `"claude-sonnet-4-20250514"`
- Sends all findings to Claude, asks for executive summary + top 3 findings + remediation
- Returns plain text narrative string
- On failure: returns error string, scan continues

**`Orchestrator` class**:
- `run_all(parsed_data)` → invokes graph, returns `final_state["final_report"]`
- Module-level `_graph` singleton compiled once

**Current issue**: `anthropic` is in requirements.txt but we are moving to Ollama. The LLM node needs full replacement.

---

### `backend/app/api/endpoints.py`
All FastAPI routes. Uses module-level `spec_parser = SpecParser()` and `orchestrator = Orchestrator()` singletons.

**Auth system**:
- Reads `SENTINEL_API_KEY` env var at module load
- `require_auth` dependency: if key set, checks `X-API-Key` header; if blank, skips (dev mode)
- `AuthDep = Depends(require_auth)` applied to all routes

**Routes**:

| Method | Path | Handler | What it does |
|---|---|---|---|
| GET | `/api/scans` | `get_scan_history` | Returns `list_scans(limit=100)` |
| GET | `/api/scans/{scan_id}/report` | `get_scan_report` | Returns `scan["report"]` or 404 |
| DELETE | `/api/scans/{scan_id}` | `remove_scan` | Calls `delete_scan()` |
| POST | `/api/specs/upload` | `upload_api_spec` | Parses JSON body spec, stores, returns APISpecResponse |
| POST | `/api/specs/upload-file` | `upload_spec_file` | Parses .json or .yaml file upload |
| GET | `/api/specs/{spec_id}` | `get_spec` | Returns `scan["parsed_data"]` |
| POST | `/api/run/{spec_id}` | `run_agents` | Loads scan, runs orchestrator, saves report |
| POST | `/api/scan-url` | `scan_api_url` | Discovers spec from URL, runs full scan |

**`discover_endpoints(base_url, auth_token)`**:
- Tries these paths in order: `/openapi.json`, `/swagger.json`, `/openapi.yaml`, `/swagger.yaml`, `/api-docs`, `/v1/openapi.json`, `/v2/openapi.json`
- Parses JSON or YAML based on content-type
- Returns `(parsed_data, raw_spec, spec_url)` or raises 422

**`URLScanRequest` model**: `{ base_url: str, auth_token: str = "" }`

---

### `backend/app/schemas/api_spec.py`
Two Pydantic models:
- `APISpecUpload`: `{ spec: Dict[str,Any], name: str, description: str = "" }`
- `APISpecResponse`: `{ id: str, name: str, status: str, endpoints_count: int }`

---

### `backend/requirements.txt`
```
fastapi
uvicorn
requests
pyyaml
python-multipart
langgraph
anthropic          ← TO BE REPLACED with ollama/httpx calls
```

---

### `backend/test_agents.py`
Simple script (not pytest). Loads sample-api/openapi.json, runs SpecParser + Orchestrator, prints result. Run from `backend/` directory.

---

## FRONTEND — FILE BY FILE

### `frontend/src/App.js` — Full Component Map

**Top-level constants**:
- `BASE` = `process.env.REACT_APP_API_URL || "http://localhost:8000"`
- `APP_NAME` = `process.env.REACT_APP_APP_NAME || "API TESTING"`

**Design token object `C`** (all colors, do not change these):
```javascript
bg: "#080c14"         // page background
surface: "#0e1420"    // card/panel background
surfaceHigh: "#141c2e"// elevated surface
border: "#1a2540"     // default border color
borderHigh: "#243050" // elevated border
accent: "#00c8ff"     // cyan, primary accent
accentDim: "#00c8ff18"// transparent accent bg
accentBorder: "#00c8ff33"
green: "#00e5a0"      // success/pass
greenDim: "#00e5a012"
yellow: "#ffb800"     // warning/medium
yellowDim: "#ffb80012"
red: "#ff4560"        // error/high/critical
redDim: "#ff456012"
text: "#dde4f0"       // primary text
textMuted: "#4a5a7a"  // secondary text
textDim: "#8899bb"    // tertiary text
sidebar: "#090d18"    // sidebar background
```

**Font variables**:
- `mono` = `'IBM Plex Mono', 'Courier New', monospace`
- `sans` = `'DM Sans', system-ui, sans-serif`

**Helper functions**:
- `sev(s)` → color for severity string (HIGH=red, MEDIUM=yellow, else green)
- `sevBg(s)` → dim background color for severity
- `fmt(iso)` → formats ISO date string to locale string

---

**`useApi()` hook**:
- State: `apiKey` (initialized from `sessionStorage.getItem("sentinel_key")`)
- `apiFetch(path, opts)`: adds Content-Type + X-API-Key header, throws "AUTH_FAILED" on 401
- `apiUpload(path, formData)`: multipart upload with X-API-Key, no Content-Type override
- Returns: `{ apiKey, setApiKey, apiFetch, apiUpload }`

---

**UI Components** (all defined in App.js):

`Pill({ label, color })` — small monospace badge with color background/border

`StatCard({ label, value, color })` — metric card with large number + label, left colored border

`Btn({ onClick, children, variant, disabled, small })`:
- variants: `primary` (cyan bg, black text), `ghost` (transparent, cyan border), `danger` (red), `subtle` (surfaceHigh)

`Input({ value, onChange, placeholder, type, style })` — styled text input

`LoginScreen({ onAuth })`:
- Shows only when backend returns 401 and no key in sessionStorage
- Has password input for API key
- Calls `GET /health` with the key to verify
- On success: saves to sessionStorage, calls `onAuth(key)`

`HistorySidebar({ apiFetch, onSelect, activeId })`:
- Fixed 260px wide left panel
- Loads from `GET /api/scans` on mount
- Each scan item shows: api_title or name, endpoint_count, created_at, status pill
- Click → calls `onSelect(scan)`
- × button → calls `DELETE /api/scans/{id}`, removes from local state
- ↻ button → refreshes list
- Active scan highlighted with accent left border + dim background

`SecurityTable({ findings })`:
- Renders table with columns: Endpoint, Risk Type, Severity, Details
- Click row → toggles expanded description panel
- Uses `f.risk_type` field (current v1 field name)
- Severity badge uses `sev()` / `sevBg()` helpers

`TestResults({ results })`:
- Accordion per endpoint, shows `{ep.method} {ep.endpoint}`
- Header shows pass✓ / fail✗ counts
- For `dynamic_fuzz_testing` test type: shows "X / Y flagged" + red boxes for vulnerable payloads
- For other tests: shows test name, HTTP status, error snippet, PASS/FAIL pill
- **No distinction between connection errors and real failures**

`ReportView({ report })`:
- Renders summary stat cards: High Risks, Total Findings, Tests Run, Failed, Passed, Deployment status with glowing dot
- Four tabs: Security, API Tests, Recommendations, AI Analysis
- Security tab → `<SecurityTable findings={report.security_findings} />`
- API Tests tab → `<TestResults results={report.api_test_results} />`
- Recommendations tab → yellow-bordered cards from `report.recommendations` array
- AI Analysis tab → shows `report.llm_analysis` as `<pre>` block, or message to set ANTHROPIC_API_KEY

---

**`App()` main component state**:
```javascript
authChecked    // bool — has /health been called yet
needsAuth      // bool — backend returned 401
specText       // string — pasted JSON content
specId         // string|null — UUID of uploaded spec
file           // File|null — selected file for upload
apiUrl         // string — URL for URL scan
report         // object|null — report from backend
activeScanId   // string|null — ID of scan being viewed
loading        // bool — any operation in progress
error          // string — error message to show
sidebarKey     // int — incremented to force sidebar remount/refresh
```

**`App()` functions**:
- `uploadSpec()` → POST /api/specs/upload with JSON body
- `uploadFile()` → POST /api/specs/upload-file with FormData
- `runScan()` → POST /api/run/{specId}, sets report from `data.result`
- `scanUrl()` → POST /api/scan-url, sets report from `data.result`
- `loadHistoryScan(scan)` → if completed: GET /api/scans/{id}/report, set report; if not: set specId only
- `wrap(fn)` → sets loading, clears error, runs fn, catches AUTH_FAILED → triggers login

**App layout**:
```
flex row, 100vh, overflow hidden
├── HistorySidebar (260px fixed)
└── flex column (flex:1)
    ├── Topbar (52px fixed, app name + loading indicator + sign out)
    └── Scrollable content area (flex:1, padding 24px 28px)
        ├── Error banner (if error)
        ├── Input panels (3-column grid)
        ├── Run scan banner (if specId && !report)
        ├── ReportView (if report)
        └── Empty state (if !report && !specId)
```

**Global styles** (injected via `<style>` tag in App):
- Imports IBM Plex Mono + DM Sans from Google Fonts
- `* { box-sizing, margin: 0, padding: 0 }`
- Custom scrollbar (5px, C.border thumb)
- `code` element: accentDim bg, accent color, mono font

---

## SAMPLE API (`sample-api/main.py`)

FastAPI app for testing. Run on port 8001.

In-memory data:
- `users`: {1: Alice (user), 2: Bob (admin)}
- `products`: {1: Laptop $999.99, 2: Mouse $29.99}
- `orders`: {1: user_id=1 product=1, 2: user_id=2 product=2}

Endpoints:
```
GET  /                       → version message
GET  /users                  → all users
GET  /users/{user_id}        → single user — INTENTIONAL BOLA (no auth)
POST /users                  → create user
GET  /products               → all products
GET  /users/{user_id}/orders → user's orders — INTENTIONAL missing auth
POST /search                 → search products by query param — COMMENT says SQL injection possible
```

OpenAPI spec at `sample-api/openapi.json` only defines 3 paths: `/users` GET, `/users/{user_id}` GET, `/users/{user_id}/orders` GET. Missing `/products`, `/search`, `POST /users`.

---

## DOCKER / INFRA

**docker-compose.yml**:
- `backend` service: builds from `./backend`, port 8000:8000, env from .env file, SQLite in `sentinel_data` named volume at `/data`
- `frontend` service: builds from `./frontend`, port 3000:80, `REACT_APP_API_URL` passed as build arg, depends_on backend

**backend/Dockerfile**: python:3.11-slim, installs requirements, sets SENTINEL_DB_PATH=/data/sentinel.db, runs uvicorn on 0.0.0.0:8000

**frontend/Dockerfile**: node:20-alpine build stage → nginx:alpine serve stage. REACT_APP_API_URL baked in at build time via ARG/ENV.

**frontend/nginx.conf**: listens 80, try_files for SPA routing, 1y cache on static assets, gzip enabled.

---

## KNOWN BUGS IN CURRENT CODE

1. **`App.test.js`** still has default CRA test looking for "learn react" text — will fail if tests run
2. **`fuzz_test()` in api_testing_agent.py**: connection exceptions set `possible_vulnerability: True` — wrong
3. **`api_testing_agent.py`**: all test failures look the same whether connection error or real failure — no distinction
4. **`security_agent.py`**: `confidence` is always "POTENTIAL" regardless of actual analysis
5. **`report_generator.py`**: `_generate_recommendations` matches on `f["risk_type"]` exact string — will break if field name changes
6. **`orchestrator.py`**: references `anthropic` library which is being replaced with Ollama
7. **`report_generator.py`**: counts connection error failures as `failed_tests` in summary
8. **`frontend/public/index.html`**: title still says "React App"
9. **`frontend/public/manifest.json`**: still says "Create React App Sample"
10. **`requirements.txt`**: has `anthropic` — needs replacing with `httpx` or `requests` for Ollama calls
11. **`ReportView`** AI Analysis tab says "Set ANTHROPIC_API_KEY" — message needs updating for Ollama

---

## WHAT DOES NOT EXIST YET (v2.0 additions)

These files/features do not exist and need to be created:
- `backend/app/agents/planner_agent.py` — does not exist
- Deep Scan Agent — does not exist
- Synthesis Agent — does not exist (synthesis logic is not in orchestrator)
- Streaming SSE endpoint `/api/run/{id}/stream` — does not exist
- `agent_logs` table in database — does not exist
- `GET /api/scans/{id}/agents` endpoint — does not exist
- `AgentProgress` React component — does not exist
- Planner tab in ReportView — does not exist
- Roadmap tab in ReportView — does not exist
- Ollama integration — does not exist anywhere
- Context-aware fuzzing (payload categories per endpoint) — does not exist
- Connectivity pre-check in api_testing_agent — does not exist
- Security headers check in deployment_agent — does not exist
