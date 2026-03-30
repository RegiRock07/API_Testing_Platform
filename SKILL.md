# SKILL.md
## API Sentinel — Implementation Skill File
**Claude Code: Read this file at the start of every session working on this project.**

---

## WHO YOU ARE IN THIS PROJECT

You are implementing API Sentinel v2.0 — an AI-powered API security testing platform. You are upgrading it from a rule-based system to a genuinely intelligent multi-agent platform that uses Ollama (local open-source LLMs) for reasoning at every step.

The codebase exists. You are modifying and extending it — not starting from scratch. Read CURRENT_STATE.md to understand exactly what exists before touching anything.

---

## THE SINGLE MOST IMPORTANT RULE

**Every LLM call must have a working fallback.**

If Ollama is not running, or the model is not pulled, or the JSON response is malformed — the scan must still complete successfully using the existing rule-based logic. A user without Ollama must get a useful (if less intelligent) report. Never let an LLM failure propagate as a scan failure.

---

## HOW TO CALL OLLAMA

Ollama runs locally. Use `requests` or `httpx` to call it — do not use any Ollama Python SDK.

```
POST {OLLAMA_BASE_URL}/api/chat
Body: {
  "model": "{model_name}",
  "messages": [
    {"role": "system", "content": "You are..."},
    {"role": "user", "content": "..."}
  ],
  "stream": false
}
Response: { "message": { "content": "..." } }
```

Always read `OLLAMA_BASE_URL` from env (default `http://localhost:11434`).
Always read model name from env var specific to that agent.
Always set a timeout — read from `OLLAMA_TIMEOUT` env (default 60).

---

## HOW TO WRITE LLM PROMPTS FOR OPEN-SOURCE MODELS

Open-source models need more explicit prompting. Follow this pattern every time:

**System message**: State the role clearly and completely.
```
You are an expert API security analyst performing a penetration test.
Your task is to analyze API endpoints for security vulnerabilities.
```

**User message structure**:
1. Context/data to analyze
2. Explicit instruction of what to output
3. Instruction to output ONLY JSON
4. Concrete example of the exact JSON schema expected
5. Reminder: no markdown, no explanation, just JSON

**Example prompt ending**:
```
Respond ONLY with a valid JSON object matching this exact structure:
{
  "risk_summary": "string",
  "auth_pattern_detected": "none|api_key|bearer|basic|oauth|unknown"
}
Do not include any text before or after the JSON. Do not use markdown code blocks.
```

---

## HOW TO PARSE LLM RESPONSES SAFELY

Always do this — never directly call `json.loads()` on raw LLM output:

```python
def parse_llm_json(raw_text: str, fallback=None):
    try:
        text = raw_text.strip()
        # Strip markdown code fences
        if text.startswith("```"):
            lines = text.split("\n")
            # Remove first line (```json or ```) and last line (```)
            text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        text = text.strip()
        return json.loads(text)
    except Exception as e:
        # Log the error, return fallback
        print(f"LLM JSON parse failed: {e}. Raw: {raw_text[:200]}")
        return fallback
```

---

## HOW TO STRUCTURE EVERY AGENT CLASS

Every agent follows this pattern:

```
class XxxAgent:

    def __init__(self):
        self.ollama_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self.model = os.getenv("XXX_MODEL", os.getenv("OLLAMA_DEFAULT_MODEL", "llama3.1:8b"))
        self.timeout = int(os.getenv("OLLAMA_TIMEOUT", "60"))

    def _call_llm(self, messages: list) -> str | None:
        """Call Ollama. Returns response text or None on failure."""
        try:
            response = requests.post(
                f"{self.ollama_url}/api/chat",
                json={"model": self.model, "messages": messages, "stream": False},
                timeout=self.timeout
            )
            response.raise_for_status()
            return response.json()["message"]["content"]
        except Exception as e:
            print(f"[{self.__class__.__name__}] Ollama call failed: {e}")
            return None

    def _fallback_logic(self, ...):
        """Original rule-based logic from v1. Used when LLM unavailable."""
        ...

    def run(self, parsed_data, planner_result=None):
        raw = self._call_llm([...])
        if raw is None:
            return self._fallback_logic(parsed_data)
        result = parse_llm_json(raw, fallback=None)
        if result is None:
            return self._fallback_logic(parsed_data)
        # Process LLM result...
        return { "agent": "xxx", "llm_used": True, ... }
```

---

## LANGGRAPH PATTERNS TO USE

### Adding a conditional edge
```python
def should_deep_scan(state: ScanState) -> str:
    security = state.get("security_result", {})
    if security.get("critical_count", 0) > 0 or security.get("high_count", 0) >= 3:
        return "deep_scan"
    return "synthesis"

graph.add_conditional_edges(
    "deployment",           # source node
    should_deep_scan,       # function that returns next node name as string
    {
        "deep_scan": "deep_scan",   # map return values to node names
        "synthesis": "synthesis"
    }
)
```

### Passing context between agents
Nodes receive the full state and return a new state dict. To pass planner output to security agent:

```python
def security_node(state: ScanState) -> ScanState:
    result = SecurityAgent().run(
        state["parsed_data"],
        state.get("planner_result", {})   # pass planner context
    )
    return {**state, "security_result": result}
```

---

## STREAMING SSE PATTERN (FastAPI)

```python
from fastapi.responses import StreamingResponse
import asyncio, json

@router.post("/api/run/{spec_id}/stream")
async def run_agents_stream(spec_id: str):
    scan = spec_parser.get_spec(spec_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    async def generate():
        def event(agent, status, data=None):
            payload = {"agent": agent, "status": status}
            if data:
                payload["data"] = data
            return f"data: {json.dumps(payload)}\n\n"

        # emit events for each agent
        yield event("planner", "running")
        await asyncio.sleep(0)  # yield control to allow streaming
        planner_result = PlannerAgent().run(scan["parsed_data"])
        yield event("planner", "completed", {"plan_ready": True})

        # ... repeat for each agent ...

        yield "data: [DONE]\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )
```

---

## REACT SSE CONSUMPTION PATTERN

```javascript
const runScanStream = async () => {
    setLoading(true);
    setStreamEvents([]);
    setError("");

    try {
        const headers = {};
        if (apiKey) headers["X-API-Key"] = apiKey;

        const response = await fetch(`${BASE}/api/run/${specId}/stream`, {
            method: "POST",
            headers
        });

        if (response.status === 401) { setNeedsAuth(true); return; }
        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        const events = [];

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            const text = decoder.decode(value, { stream: true });
            const lines = text.split("\n").filter(l => l.startsWith("data: "));

            for (const line of lines) {
                const raw = line.slice(6).trim();
                if (raw === "[DONE]") break;
                try {
                    const event = JSON.parse(raw);
                    events.push(event);
                    setStreamEvents([...events]);  // trigger re-render

                    if (event.agent === "report" && event.status === "completed") {
                        setReport(event.data.report);
                        setActiveScanId(specId);
                        setSidebarKey(k => k + 1);
                    }
                } catch { /* ignore malformed events */ }
            }
        }
    } catch (e) {
        setError(e.message || "Scan failed");
    } finally {
        setLoading(false);
        setStreamEvents([]);
    }
};
```

---

## SECURITY FINDINGS: BACKWARD COMPATIBILITY

The v1 findings use `risk_type` field. The v2 findings use `vulnerability` field. The SecurityTable component must handle both:

```javascript
// In SecurityTable, when reading the finding's main label:
const vulnName = f.vulnerability || f.risk_type || "Unknown";
```

This ensures old scan reports in the database still display correctly in the new UI.

---

## DATABASE: SAFE MIGRATION PATTERN

When adding new tables or columns, always use `IF NOT EXISTS` or `IF NOT EXISTS` column checks. Never ALTER TABLE in a way that could fail on existing databases:

```python
def init_db():
    with get_conn() as conn:
        conn.executescript("""
            -- Existing table (unchanged)
            CREATE TABLE IF NOT EXISTS scans ( ... );

            -- New table (safe to run on existing DB)
            CREATE TABLE IF NOT EXISTS agent_logs ( ... );
        """)
```

Never use `ALTER TABLE scans ADD COLUMN ...` unless absolutely necessary. If you must add a column, always use `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` pattern or handle the sqlite3 error gracefully.

---

## WHAT NEVER TO DO

1. **Never import `anthropic`** — it's being removed. All LLM calls go through Ollama.
2. **Never hardcode `localhost:8001`** as the test target — read from `parsed_data["base_url"]` or default gracefully.
3. **Never mark connection errors as security failures** — `possible_vulnerability: True` on network exceptions is a bug.
4. **Never use `list(set(recs))` for recommendations** — it loses ordering. Use a different deduplication approach like a seen set with a list.
5. **Never add new npm packages** — the frontend has no dependency upgrade path in scope.
6. **Never split App.js** — it must remain a single file.
7. **Never add a React Router** — the app has no routing and doesn't need it.
8. **Never remove existing API routes** — only add new ones.
9. **Never modify the `scans` table columns** — only add new tables.
10. **Never let a LangGraph node crash the graph** — every node must have try/except.

---

## FILE CHANGE SUMMARY

| File | Action | Why |
|---|---|---|
| `requirements.txt` | Remove `anthropic`, add `httpx` | Switching to Ollama |
| `database.py` | Add `agent_logs` table + `log_agent_run()` | Observability |
| `.env.example` | Replace Anthropic vars with Ollama vars | Config update |
| `agents/planner_agent.py` | **CREATE NEW** | New Planner Agent |
| `agents/security_agent.py` | **REWRITE** | LLM reasoning + fallback |
| `agents/api_testing_agent.py` | **REWRITE** | Fix bugs + context-aware |
| `agents/deployment_agent.py` | **EXPAND** | More checks |
| `agents/deep_scan_agent.py` | **CREATE NEW** | Exploit PoC generation |
| `orchestrator.py` | **REWRITE** | New state + conditional edges |
| `reporting/report_generator.py` | **EXPAND** | New report fields |
| `api/endpoints.py` | **ADD** streaming + agent log endpoints | v2 features |
| `docker-compose.yml` | Update env vars | Remove Anthropic, add Ollama |
| `frontend/src/App.js` | **EXPAND** | New components + streaming |
| `frontend/public/index.html` | Update title | "API Sentinel" not "React App" |

---

## LOCAL DEV SETUP (for reference)

```bash
# Terminal 1 — Ollama
ollama serve
ollama pull llama3.1:8b

# Terminal 2 — Backend
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Terminal 3 — Sample API (for testing dynamic tests)
cd sample-api
uvicorn main:app --port 8001

# Terminal 4 — Frontend
cd frontend
npm install
npm start
# Opens at http://localhost:3000
```

---

## QUICK REFERENCE: CURRENT DATA FLOWS

**Upload JSON spec**:
Frontend `uploadSpec()` → `POST /api/specs/upload` → `SpecParser.parse_spec()` → `save_scan()` → returns `{id, status: "parsed"}`

**Run scan (blocking)**:
Frontend `runScan()` → `POST /api/run/{id}` → `get_scan()` → `Orchestrator.run_all()` → `save_report()` → returns `{status, result}`

**Run scan (streaming — NEW)**:
Frontend `runScanStream()` → `POST /api/run/{id}/stream` → SSE events per agent → final event has full report

**View history**:
`HistorySidebar` → `GET /api/scans` → `list_scans()` → sidebar renders items

**Load past scan**:
`loadHistoryScan(scan)` → `GET /api/scans/{id}/report` → sets `report` state → `ReportView` renders

**Scan URL**:
Frontend `scanUrl()` → `POST /api/scan-url` → `discover_endpoints()` tries 7 URL paths → `Orchestrator.run_all()` → returns result directly (no separate upload step)
