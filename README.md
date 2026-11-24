# API Sentinel

API Sentinel is an API security testing platform. Give it an OpenAPI spec or just the URL of an API, and it:

- reads the spec
- plans what to test
- runs live HTTP tests and payload fuzzing against every endpoint
- checks how the API is deployed
- explains the results in a report you can view, compare with earlier scans, or export as PDF

A pipeline of agents does the work. Each agent uses an LLM (Groq, Gemini or a local Ollama model) when one is configured, and falls back to built-in rules when it isn't. So scans always finish, even with no API key.

> Only scan systems you own or are authorized to test. The repo includes a deliberately vulnerable target, [`sample-api/`](sample-api/), for trying it out.

## Contents

- [How it works](#how-it-works)
- [Features](#features)
- [Repository layout](#repository-layout)
- [Run with Docker](#run-with-docker)
- [Run without Docker](#run-without-docker)
- [Configuration](#configuration)
- [Try it on sample-api](#try-it-on-sample-api)
- [API reference](#api-reference)
- [Tests](#tests)
- [Troubleshooting](#troubleshooting)

## How it works

```
 React dashboard ──► FastAPI backend ──► spec parser ──► LangGraph pipeline
 (upload / paste /    (REST + live       (endpoints,       │
  URL, live progress)  progress stream)   params, auth)     ▼
                                                    1. Planner
                                                    2. Test generation
                                                    3. Security (static)
                                                    4. API testing (live HTTP)
                                                    5. Deployment checks
                                                    6. Deep scan ── only when findings are serious
                                                    7. LLM analysis
                                                    8. Report ──► SQLite ──► dashboard / PDF
```

The orchestrator ([`backend/app/orchestrator.py`](backend/app/orchestrator.py)) is a LangGraph `StateGraph`. It runs in a worker thread. As each agent starts and finishes, its progress is streamed to the browser as server-sent events.

| # | Agent | What it does | Without an LLM |
|---|-------|--------------|----------------|
| 1 | **Planner** | Ranks endpoints by risk and suggests attack vectors and fuzz categories | Rule-based risk ranking |
| 2 | **Test generation** | Writes targeted test cases per endpoint | Standard test-case set |
| 3 | **Security** | Static analysis of the spec, inspired by the OWASP API Top 10: BOLA, missing authentication, excessive data exposure, missing rate limiting. Each finding carries severity, confidence and detection type. | (rule-based) |
| 4 | **API testing** | Sends real requests to each endpoint, in parallel, within a time budget. Checks: <ul><li>schema-aware valid request</li><li>invalid parameter</li><li>nonexistent resource</li><li>undocumented method</li><li>unauthenticated access</li><li>fuzzing (SQL injection, XSS, path traversal and more) of path and query parameters</li></ul>Each check keeps the request and response as evidence. | (no LLM needed) |
| 5 | **Deployment** | Checks reachability and latency, HTTPS enforcement, CORS, 6 security headers and exposed API docs. Gives a score out of 6. | (no LLM needed) |
| 6 | **Deep scan** | Runs only when there is any CRITICAL finding, 2+ HIGH or 3+ MEDIUM. Writes proof-of-concept exploit steps for the worst findings. | Rule-based PoC |
| 7 | **LLM analysis** | Executive summary, top risks and remediation roadmap | Notes that the analysis was unavailable |
| 8 | **Report** | Merges everything, adds recommendations, and records which stages used the LLM | (no LLM needed) |

## Features

- **Three ways to start a scan:**
  - paste a spec
  - upload a `.json` / `.yaml` / `.yml` file
  - enter a URL

  Uploads take an optional **target base URL**, used when the spec's `servers` are missing, relative or wrong.
- **URL scan:** discovers the spec automatically. It tries the URL itself, then common locations (`/openapi.json`, `/swagger.json`, `/v3/api-docs`, …), then runs the full pipeline.
- **Baseline scan:** when no spec is found, it still checks:
  - the SSL/TLS certificate and HTTPS redirect
  - security headers and CORS
  - exposed sensitive paths (`/.env`, `/.git/config`, `/admin`, …)
  - the HTTP methods the server allows

  The result is saved like any other scan.
- **Authenticated scanning:** scan with a Bearer token, an API key (custom header name) or HTTP Basic credentials. The credential is used only for the requests to the target. It is never written to the database, the report or the browser's storage; the report records only that a credential of a given type was used.
- **Safe mode** (on by default): DELETE, PUT and PATCH requests are never sent to the target. Those tests are reported as *Skipped (safe mode)*.
- **Scan comparison:** pick an earlier scan of the same API and see:
  - new, fixed and unchanged findings (matched by finding id)
  - changes in severity counts and test pass/fail counts
  - the change in deployment score
  - which individual tests changed outcome
- **PDF export:** a formatted report containing:
  - a cover page and executive summary
  - findings sorted by severity, with proof-of-concept details
  - per-endpoint test tables
  - deployment checks and recommendations
  - the AI analysis

  JSON export is also available.
- **Scan history:** every scan and report is stored in SQLite. Re-scan re-runs the pipeline on a stored spec.
- **Sign-in:** Google sign-in through Firebase in the UI. The backend verifies Firebase ID tokens when it is given Firebase credentials. Otherwise it runs in dev mode with no sign-in check.

## Repository layout

```
backend/          FastAPI app (Python)
  app/main.py         app, CORS, /health
  app/orchestrator.py LangGraph pipeline
  app/agents/         the agents above
  app/api/            REST + streaming routes, Firebase auth
  app/services/       spec parsing, LLM client, baseline checks, comparison
  app/reporting/      report assembly and PDF rendering
frontend/         React dashboard (Create React App)
sample-api/       deliberately vulnerable FastAPI app to scan
evaluation/       before/after evaluation data and a sample PDF report
docker-compose.yml
.env.example      every environment variable, documented
```

## Run with Docker

You need Docker with Compose v2.

```bash
cp .env.example .env          # optional: add GROQ_API_KEY for AI features
docker compose up --build
```

| What | URL |
|------|-----|
| Frontend (nginx) | http://localhost:3000 |
| Backend | http://localhost:8000 |
| API docs | http://localhost:8000/docs |

- The backend has a healthcheck on `/health`, and the frontend starts once the backend is healthy.
- Scan data is kept in the `sentinel_data` volume. `docker compose down -v` deletes it.
- The frontend is a production build, and the backend URL is baked in at build time from `REACT_APP_API_URL` (default `http://localhost:8000`). Rebuild after changing it.
- From inside the backend container, `localhost` means the container itself. To scan an API running on your machine (such as sample-api), use `http://host.docker.internal:<port>`.

## Run without Docker

You need **Python 3.11+** and **Node.js 20+**.

On Windows, use **127.0.0.1** instead of `localhost` for the backend and sample-api. `localhost` tries IPv6 first, which can stall each request for about 2 seconds.

### 1. Backend

Run these from the repository root.

**Windows (PowerShell)**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt
Copy-Item .env.example .env
cd backend
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

**macOS / Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
cp .env.example .env
cd backend
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

- `.env` is optional, and every value in it is optional (see [Configuration](#configuration)). Add `GROQ_API_KEY` to turn on the AI stages.
- Check that the backend is up: http://127.0.0.1:8000/health should return `{"status":"healthy"}`.
- The database file is created at `backend/sentinel.db`.

### 2. Sample API (optional test target)

In a second terminal, with the same virtual environment activated:

```bash
cd sample-api
uvicorn main:app --host 127.0.0.1 --port 8001
```

### 3. Frontend

In a third terminal:

```bash
cd frontend
npm ci
npm start
```

- `npm start` serves the dashboard at http://localhost:3000.
- Open it at **localhost**, not 127.0.0.1. Google sign-in only works on domains the Firebase project authorizes, and by default that list contains `localhost` but not `127.0.0.1`.
- The dashboard calls the backend at the URL in [`frontend/.env.development`](frontend/.env.development) (`http://127.0.0.1:8000`).

## Configuration

All variables are optional. Copy [`.env.example`](.env.example) to `.env` in the repository root. Both the backend and `docker compose` read it. Never commit `.env`; it is git-ignored.

In the table, `<placeholder>` means "put your value here".

### LLM

| Variable | Purpose | Default |
|----------|---------|---------|
| `LLM_PROVIDER` | `groq`, `gemini` or `ollama` | `groq` |
| `GROQ_API_KEY` | Groq key, from https://console.groq.com. Needed for the AI stages with the default provider. | empty: rule-based only |
| `GROQ_MODEL_PRIMARY` | Main Groq model | `openai/gpt-oss-120b` |
| `GROQ_MODEL_FALLBACK` | Model tried when the main model fails | `openai/gpt-oss-20b` |
| `GROQ_MODEL` | Legacy name for `GROQ_MODEL_PRIMARY` | – |
| `GROQ_TEMPERATURE` | Sampling temperature | `0.2` |
| `GOOGLE_API_KEY` | Gemini key, from https://aistudio.google.com. Used when `LLM_PROVIDER=gemini`, or as a fallback when Groq is rate-limited or all Groq models fail. | empty |
| `GEMINI_MODEL` | Gemini model | `gemini-3.8-flash` |
| `OLLAMA_BASE_URL` | Ollama server, used when `LLM_PROVIDER=ollama` | `http://localhost:11434` (Docker: `http://host.docker.internal:11434`) |
| `OLLAMA_DEFAULT_MODEL` | Ollama model | `llama3.1:8b` |
| `OLLAMA_TIMEOUT` | Ollama request timeout in seconds | `60` |
| `LLM_TIMEOUT_SECONDS` | Hard timeout per Groq/Gemini request, with no SDK retries | `45` |

### Authentication

| Variable | Purpose | Default |
|----------|---------|---------|
| `FIREBASE_CREDENTIALS_JSON` | Firebase service-account JSON on one line, in single quotes. When set, every API request needs a Firebase ID token (production mode). | empty: dev mode |
| `FIREBASE_CREDENTIALS` | Path to the service-account file instead of the JSON. Not passed through by docker-compose. | empty |
| `SENTINEL_API_KEY` | Dev mode only. If set, API calls must send `Authorization: ApiKey <key>`. The web UI does not send this header, so leave it empty when you use the UI. | empty |

### Backend server

| Variable | Purpose | Default |
|----------|---------|---------|
| `ALLOWED_ORIGINS` | Comma-separated CORS origins, or `*` | `*` |
| `SENTINEL_DB_PATH` | SQLite file path | `backend/sentinel.db` (Docker: `/data/sentinel.db`) |

### Frontend

| Variable | Purpose | Default |
|----------|---------|---------|
| `REACT_APP_API_URL` | Backend URL the dashboard calls. It is fixed when the frontend is built: for `npm start` it comes from `frontend/.env.development`, for `npm run build` from `frontend/.env.production`, and for Docker from `.env`. | `http://127.0.0.1:8000` (dev) |
| `REACT_APP_APP_NAME` | Name shown in the UI | `API Sentinel` |

Example `.env` with AI features on:

```dotenv
GROQ_API_KEY=<your-groq-api-key>
# GOOGLE_API_KEY=<your-google-api-key>
```

## Try it on sample-api

[`sample-api/`](sample-api/) is a small e-commerce API with intentional flaws: no authentication, IDs in paths (BOLA), full user objects in responses, and an unthrottled search endpoint.

- The live app exposes 7 endpoints at http://127.0.0.1:8001/openapi.json.
- [`sample-api/openapi.json`](sample-api/openapi.json) is a smaller hand-written spec with 3 endpoints.

Start the backend and sample-api as described above.

### In the dashboard

1. **URL scan:** enter `http://127.0.0.1:8001` and run it. The spec is discovered automatically, and progress streams per agent. A typical result is 8 findings (4 MEDIUM, 4 LOW), 19 tests and a deployment score of 3/6.
2. **Upload scan:** upload `sample-api/openapi.json` and set **Target base URL** to `http://127.0.0.1:8001`, because that spec has no `servers`.
3. **Authenticated scan:** open **Scan options**, choose *Bearer token*, enter any value and run. The report header shows **Authenticated**. sample-api ignores the token, but every test request carries it.
4. **Compare:** on the newer scan's report, click **Compare** and pick the earlier scan.
5. **Download PDF:** use the button next to **Export JSON**.

### With curl

These commands assume dev mode (no Firebase credentials). In Windows PowerShell 5.1, type `curl.exe` instead of `curl`, or use Git Bash.

```bash
# Upload a spec file with an explicit target, then run the scan (streams progress events)
curl -F "file=@sample-api/openapi.json" -F "base_url=http://127.0.0.1:8001" \
     http://127.0.0.1:8000/api/specs/upload-file           # -> {"id": "<scan-id>", ...}
curl -N -X POST http://127.0.0.1:8000/api/run/<scan-id>/stream \
     -H "Content-Type: application/json" -d '{"safe_mode": true}'

# URL scan: discover and store the spec, then stream it the same way
curl -X POST http://127.0.0.1:8000/api/scan-url/discover \
     -H "Content-Type: application/json" -d '{"base_url": "http://127.0.0.1:8001"}'

# Authenticated scan
curl -N -X POST http://127.0.0.1:8000/api/run/<scan-id>/stream \
     -H "Content-Type: application/json" \
     -d '{"safe_mode": true, "auth": {"type": "bearer", "value": "<token>"}}'

# Compare two scans (base = older, target = newer), then download a PDF
curl "http://127.0.0.1:8000/api/scans/compare?base=<older-id>&target=<newer-id>"
curl -o report.pdf http://127.0.0.1:8000/api/scans/<scan-id>/report/pdf
```

The stream sends `data: {"agent": ..., "status": "running|completed|skipped|error", "data": {...}}` events. The last one before `data: [DONE]` is `report` / `completed`, and its data contains the full report.

## API reference

Interactive docs are at `/docs`. When Firebase is configured, every `/api/*` route needs `Authorization: Bearer <Firebase ID token>`.

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | Liveness check |
| POST | `/api/specs/upload` | Store a spec from a JSON body: `{name, spec, base_url?}` |
| POST | `/api/specs/upload-file` | Store an uploaded `.json` / `.yaml` / `.yml` file (multipart form, optional `base_url` field) |
| POST | `/api/scan-url/discover` | Find the spec at a URL and store it, or run baseline checks when there is none |
| POST | `/api/run/{id}/stream` | Run the pipeline and stream progress. Optional body: `{safe_mode, auth: {type, value, header_name}}` |
| POST | `/api/run/{id}` | Run the pipeline and return the report in one blocking response (same body) |
| POST | `/api/scan-url` | Older blocking discover-and-scan in one call |
| GET | `/api/scans` | Scan history |
| GET | `/api/specs/{id}` | A stored spec and its parsed endpoints |
| GET | `/api/scans/{id}/report` | Report as JSON |
| GET | `/api/scans/{id}/report/pdf` | Report as PDF |
| GET | `/api/scans/compare?base=&target=` | Differences between two scans |
| DELETE | `/api/scans/{id}` | Delete a scan |

## Tests

Frontend tests use Jest and React Testing Library. They cover:
- the login screen
- parsing of the live progress stream
- scan options
- scan comparison
- PDF download

```bash
cd frontend
npm test -- --watchAll=false      # one run, no watch mode
npm run build                     # production build into frontend/build
```

On Windows PowerShell, `$env:CI="true"; npm test` also runs the tests once.

## Troubleshooting

- **Requests are slow on Windows, or the backend can't be reached:** use `127.0.0.1` instead of `localhost` (see [Run without Docker](#run-without-docker)).
- **"Address already in use" on port 8000 or 8001:** another process is listening on that port. Stop it, or start uvicorn with a different `--port`.
  - If you move the backend, update `REACT_APP_API_URL` to match.
  - If you move the target, scan it on its new URL.
- **Scans finish, but `llm_usage` shows `false` for stages:** check whether `GROQ_API_KEY` is missing, or whether Groq is rate-limiting you. The free tier allows a limited number of tokens per minute, so back-to-back scans can hit it. The backend log shows the cause, and the agents fall back to their rule-based logic.
- **The UI gets HTTP 401 for every request:** `SENTINEL_API_KEY` is set but the UI doesn't send it. Leave it empty, or configure Firebase.
- **Google sign-in fails with `auth/unauthorized-domain`:** open the UI at `http://localhost:3000`, or add your domain to the Firebase project's authorized domains.
