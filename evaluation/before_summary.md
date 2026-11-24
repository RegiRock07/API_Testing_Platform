# Baseline ("before") scan results: last semester's code

| | |
|---|---|
| Scanner code | `main` @ `4a739d6`, run from the worktree `C:\Projects\API_Testing_Platform_before` |
| Scanner backend | `uvicorn app.main:app` on `127.0.0.1:8000` |
| Target | `sample-api/main.py` on `127.0.0.1:8001` |
| Run date | 2026-11-24 |
| Raw reports | `before_upload.json`, `before_url.json` |
| LLM | Groq, same `GROQ_API_KEY` as the main repo. **Every LLM call failed** (see "Environment caveats") |

Two scan flows were run:

1. **Upload:** `POST /api/specs/upload` with `sample-api/openapi.json`, then `POST /api/run/{id}/stream`. Took 50.5 s.
2. **URL scan:** `POST /api/scan-url` with `base_url = http://127.0.0.1:8001`. The scanner found the live spec at `/openapi.json`. Took 9.7 s.

> The two flows did not scan the same API surface. The committed `sample-api/openapi.json` lists only **3 operations**, all GET (`/users`, `/users/{user_id}`, `/users/{user_id}/orders`). The live spec has **7 operations** (it also has `GET /`, `POST /users`, `GET /products` and `POST /search`). Compare upload results with upload results and URL results with URL results.

---

## 1. Findings by severity

| Severity | Upload | URL scan |
|---|---:|---:|
| Critical | 0 | 0 |
| High | 0 | 0 |
| Medium | 2 | 4 |
| Low | 3 | 4 |
| **Total** | **5** | **8** |

What the findings were:

| Finding | Severity | Upload | URL scan |
|---|---|---|---|
| Potential BOLA: object ID in path | Medium | `/users/{user_id}`, `/users/{user_id}/orders` | same 2 |
| Potential missing authentication | Medium | none | `POST /users`, `POST /search` |
| Potential excessive data exposure | Low | `/users`, `/users/{user_id}`, `/users/{user_id}/orders` | same 3 |
| Potential lack of rate limiting | Low | none | `POST /search` |

Every finding is a **static heuristic** based only on the spec: `detection_type: STATIC` and `confirmed: false`. None was verified with a live request. The URL scan triggered deep scan (4 Medium), but its LLM calls failed, so no finding was promoted or confirmed.

How these compare with the vulnerabilities planted in `sample-api/main.py`:
- **BOLA** on `/users/{user_id}` and `/users/{user_id}/orders`: flagged, but only as "potential".
- **No authentication anywhere:** flagged only on the two POST endpoints. The GET endpoints that return user data were not flagged for missing auth.
- **Simulated SQL injection on `POST /search`:** not detected. The fuzzer only injects payloads into *path* parameters, and `/search` takes a *query* parameter.

---

## 2. API tests

| | Upload | URL scan |
|---|---:|---:|
| Tests run | **0** | 20 |
| Passed | 0 | 15 |
| Failed | 0 | 5 |

### Upload: 0 tests is a scanner failure, not a clean result

The backend log shows `[Stream] APITesting timed out`. The streaming endpoint allows the API-testing agent 30 s, and two scanner problems made the agent exceed it:

- An uploaded spec has no `base_url`, so the agent falls back to the hard-coded `http://localhost:8001`. On this Windows machine, `localhost` is tried over IPv6 (`::1`) first. That attempt is refused, and the IPv4 fallback costs about **2 s per request**: measured at 2.06 s for `localhost:8001` against 0.03 s for `127.0.0.1:8001`.
- The 3 endpoints need about 34 requests (12 fuzz payloads for each of the 2 path-parameter endpoints, plus the basic tests), which comes to roughly 70 s.

When the timeout fires, the partial results are discarded. The report then shows `total_tests_run: 0, failed_tests: 0`, and nothing in the summary indicates that testing timed out.

### URL scan: the 5 failures and their cause

| # | Endpoint | Test | Got | Expected by scanner | Cause | Why |
|---|---|---|---|---|---|---|
| 1 | `GET /users` | wrong_method | 422 | 400/405 | **Scanner** | The "wrong method" chosen was POST, but `POST /users` is a real route. The 422 is a body-validation error from that route. |
| 2 | `POST /users` | valid_request | 422 | < 400 | **Scanner** | The "valid" request is sent with **no body**. The route requires a `User` JSON body. |
| 3 | `POST /users` | wrong_method | 200 | 400/405 | **Scanner** | The "wrong method" chosen was GET, but `GET /users` is a real route. |
| 4 | `POST /search` | valid_request | 422 | < 400 | **Scanner** | The required query parameter `query` is never sent. |
| 5 | `GET /users/{user_id}/orders` | nonexistent_resource | 200 (`[]`) | 404 | **API** | The API returns an empty list for user 999999 instead of 404. `/users/{user_id}` does return 404 for unknown users. This is a genuine, low-severity API inconsistency. |

**4 of the 5 failures came from the scanner, and 1 came from the API.** Excluding scanner errors, 15 of 16 tests reflect real API behaviour and pass.

The scanner behaviours behind failures 1–4, from `api_testing_agent.py` on `main`:
- `wrong_method = "POST" if method != "POST" else "GET"`: it never checks whether that method is defined on the same path.
- The "valid" request never builds a request body or required query parameters from the spec.

---

## 3. Deployment

| | Upload | URL scan |
|---|---|---|
| Status | `unreachable` | `unhealthy` |
| Security score | `N/A` (checks did not run) | `2/6` |
| HTTP status of health probe | none (timed out) | 404 |
| Latency | none | 22.85 ms |

### Upload: `unreachable` is caused by the scanner

- An uploaded spec has no `base_url`, so the deployment agent defaults to `http://localhost:8000`. That is **the scanner's own backend**, not the API being scanned.
- The scanner also makes that request synchronously inside the async SSE generator, which blocks the event loop. Its own server therefore can't answer `/health`, the request times out after 10 s, and the result is "unreachable". The backend log has no `/health` request recorded during the scan.

### URL scan: the score breakdown

The score is 6 binary checks:

| Check | Result | Point | Cause |
|---|---|---|---|
| `/health` returns 200 | 404 | 0 | **Scanner.** The sample API has no `/health` route. It was up and answered `GET /` with 200 in about 23 ms, but the agent treats the 404 as "unhealthy". |
| All 6 security headers present | 0 of 6 present | 0 | API (real) |
| HTTPS enforced | http | 0 | Expected for a local target. The agent skips the HTTPS *finding* for `127.*`/`localhost` but still withholds the point. |
| CORS not misconfigured | OK | 1 | |
| Docs not exposed | `/docs` exposed | 0 | API (real) |
| Latency < 1000 ms | 22.85 ms | 1 | |

Deployment findings that apply to the API: 6 missing security headers (X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security, Content-Security-Policy, X-XSS-Protection, Referrer-Policy) and `/docs` being publicly reachable.

If liveness had been judged from a route that exists, the status would have been healthy and the score 3/6.

---

## 4. Problems caused by the scanner rather than the API

| # | Flow | Symptom | Root cause in the old code |
|---|---|---|---|
| S1 | Upload | 0 API tests run; summary shows 0/0 | Hard-coded `localhost:8001` (about 2 s per request through the IPv6 fallback) plus a 30 s stream timeout that discards partial results without reporting it |
| S2 | Upload | Deployment `unreachable`, score N/A | Deployment probes `localhost:8000`, the scanner itself, and blocks its own event loop while doing it |
| S3 | URL | `GET /users` wrong_method failed | The "wrong" method is defined on the path |
| S4 | URL | `POST /users` valid_request failed | No request body generated |
| S5 | URL | `POST /users` wrong_method failed | The "wrong" method is defined on the path |
| S6 | URL | `POST /search` valid_request failed | Required query parameter not sent |
| S7 | URL | Deployment `unhealthy`, −1 score point | Assumes every API exposes `/health` |
| S8 | Both | No `POST /search` SQLi detection | Fuzzer only targets path parameters |

The only genuine API test failure was `GET /users/{user_id}/orders` returning 200 `[]` for a non-existent user.

---

## 5. Environment caveats

- **The LLM was unavailable for the whole run.** Groq returned `404 model_not_found` for both `llama-3.3-70b-versatile` and `llama-3.1-8b-instant`, so the planner, test generation, deep scan and final analysis all used their non-LLM fallbacks (`test_generation.llm_used: false`). The key comes from the main repo's `.env`, so the "after" run will hit the same problem unless the key or models change.
- sample-api was bound to `127.0.0.1` only, as specified. That binding is what exposes the `localhost` IPv6 delay in S1. A server bound to `0.0.0.0`/`::` would hide it, but the scanner would still be pointing at a hard-coded host.
- Python 3.13.4 in a virtual env at `C:\Projects\API_Testing_Platform\.venv`, with the worktree's `backend/requirements.txt` installed.
