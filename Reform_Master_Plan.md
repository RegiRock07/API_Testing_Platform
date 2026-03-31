# API Sentinel — Reform Master Plan
## The single source of truth for the credibility refactor

---

## Context

You are refactoring API Sentinel, a production-grade API security testing platform built with FastAPI + Python 3.11, LangGraph, SQLite, Ollama (local LLM), and React 19 (single App.js file).

The system has strong architecture and UI but produces untrustworthy outputs. Your only job is to fix correctness, credibility, and reliability. Do NOT add new features. Do NOT expand scope.

**Key files:**
- `backend/app/agents/api_testing_agent.py` — primary fix target
- `backend/app/agents/security_agent.py` — primary fix target
- `backend/app/agents/planner_agent.py` — secondary fix target
- `backend/app/orchestrator.py` — synthesis logic
- `backend/app/report_generator.py` — summary and roadmap
- `frontend/src/App.js` — UI fixes only

**Invariants you must never break:**
1. System must complete a full scan with no Ollama running (rule-based fallback always exists)
2. Connection errors are never security failures — they are a separate category
3. Never crash on LLM response — always try/except, strip markdown fences, fallback
4. App.js stays one file, no new npm packages
5. All existing API routes preserved
6. Design token object `C` is untouched

---

## Problem 1 — False Test Failures (Fix First)

**What is wrong:** The stat card shows "49 FAILED" in red. Most are not security failures. HTTP 415 on a multipart upload endpoint is shown as FAIL — but this is caused by the test sending the wrong Content-Type, not a vulnerability. Any non-2xx response is currently treated as a test failure regardless of context.

**Decision: Replace PASS/FAIL with 4-outcome classification:**

- `PASS` — test ran, result is expected and safe
- `SECURITY_FAILURE` — unexpected success on a protected/invalid request, or auth bypass, or sensitive data in error response
- `EXPECTED_FAILURE` — API responded correctly to a bad request (4xx, 405, 415, etc.)
- `CONNECTION_ERROR` — could not reach the API at all

**Classification rules per test type:**

| test_type | Expected | Outcome if expected | Outcome if unexpected |
|-----------|----------|--------------------|-----------------------|
| `valid_request` | 2xx | PASS | SECURITY_FAILURE |
| `invalid_parameter` | 400, 422, 415 | EXPECTED_FAILURE | SECURITY_FAILURE if 2xx |
| `nonexistent_resource` | 404 | EXPECTED_FAILURE | SECURITY_FAILURE if 2xx |
| `wrong_method` | 405 | EXPECTED_FAILURE | SECURITY_FAILURE if 2xx |
| `fuzz_testing` | any 4xx | EXPECTED_FAILURE | SECURITY_FAILURE if 2xx + reflected payload or stack trace in body |
| Connection refused/timeout | — | — | CONNECTION_ERROR |

HTTP 415 specifically: always `EXPECTED_FAILURE` with note "Content-Type mismatch in test construction — not an API vulnerability."

**New fields each test result must include:**
- `outcome` — one of the 4 types above
- `expected_status` — what status code(s) we expected
- `actual_status` — what we got
- `note` — human-readable explanation
- `evidence` — only set on SECURITY_FAILURE, what triggered it

**New agent output counters (replace single failed_count):**
- `security_failure_count`
- `expected_failure_count`
- `pass_count`
- `connection_error_count`
- `api_was_reachable`

---

## Problem 2 — OWASP Findings Are Speculative and Duplicate

**What is wrong:** Every parameterized endpoint gets BOLA flagged at HIGH. Every endpoint without explicit auth gets Broken Authentication flagged at HIGH. Same endpoint+vulnerability appears multiple times. Confidence is always "POTENTIAL" regardless of evidence quality.

**Decision: Add detection_type and confidence to every finding:**

- `detection_type` — `"STATIC"` (spec-based) or `"DYNAMIC"` (confirmed via live request)
- `confidence` — `"LOW"`, `"MEDIUM"`, or `"HIGH"`

Security agent always emits `STATIC`. Synthesis agent upgrades to `DYNAMIC` after cross-correlating with live test results.

**Decision: Severity cap for STATIC findings:**

If `detection_type == "STATIC"`, maximum allowed severity is `MEDIUM`. Even if the rule would give HIGH or CRITICAL, cap it at MEDIUM. Only DYNAMIC findings may be HIGH or CRITICAL. A finding that has never touched the live API cannot be called HIGH.

**Decision: Deduplication:**

Deduplication key is `(endpoint_path, http_method, vulnerability_type)`. Only one finding per unique key. If two rules fire on the same key, keep the one with higher confidence.

**Decision: Graduated BOLA detection (replace the current blanket rule):**

- Endpoint has no path parameter → no BOLA finding at all
- Endpoint has path parameter + no security scheme + user-scoped param name → MEDIUM confidence
- Endpoint has path parameter + security scheme present → LOW confidence
- Planner flagged this endpoint as high-risk → bump to MEDIUM (never above without DYNAMIC)
- Confirmed via live test → HIGH, DYNAMIC (set by synthesis)

**Decision: Graduated Auth detection (replace the current blanket rule):**

- Security scheme defined in spec → no auth finding
- No security scheme + mutating method (POST/PUT/PATCH/DELETE) → MEDIUM confidence, STATIC
- No security scheme + read-only method (GET) → LOW confidence, STATIC
- Tested without token and returned 2xx → HIGH confidence, DYNAMIC (set by synthesis)

**Decision: Finding name format must communicate certainty:**

- Static BOLA → `"Potential BOLA — Object ID in Path (Static)"`
- Confirmed BOLA → `"Confirmed BOLA — Unauthorized Access Detected"`
- Static auth → `"Potential Missing Authentication (Static)"`
- Confirmed auth bypass → `"Confirmed Auth Bypass Detected"`

---

## Problem 3 — No Real Vulnerability Validation

**What is wrong:** The system describes vulnerabilities but never proves them. All findings are speculative.

**Decision: Add BOLA Validation Test to api_testing_agent:**

For each endpoint with a path parameter that security_agent flagged for BOLA, run a new test type `bola_validation`:

1. Replace all `{param}` in path with value `"1"` → baseline request (no auth headers)
2. Replace all `{param}` in path with value `"2"` → tampered request (no auth headers)
3. Compare results:
   - Both return 200 AND response bodies differ → `SECURITY_FAILURE`, evidence = "Endpoint returned different 200 responses for ID=1 and ID=2 without auth"
   - Tampered returns 403 or 404 → `EXPECTED_FAILURE` (auth protected it correctly)
   - Either connection error → `CONNECTION_ERROR`, skip

Extra fields to store: `bola_baseline_status`, `bola_tampered_status`, `bola_response_differs`.

**Decision: Add Auth Bypass Validation Test to api_testing_agent:**

For each endpoint flagged for auth issues, run a new test type `auth_bypass_validation` with three variants:

- `no_token` — remove Authorization header entirely. If 2xx → SECURITY_FAILURE
- `invalid_token` — set `Authorization: Bearer INVALID_TOKEN_SENTINEL_12345`. If 2xx → SECURITY_FAILURE
- `none_algorithm_jwt` — set `Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhdHRhY2tlciJ9.`. If 2xx → SECURITY_FAILURE with CRITICAL severity (accepts unsigned JWT)

Only run if `api_was_reachable == True`. Extra fields to store: `auth_test_variant`, `auth_bypass_detected`.

**Decision: Synthesis agent cross-correlates and promotes findings:**

After all agents complete, synthesis reads `api_test_result` and upgrades matching security findings:
- BOLA validation returned SECURITY_FAILURE → set finding to `DYNAMIC`, `confidence=HIGH`, `severity=HIGH`, `confirmed=True`
- Auth bypass validation returned SECURITY_FAILURE → set finding to `DYNAMIC`, `confidence=HIGH`, `severity=HIGH`, `confirmed=True`

---

## Problem 4 — Planner Tab Is Empty

**What is wrong:** Planner tab always shows "No planner assessment available. Run scan with Ollama for LLM-powered planning." This is an empty feature in production.

**Decision: Planner must always return structured data, with or without Ollama.**

If Ollama is available: run the LLM call as designed and return the full plan.

If Ollama is unavailable: run a rule-based fallback that derives the same output fields from `parsed_data` and `security_result`:
- `risk_summary` — derive from endpoint count and finding counts
- `auth_pattern_detected` — derive from spec security schemes
- `high_risk_endpoints` — derive from findings where severity is HIGH or CRITICAL
- `testing_priorities` — first 5 endpoints from parsed_data

The Planner tab must never show "No planner assessment available." No empty features allowed.

---

## Problem 5 — Stat Cards Show Inflated Failure Count

**What is wrong:** "49 FAILED" shown in large red. This includes expected behavior and connection errors, not just security issues.

**Decision: Replace the single FAILED stat card with three separate cards:**
- `SECURITY FAILURES` — red — only real security issues
- `EXPECTED BEHAVIOR` — gray/muted — correct API responses to bad requests
- `PASSED` — green

Connection error count shown as a small inline note below the cards, not as a stat card, with text clarifying it is not a security failure.

---

## Problem 6 — Security Table Has No Filtering

**What is wrong:** All findings dumped in insertion order. No way to filter or sort. Unusable at 34+ findings.

**Decision: Add a filter bar above the SecurityTable using React state only (no new packages):**
- Severity filter pills: ALL / CRITICAL / HIGH / MEDIUM / LOW
- Detection type filter pills: ALL / STATIC / DYNAMIC
- Sort toggle: by severity (default) / by endpoint

Severity sort order: CRITICAL > HIGH > MEDIUM > LOW. All existing expand/collapse behavior preserved.

Each finding row must show a detection badge: `● CONFIRMED` in green for DYNAMIC, `○ STATIC` in muted for STATIC.

---

## Problem 7 — AI Analysis Is a Template String

**What is wrong:** "This API has 34 security findings including 0 critical and 18 high severity issues." This is a static sentence with numbers inserted. It is not analysis and does not change meaningfully between different APIs.

**Decision: Build executive_summary from actual finding patterns:**

1. If confirmed findings exist → lead with confirmed count: "X vulnerabilities were confirmed via live testing."
2. If no confirmed findings → say so explicitly: "No vulnerabilities were confirmed via live testing (API was unreachable or all findings are static analysis only)."
3. If any OWASP category has 5+ findings → call it systemic: "19 findings fall under OWASP API2 — this suggests an architectural gap, not isolated misconfigurations."
4. Close with static finding count if relevant.

The summary must produce different text for different APIs. Generic template sentences are not allowed.

---

## Problem 8 — Roadmap Is Generic

**What is wrong:** "Fix critical severity findings immediately" is useless without specifics.

**Decision: Build roadmap items from actual finding data:**

- **Immediate** (confirmed=True or CRITICAL severity) → "Fix [vulnerability_name] on [method] [endpoint]"
- **Short Term** (HIGH severity, STATIC) → "Investigate potential [vulnerability_name] on [endpoint_list]". Group by vulnerability type, list up to 3 endpoints then "and N more."
- **Long Term** (systemic MEDIUM/LOW patterns, 3+ same vuln type) → "Implement [mitigation] across [count] endpoints"

Every roadmap item must reference at least one specific endpoint path or a specific count. Generic advice with no reference is not allowed.

---

## Implementation Order

Complete each step fully before starting the next.

**Step 1 — Fix api_testing_agent.py**
Implement 4-outcome classification. Add BOLA validation test. Add auth bypass validation test. Update agent return shape with new counters. Fallback must work with no Ollama.

**Step 2 — Fix security_agent.py**
Add `detection_type` and `confidence` to all findings. Apply severity cap (STATIC → max MEDIUM). Implement deduplication by (endpoint, method, vulnerability_type). Update BOLA detection logic. Update auth detection logic. Update finding name format.

**Step 3 — Fix orchestrator.py synthesis node**
Read bola_validation results, promote matching BOLA findings to DYNAMIC. Read auth_bypass_validation results, promote matching auth findings to DYNAMIC. Update cross-cutting concern logic to use confidence level, not just count.

**Step 4 — Fix report_generator.py**
Update summary block with new counters. Build executive_summary from patterns. Build roadmap from actual finding data. Ensure planner_assessment is always populated.

**Step 5 — Fix planner_agent.py**
Implement rule-based fallback. Planner always returns structured data. Planner tab never shows empty state.

**Step 6 — Fix App.js**
Update StatCards to show three separate metrics. Update TestResults to display EXPECTED_FAILURE in gray. Add filter bar to SecurityTable. Add detection badge to each finding row.

---

## Success Criteria

The refactor is complete when all of the following are true:

- Scanning an unreachable API produces 0 security failures and 0 false failures
- No duplicate (endpoint + vulnerability) combinations exist in any scan result
- All STATIC findings have severity ≤ MEDIUM
- At least one endpoint has BOLA confirmed via live test when the API is running
- At least one endpoint has auth bypass validated via live test when the API is running
- Planner tab always shows content on every scan regardless of Ollama availability
- StatCards show three separate metrics (security failures / expected behavior / passed)
- SecurityTable has severity and detection_type filters working
- Every roadmap item references a specific endpoint path or count
- AI Analysis tab produces different text for different APIs
- A security engineer reading the output would trust the results
