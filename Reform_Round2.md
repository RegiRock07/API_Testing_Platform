# API Sentinel — Reform Round 2
## Fixing the 5 Remaining Credibility Issues

---

## Context

Round 1 fixes are implemented and working. This document covers only what remains broken. Do not touch anything that is already working correctly.

**What is already working — do not break these:**
- 4-outcome test classification (PASS / SECURITY_FAILURE / EXPECTED_FAILURE / CONNECTION_ERROR)
- Severity cap: STATIC findings max = MEDIUM
- Planner tab with rule-based fallback
- AI Analysis pattern-based summary
- Stat cards: SECURITY FAILURES / EXPECTED BEHAVIOR / PASSED
- Security table filters (severity, detection type, sort)
- Detection badges (○ STATIC / ● CONFIRMED)
- Agent Progress panel across all three scan flows
- PDF export

**Files you will touch in this round:**
- `backend/app/agents/api_testing_agent.py` — fix unreachable root cause, fix empty results when unreachable
- `backend/app/agents/security_agent.py` — fix deduplication
- `backend/app/report_generator.py` — fix roadmap short term, fix security score label
- `frontend/src/App.js` — fix security score display when unreachable

---

## Problem 0 — API Testing Always Shows Unreachable (Diagnose First)

**Why this is Problem 0:**
Everything else in this document assumes the API testing agent runs correctly when a live API is provided. If the agent never actually makes HTTP requests, Problems 2, 3, and 4 are all masking a deeper issue. Diagnose and fix this before touching anything else.

You scanned `https://petstore.swagger.io/v2` which is a live public API. It should be reachable. The fact that it shows unreachable means one of the following is true. Work through them in order.

---

**Step 0.1 — Check if base_url is reaching the agent**

After any scan, fetch `GET /api/scans/{id}/report` raw JSON. Check two fields:
- `report.api_test_result.base_url_tested` — is it a real URL or null/empty?
- `report.api_test_result.status` — is it "completed" or "skipped"?

If `base_url_tested` is null or empty: the URL is not being passed from the orchestrator into the agent. Fix the orchestrator to extract `base_url` from `parsed_data["servers"][0]["url"]` and pass it into the api_testing node explicitly.

---

**Step 0.2 — Check what the connectivity pre-check actually hits**

Read the connectivity check code in `api_testing_agent.py`. Find the exact URL it tries to reach. It must hit the base URL root directly — for example `GET https://petstore.swagger.io/v2`. It must NOT hit `/health` or any assumed endpoint that may not exist on the target API. If it is hitting `/health` — change it to hit the base URL directly.

---

**Step 0.3 — Check the connectivity timeout**

Find the timeout value on the connectivity check HTTP request. It must be at least 10 seconds for external public APIs. If it is set to 3 or 5 seconds, public APIs will frequently time out and get marked unreachable incorrectly. Set it to 10 seconds minimum.

---

**Step 0.4 — Verify HTTP requests are actually executing**

Add a log statement (`print` or `logger.info`) immediately before the first real HTTP request in `api_testing_agent.py`. Run a scan. If the log never appears in the backend console — the agent is returning early before making any requests. Find the early return condition and fix it.

---

**Step 0.5 — Test with a guaranteed-live endpoint**

Run a scan using `https://httpbin.org` as the base URL. httpbin is always up and responds to any request. If API Testing still shows unreachable with httpbin — the problem is definitively in your code, not in petstore being down. If it shows reachable — petstore was just down and your code is fine.

---

**Success criteria for Problem 0:**
- `base_url_tested` in the raw report JSON is a real URL, not null or empty
- Scanning `https://httpbin.org` shows API Testing as reachable with actual test results
- At least some PASS or EXPECTED_FAILURE outcomes appear when scanning a live API

Do not proceed to Problem 1 until Problem 0 passes.

---

## Problem 1 — Deduplication Is Still Broken

**What is wrong:**
The same (endpoint + vulnerability) combination appears multiple times. Current scan shows:
- `/pet/{petId}` → "Potential BOLA — Object ID in Path (Static)" appears 3 times
- `/pet/{petId}/uploadImage` → "Potential BOLA — Object ID in Path (Static)" appears twice
- `/store/order/{orderId}` → "Potential BOLA — Object ID in Path (Static)" appears twice

This means deduplication was either not implemented or the key is wrong.

**Root cause to investigate first:**
Read `security_agent.py` and find where deduplication happens. Check what the key is. The most likely cause is that the method is different for each duplicate — GET, POST, DELETE on the same path each get their own BOLA finding, when BOLA is a path-level vulnerability not a method-level one.

**Decision — Deduplication key:**

BOLA and auth findings are path-level vulnerabilities. The deduplication key must be:

```
(endpoint_path, vulnerability_type)
```

NOT:

```
(endpoint_path, method, vulnerability_type)
```

For example, if GET /pet/{petId}, POST /pet/{petId}, and DELETE /pet/{petId} all trigger BOLA — that is ONE finding for the path `/pet/{petId}`, not three. Keep the finding with the highest confidence. Store all affected methods in an `affected_methods` list on the single finding.

Other vulnerability types (BFLA, rate limiting, SSRF) remain deduplicated by `(endpoint_path, method, vulnerability_type)` because those are method-specific.

**Vulnerability types that use path-level dedup key:**
- Anything containing "BOLA"
- Anything containing "Missing Authentication"
- Anything containing "Inventory"

**Vulnerability types that use method-level dedup key:**
- BFLA
- Rate Limiting / Resource Consumption
- SSRF
- Security Misconfiguration
- Everything else

**Expected result after fix:**
25 findings should collapse to roughly 10-14 unique findings. The security table should show one row per unique path+vulnerability, not one row per method+vulnerability.

---

## Problem 2 — API Tests Tab Is Empty When Unreachable

**What is wrong:**
When the API is unreachable, the API Tests tab shows "No test results." This makes it look like the agent never ran. The stat cards correctly show 0/0/0 with the API unreachable, but there is no explanation in the tab itself.

**What should happen:**
When `api_was_reachable == False`, the API Tests tab must show:
- A clear banner at the top: "API was unreachable — no live tests were executed. Tests will run automatically when a live base URL is provided."
- A list of endpoints that WOULD have been tested, shown as CONNECTION_ERROR rows
- Each row should show the endpoint path, method, and status "Unreachable" in muted color — not red

**Decision — api_testing_agent behavior when unreachable:**

Currently when the API is unreachable the agent returns an empty results list. Change it to return a skeleton result for each endpoint:

Each endpoint in `parsed_data["endpoints"]` should produce one result entry with:
- `endpoint`: the path
- `method`: the method
- `tests`: one test entry with:
  - `test_type`: "connectivity_check"
  - `outcome`: "CONNECTION_ERROR"
  - `note`: "API was unreachable — skipped all tests for this endpoint"
  - `actual_status`: null
  - `connection_error`: true

This gives the frontend data to render, making it clear the agent ran and made a decision, rather than appearing to have done nothing.

**Decision — Frontend display:**

In the TestResults component in App.js, add a check at the top:

If `report.summary.api_was_reachable == false`, show a yellow/amber banner:
"API was unreachable during testing. The endpoints below were identified from the spec but could not be tested. Provide a live base URL to enable active testing."

CONNECTION_ERROR rows render in muted gray with label "Unreachable" — identical to how they currently render, just now there will actually be rows to show.

---

## Problem 3 — Roadmap Short Term Is a Generic Fallback

**What is wrong:**
Short Term section shows: "Review static analysis findings for false positives."
This is a hardcoded fallback string that appears when there are no HIGH severity findings. Since all static findings are now capped at MEDIUM, there will never be HIGH findings from static analysis, so this fallback always triggers.

**Decision — Fix the Short Term roadmap logic:**

Short Term should not depend on HIGH severity findings. Change the logic:

Short Term items are the top MEDIUM confidence findings grouped by vulnerability type, showing the most affected endpoints.

Algorithm:
1. Take all findings where `severity == "MEDIUM"` and `confirmed == False`
2. Group by `vulnerability_type`
3. For each group, create one roadmap item:
   - Format: "Investigate [vulnerability_type] across [endpoint_list]"
   - List up to 3 endpoint paths, then "and N more" if there are additional ones
   - Example: "Investigate Potential BOLA across /pet/{petId}, /store/order/{orderId}, /user/{username} and 6 more"
4. Sort groups by count descending — most widespread issues first
5. Show top 3 groups maximum

Remove the generic "Review static analysis findings for false positives" fallback entirely. If there are no MEDIUM findings either, show: "No short-term actions identified — all findings are low severity."

**Expected result:**
Short Term section shows specific vulnerability types and specific endpoint paths, never a generic sentence.

---

## Problem 4 — Security Score Shows 0/6 When Unreachable

**What is wrong:**
When the deployment is unreachable, the stat card shows "0/6" for SECURITY SCORE. This implies the deployment was checked and failed all 6 checks. In reality, 0 checks ran because the deployment was unreachable.

The 6 checks are: security headers (X-Content-Type-Options, X-Frame-Options, HSTS, CSP, X-XSS-Protection, Referrer-Policy), HTTPS enforcement, CORS configuration, docs exposure.

Showing 0/6 when nothing was checked is misleading.

**Decision — report_generator.py:**

In the deployment summary, add a field:
- `deployment_checks_ran`: bool — True if deployment agent got a response, False if unreachable

**Decision — Frontend stat card:**

In App.js, update the Security Score stat card:

If `deployment_checks_ran == false` OR `deployment_status == "unreachable"`:
- Display value: `"N/A"`
- Label: `"SECURITY SCORE"`
- Subtext: `"deployment unreachable"`
- Color: muted/gray instead of cyan

If deployment was reachable:
- Display value: `"X/6"` as currently
- Color: cyan as currently

---

## Implementation Order

Complete each problem fully before starting the next. Test after each one.

**Step 0 — Diagnose and fix API Testing unreachable**

Follow the 5 diagnostic steps in Problem 0 in order. Do not skip any. Do not proceed until scanning a live API produces real test results.

**Step 1 — Fix deduplication in security_agent.py**

Read the current deduplication code first. Identify why duplicates still appear — is the key wrong, or is dedup not running at all. Fix the key to be path-level for BOLA and auth findings. Verify by checking that a scan of Petstore produces one BOLA finding per unique path, not one per method.

**Step 2 — Fix api_testing_agent.py unreachable behavior**

When connectivity check fails and `api_was_reachable = False`, generate skeleton CONNECTION_ERROR results for every endpoint in `parsed_data["endpoints"]` instead of returning an empty list. Update the agent return shape — `results` is never empty even when unreachable.

**Step 3 — Fix report_generator.py roadmap short term**

Replace the HIGH-severity-dependent short term logic with the MEDIUM-grouped-by-type logic described above. Remove the generic fallback string. Verify by checking that Petstore scan shows specific endpoint paths in Short Term.

**Step 4 — Fix security score when unreachable**

Add `deployment_checks_ran` field in report_generator.py. Update App.js stat card to show "N/A" in gray when unreachable. Verify by checking that an unreachable deployment shows "N/A" not "0/6".

---

## Success Criteria

All must pass. Do not close this task until every one passes.

- [ ] `base_url_tested` in raw report JSON is a real URL, not null or empty
- [ ] Scanning `https://httpbin.org` shows API Testing as reachable with real test results
- [ ] No duplicate (endpoint + vulnerability_type) combinations — one finding per unique path+vuln
- [ ] `/pet/{petId}` BOLA appears exactly once in the security table, with affected methods listed
- [ ] API Tests tab shows endpoint rows with "Unreachable" status when API is not live — not empty
- [ ] API Tests tab shows amber banner when API was unreachable
- [ ] Roadmap Short Term references specific vulnerability types and specific endpoint paths
- [ ] Roadmap Short Term never shows "Review static analysis findings for false positives"
- [ ] Security Score stat card shows "N/A" in gray when deployment is unreachable
- [ ] Security Score stat card shows "X/6" in cyan only when deployment was actually checked
