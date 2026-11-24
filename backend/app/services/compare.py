# backend/app/services/compare.py
#
# Compare two scan reports of the same API: what changed between a base
# (older) scan and a target (newer) scan.
#
#  - Security findings are matched by their `id`
#    ("<risk type>|<METHOD>|<path>", set by SecurityAgent). Older reports
#    without ids fall back to (endpoint, method, risk_type).
#  - Tests are matched by (method, endpoint, test name) so individual
#    pass -> fail / fail -> pass flips are listed, not just count deltas.

from __future__ import annotations

from typing import Any, Optional

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
_SEV_RANK  = {s: i for i, s in enumerate(SEVERITIES)}


def _finding_key(f: dict):
    return f.get("id") or f"{f.get('risk_type')}|{f.get('method')}|{f.get('endpoint')}"


def _sort_findings(findings: list) -> list:
    return sorted(findings, key=lambda f: (_SEV_RANK.get(f.get("severity"), 9),
                                           f.get("endpoint", ""), f.get("method", "")))


def _slim(f: dict) -> dict:
    """The fields the comparison view needs (no PoC blobs or evidence)."""
    return {k: f.get(k) for k in ("id", "severity", "confidence", "vulnerability", "risk_type",
                                  "endpoint", "method", "description", "detection_type")
            if f.get(k) is not None}


def _severity_counts(findings: list) -> dict:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        if f.get("severity") in counts:
            counts[f["severity"]] += 1
    return counts


def _test_outcome(t: dict) -> str:
    if t.get("skipped") or t.get("passed") is None:
        return "skipped"
    return "passed" if t.get("passed") else "failed"


def _tests(report: dict) -> dict:
    """{(METHOD, path, test): outcome} for every test in the report."""
    out = {}
    for ep in report.get("api_test_results") or []:
        for t in ep.get("tests") or []:
            out[(ep.get("method"), ep.get("endpoint"), t.get("test"))] = {
                "outcome": _test_outcome(t), "status_code": t.get("status_code")}
    return out


def _test_counts(tests: dict) -> dict:
    counts = {"total": len(tests), "passed": 0, "failed": 0, "skipped": 0}
    for v in tests.values():
        counts[v["outcome"]] += 1
    return counts


def _parse_score(score: Any) -> Optional[tuple[int, int]]:
    try:
        got, total = str(score).split("/")
        return int(got), int(total)
    except (ValueError, AttributeError):
        return None


def _delta(base: dict, target: dict) -> dict:
    return {k: target.get(k, 0) - base.get(k, 0) for k in target}


def compare_reports(base: dict, target: dict) -> dict:
    """Diff two (non-baseline) scan reports. `base` is the older one."""
    base_f   = {_finding_key(f): f for f in base.get("security_findings") or []}
    target_f = {_finding_key(f): f for f in target.get("security_findings") or []}

    new       = [_slim(target_f[k]) for k in target_f if k not in base_f]
    fixed     = [_slim(base_f[k])   for k in base_f   if k not in target_f]
    unchanged = []
    for k in target_f:
        if k in base_f:
            item = _slim(target_f[k])
            before = base_f[k].get("severity")
            if before != target_f[k].get("severity"):
                item["severity_before"] = before     # same issue, re-rated
            unchanged.append(item)

    base_sev, target_sev = (_severity_counts(base_f.values()),
                            _severity_counts(target_f.values()))

    base_t, target_t = _tests(base), _tests(target)
    base_tc, target_tc = _test_counts(base_t), _test_counts(target_t)
    test_changes = []
    for key in sorted(set(base_t) | set(target_t), key=lambda k: tuple(str(x) for x in k)):
        before = base_t.get(key, {}).get("outcome", "absent")
        after  = target_t.get(key, {}).get("outcome", "absent")
        if before != after:
            method, endpoint, test = key
            test_changes.append({
                "method": method, "endpoint": endpoint, "test": test,
                "before": before, "after": after,
                "status_before": base_t.get(key, {}).get("status_code"),
                "status_after":  target_t.get(key, {}).get("status_code"),
            })

    base_dep, target_dep = base.get("deployment") or {}, target.get("deployment") or {}
    bs, ts = _parse_score(base_dep.get("security_score")), _parse_score(target_dep.get("security_score"))

    return {
        "findings": {
            "new":       _sort_findings(new),
            "fixed":     _sort_findings(fixed),
            "unchanged": _sort_findings(unchanged),
        },
        "severity": {"base": base_sev, "target": target_sev, "delta": _delta(base_sev, target_sev)},
        "tests": {
            "base": base_tc, "target": target_tc, "delta": _delta(base_tc, target_tc),
            "changes": test_changes,
        },
        "deployment": {
            "base_score":   base_dep.get("security_score", "N/A"),
            "target_score": target_dep.get("security_score", "N/A"),
            "score_delta":  (ts[0] - bs[0]) if bs and ts and bs[1] == ts[1] else None,
            "base_status":   base_dep.get("status", "unknown"),
            "target_status": target_dep.get("status", "unknown"),
        },
    }
