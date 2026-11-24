"""Run the two 'before' scans against the old backend on :8000 and save full outputs."""
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

BACKEND = "http://127.0.0.1:8000"
REPO = Path(r"C:\Projects\API_Testing_Platform")
WORKTREE = Path(r"C:\Projects\API_Testing_Platform_before")
OUT = REPO / "evaluation"
OUT.mkdir(exist_ok=True)


def now():
    return datetime.now(timezone.utc).isoformat()


def upload_scan():
    spec = json.loads((WORKTREE / "sample-api" / "openapi.json").read_text(encoding="utf-8"))
    started = now()
    t0 = time.time()
    up = requests.post(f"{BACKEND}/api/specs/upload",
                       json={"spec": spec, "name": "sample-api (before)"}, timeout=60)
    up.raise_for_status()
    upload_resp = up.json()
    spec_id = upload_resp["id"]

    events, report, errors = [], None, []
    with requests.post(f"{BACKEND}/api/run/{spec_id}/stream", stream=True, timeout=600) as r:
        r.raise_for_status()
        for line in r.iter_lines(decode_unicode=True):
            if not line or not line.startswith("data: "):
                continue
            payload = line[len("data: "):]
            if payload == "[DONE]":
                break
            ev = json.loads(payload)
            if ev.get("agent") == "report" and ev.get("status") == "completed":
                report = ev["data"]["report"]
                events.append({"agent": "report", "status": "completed", "data": "<see report>"})
            else:
                events.append(ev)
                if ev.get("agent") == "error":
                    errors.append(ev)
            print("  event:", ev.get("agent"), ev.get("status"), flush=True)

    out = {
        "flow": "upload + /api/run/{id}/stream",
        "code_version": "main @ 4a739d6 (last semester)",
        "started_at": started,
        "duration_seconds": round(time.time() - t0, 1),
        "upload_response": upload_resp,
        "stream_events": events,
        "stream_errors": errors,
        "report": report,
    }
    (OUT / "before_upload.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print("saved before_upload.json; report present:", report is not None)


def url_scan():
    started = now()
    t0 = time.time()
    r = requests.post(f"{BACKEND}/api/scan-url",
                      json={"base_url": "http://127.0.0.1:8001"}, timeout=900)
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text
    out = {
        "flow": "/api/scan-url",
        "code_version": "main @ 4a739d6 (last semester)",
        "target": "http://127.0.0.1:8001",
        "started_at": started,
        "duration_seconds": round(time.time() - t0, 1),
        "http_status": r.status_code,
        "response": body,
    }
    (OUT / "before_url.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print("saved before_url.json; http", r.status_code)


if __name__ == "__main__":
    which = sys.argv[1:] or ["upload", "url"]
    if "upload" in which:
        print("== upload scan", flush=True)
        upload_scan()
    if "url" in which:
        print("== url scan", flush=True)
        url_scan()
