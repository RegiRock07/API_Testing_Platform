# backend/app/scheduler.py
"""
APScheduler-based scheduled scan runner.
Runs in-process within the FastAPI app (no Redis needed).
"""
import asyncio
import json
import hashlib
import hmac
import requests
from datetime import datetime, timezone, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

# Module-level scheduler singleton
_scheduler = None


# ─────────────────────────────────────────
# Sync wrapper — APScheduler calls this
# ─────────────────────────────────────────

def _run_scheduled_scan(schedule_id: str) -> None:
    """
    Sync entry-point called by APScheduler BackgroundScheduler.
    Spins up a fresh event loop to run the async logic.
    """
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(_run_scheduled_scan_async(schedule_id))
        loop.close()
    except Exception as e:
        print(f"[Scheduler] Error in schedule {schedule_id}: {e}")


# ─────────────────────────────────────────
# Async scan logic
# ─────────────────────────────────────────

async def _run_scheduled_scan_async(schedule_id: str) -> None:
    """
    Async inner routine: load schedule, run scan, update next_run_at,
    check for new critical/high findings, fire webhooks.
    """
    # Lazy imports to avoid circular references at module load time
    from app.database import (
        get_scheduled_scan,
        update_scheduled_scan_run,
        save_report,
        get_webhooks_for_user,
        update_webhook_triggered,
    )
    from app.orchestrator import Orchestrator
    from app.services.spec_parser import SpecParser

    schedule = get_scheduled_scan(schedule_id)
    if not schedule or not schedule.get("enabled"):
        print(f"[Scheduler] Schedule {schedule_id} not found or disabled, skipping")
        return

    print(f"[Scheduler] Running: {schedule.get('scan_name')} ({schedule_id})")

    spec_id = schedule.get("spec_id")
    base_url = schedule.get("base_url", "") or ""
    auth_config = schedule.get("auth_config") or {}

    # ── Build parsed_data ──────────────────────────────────────────
    if spec_id:
        sp = SpecParser()
        scan_data = sp.get_spec(spec_id)
        if not scan_data:
            print(f"[Scheduler] Spec {spec_id} not found for schedule {schedule_id}")
            return
        parsed_data = scan_data.get("parsed_data", {})
        if base_url:
            parsed_data["base_url"] = base_url
        if auth_config:
            parsed_data["auth"] = auth_config
    elif base_url:
        # URL-based discovery
        from app.api.endpoints import discover_endpoints
        bearer = auth_config.get("bearer_token", "") if auth_config else ""
        try:
            parsed_data, raw_spec, spec_url = discover_endpoints(base_url, bearer)
            if parsed_data is None:
                print(f"[Scheduler] No OpenAPI spec found at {base_url} for schedule {schedule_id}")
                return
        except Exception as e:
            print(f"[Scheduler] Endpoint discovery failed for {schedule_id}: {e}")
            return
        parsed_data["base_url"] = base_url
        if auth_config:
            parsed_data["auth"] = auth_config
    else:
        print(f"[Scheduler] Schedule {schedule_id} has neither spec_id nor base_url")
        return

    # ── Run the full scan ──────────────────────────────────────────
    orch = Orchestrator()
    result = orch.run_all(parsed_data)

    # Persist the report back to the scan record
    save_report(schedule_id, result)

    # ── Update next run time ──────────────────────────────────────
    interval = schedule.get("interval_hours", 24)
    next_run = datetime.now(timezone.utc) + timedelta(hours=interval)
    update_scheduled_scan_run(schedule_id, next_run.isoformat())
    print(f"[Scheduler] Scan {schedule_id} completed. Next run: {next_run.isoformat()}")

    # ── New-findings alert check ──────────────────────────────────
    if schedule.get("alert_on_new_findings"):
        _check_and_alert(schedule, result)

    # ── scan.completed webhook ─────────────────────────────────────
    _trigger_webhooks(schedule.get("user_id"), "scan.completed", {
        "scan_id": schedule_id,
        "scan_name": schedule.get("scan_name"),
        "result": result,
    })


# ─────────────────────────────────────────
# New-findings alert
# ─────────────────────────────────────────

def _check_and_alert(schedule: dict, current_result: dict) -> None:
    """
    If current scan has critical/high risks and alert_on_new_findings is set,
    fire the scan.new_critical webhook.
    """
    summary = current_result.get("summary", {})
    critical = summary.get("critical_risks", 0)
    high = summary.get("high_risks", 0)

    if critical > 0 or high > 0:
        _trigger_webhooks(schedule.get("user_id"), "scan.new_critical", {
            "scan_id": schedule.get("spec_id", ""),
            "scan_name": schedule.get("scan_name"),
            "critical_count": critical,
            "high_count": high,
            "risk_score": summary.get("overall_risk_score", "N/A"),
        })


# ─────────────────────────────────────────
# Webhook dispatch
# ─────────────────────────────────────────

def _trigger_webhooks(user_id: str, event_type: str, data: dict) -> None:
    """
    POST a signed JSON payload to all active webhooks matching event_type.
    """
    from app.database import get_webhooks_for_user, update_webhook_triggered

    try:
        webhooks = get_webhooks_for_user(user_id)
        if not webhooks:
            return

        payload = {
            "event": event_type,
            "timestamp": datetime.now(timezone.utc).timestamp(),
            "data": data,
        }
        payload_json = json.dumps(payload)

        for webhook in webhooks:
            event_types = webhook.get("event_types", [])
            # Skip if webhook doesn't subscribe to this event type
            if event_type not in event_types and "scan.completed" not in event_types:
                continue

            target_url = webhook.get("target_url", "")
            secret = webhook.get("secret", "")

            headers = {"Content-Type": "application/json"}
            if secret:
                headers["X-Sentinel-Signature"] = hmac.new(
                    secret.encode(),
                    payload_json.encode(),
                    hashlib.sha256,
                ).hexdigest()

            try:
                resp = requests.post(target_url, data=payload_json, headers=headers, timeout=10)
                update_webhook_triggered(webhook["id"])
                print(f"[Scheduler] Webhook {webhook['id']} triggered: {resp.status_code}")
            except Exception as e:
                print(f"[Scheduler] Webhook {webhook['id']} post failed: {e}")

    except Exception as e:
        print(f"[Scheduler] _trigger_webhooks error: {e}")


# ─────────────────────────────────────────
# Scheduler lifecycle
# ─────────────────────────────────────────

def get_scheduler() -> BackgroundScheduler:
    """Return the module-level BackgroundScheduler singleton."""
    global _scheduler
    if _scheduler is None:
        _scheduler = BackgroundScheduler(timezone="UTC")
    return _scheduler


def init_scheduler() -> None:
    """
    Called on FastAPI startup.
    Loads all due schedules (enabled=1, next_run_at <= now) and
    registers each with APScheduler.
    """
    from app.database import get_due_scheduled_scans

    scheduler = get_scheduler()
    due = get_due_scheduled_scans()

    for schedule in due:
        sid = schedule["id"]
        interval = schedule.get("interval_hours", 24)

        scheduler.add_job(
            _run_scheduled_scan,
            trigger=IntervalTrigger(hours=interval),
            id=sid,
            args=[sid],
            replace_existing=True,
            next_run_time=datetime.now(timezone.utc),
        )
        print(f"[Scheduler] Registered: {schedule.get('scan_name')} ({sid}), "
              f"interval={interval}h")

    if not scheduler.running:
        scheduler.start()
        print(f"[Scheduler] Started ({len(due)} due schedule(s))")


def shutdown_scheduler() -> None:
    """Called on FastAPI shutdown. Stops the scheduler gracefully."""
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        print("[Scheduler] Stopped")


def trigger_schedule_now(schedule_id: str) -> None:
    """
    Trigger a specific schedule immediately (adds to the APScheduler queue).
    If the job already exists it is replaced.
    """
    scheduler = get_scheduler()
    job_id = f"{schedule_id}_immediate"

    # Remove any existing immediate job for this schedule
    existing = [j for j in scheduler.get_jobs() if j.id == job_id]
    if existing:
        scheduler.remove_job(job_id)

    scheduler.add_job(
        _run_scheduled_scan,
        trigger=IntervalTrigger(hours=1),  # dummy one-time trigger
        id=job_id,
        args=[schedule_id],
        replace_existing=True,
        next_run_time=datetime.now(timezone.utc),
    )
    print(f"[Scheduler] Queued immediate run for schedule {schedule_id}")
