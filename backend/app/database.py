# backend/app/database.py
#
# SQLite persistence layer.
# Replaces the in-memory dict in SpecParser.
# Uses Python's built-in sqlite3 — no extra deps needed.

import sqlite3
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Store the DB file next to this file, or override via env var
import os
DB_PATH = os.getenv("SENTINEL_DB_PATH", str(Path(__file__).parent.parent / "sentinel.db"))


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row   # rows behave like dicts
    return conn


def init_db():
    """Create tables if they don't exist. Call once at startup."""
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'parsed',
                api_title   TEXT,
                api_version TEXT,
                endpoint_count INTEGER DEFAULT 0,
                original_spec  TEXT,   -- JSON blob
                parsed_data    TEXT,   -- JSON blob
                report         TEXT    -- JSON blob, set after agents run
            );

            CREATE INDEX IF NOT EXISTS idx_scans_created
                ON scans(created_at DESC);

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
        """)

        # Add new tables for users, scheduled scans, webhooks, and scan comparison
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id              TEXT PRIMARY KEY,
                email           TEXT UNIQUE NOT NULL,
                password_hash   TEXT NOT NULL,
                created_at      TEXT NOT NULL,
                last_login      TEXT,
                is_active       INTEGER DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS scheduled_scans (
                id                  TEXT PRIMARY KEY,
                user_id             TEXT NOT NULL,
                scan_name           TEXT NOT NULL,
                spec_id             TEXT,
                base_url            TEXT,
                auth_config         TEXT,
                interval_hours      INTEGER,
                enabled             INTEGER DEFAULT 1,
                last_run_at         TEXT,
                next_run_at         TEXT,
                alert_on_new_findings  INTEGER DEFAULT 1,
                webhook_url         TEXT,
                created_at          TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS webhooks (
                id              TEXT PRIMARY KEY,
                user_id         TEXT NOT NULL,
                name            TEXT NOT NULL,
                target_url      TEXT NOT NULL,
                secret          TEXT,
                event_types     TEXT,
                active          INTEGER DEFAULT 1,
                created_at      TEXT NOT NULL,
                last_triggered  TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS scan_comparison (
                id                  TEXT PRIMARY KEY,
                user_id             TEXT NOT NULL,
                scan_a_id           TEXT NOT NULL,
                scan_b_id           TEXT NOT NULL,
                created_at          TEXT NOT NULL,
                findings_resolved   INTEGER DEFAULT 0,
                findings_new        INTEGER DEFAULT 0,
                findings_worsened   INTEGER DEFAULT 0,
                score_improvement   REAL,
                comparison_data     TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (scan_a_id) REFERENCES scans(id),
                FOREIGN KEY (scan_b_id) REFERENCES scans(id)
            );

            CREATE INDEX IF NOT EXISTS idx_scheduled_scans_user ON scheduled_scans(user_id);
            CREATE INDEX IF NOT EXISTS idx_webhooks_user ON webhooks(user_id);
            CREATE INDEX IF NOT EXISTS idx_scan_comparison_user ON scan_comparison(user_id);
        """)

        # Add user_id column to existing scans table if it doesn't exist
        try:
            conn.execute("ALTER TABLE scans ADD COLUMN user_id TEXT")
        except sqlite3.OperationalError:
            pass  # column already exists


# ── CRUD helpers ──────────────────────────────────────────────────

def save_scan(
    name: str,
    original_spec: dict,
    parsed_data: dict,
    user_id: str = None,
) -> str:
    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    with get_conn() as conn:
        conn.execute(
            """INSERT INTO scans
               (id, name, created_at, status, api_title, api_version,
                endpoint_count, original_spec, parsed_data, user_id)
               VALUES (?, ?, ?, 'parsed', ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                name,
                now,
                parsed_data.get("title", "Unnamed API"),
                parsed_data.get("version", ""),
                parsed_data.get("total_endpoints", 0),
                json.dumps(original_spec),
                json.dumps(parsed_data),
                user_id,
            )
        )
    return scan_id


def get_scan(scan_id: str) -> Optional[dict]:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()

    if not row:
        return None

    return _deserialise(row)


def save_report(scan_id: str, report: dict):
    """Attach a completed report to an existing scan row."""
    with get_conn() as conn:
        conn.execute(
            "UPDATE scans SET report = ?, status = 'completed' WHERE id = ?",
            (json.dumps(report), scan_id)
        )


def list_scans(limit: int = 50, user_id: str = None) -> list[dict]:
    """Return recent scans, most recent first, without the heavy JSON blobs."""
    with get_conn() as conn:
        if user_id:
            rows = conn.execute(
                """SELECT id, name, created_at, status, api_title,
                          api_version, endpoint_count
                   FROM scans
                   WHERE user_id = ?
                   ORDER BY created_at DESC
                   LIMIT ?""",
                (user_id, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT id, name, created_at, status, api_title,
                          api_version, endpoint_count
                   FROM scans
                   ORDER BY created_at DESC
                   LIMIT ?""",
                (limit,)
            ).fetchall()

    return [dict(r) for r in rows]


def delete_scan(scan_id: str, user_id: str = None) -> bool:
    with get_conn() as conn:
        if user_id:
            cur = conn.execute("DELETE FROM scans WHERE id = ? AND user_id = ?", (scan_id, user_id))
        else:
            cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    return cur.rowcount > 0


def log_agent_run(scan_id: str, agent_name: str, status: str, summary: str = "") -> None:
    """Insert an agent log entry."""
    now = datetime.now(timezone.utc).isoformat()
    log_id = str(uuid.uuid4())
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO agent_logs
               (id, scan_id, agent_name, status, started_at, completed_at, result_summary)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (log_id, scan_id, agent_name, status, now, now, summary)
        )


# ── User helpers ──────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    from passlib.context import CryptContext
    pwd_ctx = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
    return pwd_ctx.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    from passlib.context import CryptContext
    pwd_ctx = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
    return pwd_ctx.verify(plain, hashed)


def create_user(email: str, password_hash: str) -> str:
    user_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO users (id, email, password_hash, created_at, is_active)
               VALUES (?, ?, ?, ?, 1)""",
            (user_id, email, password_hash, now)
        )
    return user_id


def get_user_by_email(email: str) -> Optional[dict]:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE email = ? AND is_active = 1", (email,)
        ).fetchone()
    return dict(row) if row else None


def get_user_by_id(user_id: str) -> Optional[dict]:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE id = ? AND is_active = 1", (user_id,)
        ).fetchone()
    return dict(row) if row else None


def update_last_login(user_id: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        conn.execute("UPDATE users SET last_login = ? WHERE id = ?", (now, user_id))


# ── Scheduled scan helpers ───────────────────────────────────────

def save_scheduled_scan(
    user_id: str,
    scan_name: str,
    spec_id: str,
    base_url: str,
    auth_config: dict,
    interval_hours: int,
    webhook_url: str,
    alert_on_new_findings: bool,
) -> str:
    schedule_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    next_run = datetime.now(timezone.utc).timestamp() + (interval_hours * 3600)
    next_run_at = datetime.fromtimestamp(next_run, tz=timezone.utc).isoformat()
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO scheduled_scans
               (id, user_id, scan_name, spec_id, base_url, auth_config,
                interval_hours, enabled, last_run_at, next_run_at,
                alert_on_new_findings, webhook_url, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 1, NULL, ?, ?, ?, ?)""",
            (schedule_id, user_id, scan_name, spec_id, base_url,
             json.dumps(auth_config), interval_hours, next_run_at,
             1 if alert_on_new_findings else 0, webhook_url, now)
        )
    return schedule_id


def get_scheduled_scans_for_user(user_id: str) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT * FROM scheduled_scans
               WHERE user_id = ? ORDER BY created_at DESC""",
            (user_id,)
        ).fetchall()
    results = []
    for row in rows:
        d = dict(row)
        if d.get("auth_config"):
            d["auth_config"] = json.loads(d["auth_config"])
        if d.get("event_types"):
            d["event_types"] = json.loads(d["event_types"])
        results.append(d)
    return results


def get_scheduled_scan(schedule_id: str) -> Optional[dict]:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM scheduled_scans WHERE id = ?", (schedule_id,)
        ).fetchone()
    if not row:
        return None
    d = dict(row)
    if d.get("auth_config"):
        d["auth_config"] = json.loads(d["auth_config"])
    return d


def update_scheduled_scan(schedule_id: str, **fields) -> None:
    allowed = ["scan_name", "spec_id", "base_url", "auth_config",
               "interval_hours", "enabled", "alert_on_new_findings", "webhook_url"]
    sets = []
    values = []
    for k, v in fields.items():
        if k in allowed:
            sets.append(f"{k} = ?")
            if k in ("auth_config",):
                values.append(json.dumps(v))
            elif k in ("enabled", "alert_on_new_findings", "interval_hours"):
                values.append(1 if v else 0)
            else:
                values.append(v)
    if not sets:
        return
    values.append(schedule_id)
    with get_conn() as conn:
        conn.execute(f"UPDATE scheduled_scans SET {', '.join(sets)} WHERE id = ?", values)


def update_scheduled_scan_run(schedule_id: str, next_run_at: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        conn.execute(
            "UPDATE scheduled_scans SET last_run_at = ?, next_run_at = ? WHERE id = ?",
            (now, next_run_at, schedule_id)
        )


def delete_scheduled_scan(schedule_id: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM scheduled_scans WHERE id = ?", (schedule_id,))
    return cur.rowcount > 0


def get_due_scheduled_scans() -> list[dict]:
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT * FROM scheduled_scans
               WHERE enabled = 1 AND next_run_at <= ?""",
            (now,)
        ).fetchall()
    results = []
    for row in rows:
        d = dict(row)
        if d.get("auth_config"):
            d["auth_config"] = json.loads(d["auth_config"])
        results.append(d)
    return results


# ── Webhook helpers ───────────────────────────────────────────────

def save_webhook(
    user_id: str,
    name: str,
    target_url: str,
    secret: str,
    event_types: list[str],
) -> str:
    webhook_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO webhooks
               (id, user_id, name, target_url, secret, event_types, active, created_at)
               VALUES (?, ?, ?, ?, ?, ?, 1, ?)""",
            (webhook_id, user_id, name, target_url, secret,
             json.dumps(event_types), now)
        )
    return webhook_id


def get_webhooks_for_user(user_id: str) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM webhooks WHERE user_id = ? AND active = 1 ORDER BY created_at DESC",
            (user_id,)
        ).fetchall()
    results = []
    for row in rows:
        d = dict(row)
        if d.get("event_types"):
            d["event_types"] = json.loads(d["event_types"])
        results.append(d)
    return results


def get_webhook(webhook_id: str) -> Optional[dict]:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM webhooks WHERE id = ? AND active = 1", (webhook_id,)
        ).fetchone()
    if not row:
        return None
    d = dict(row)
    if d.get("event_types"):
        d["event_types"] = json.loads(d["event_types"])
    return d


def delete_webhook(webhook_id: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE webhooks SET active = 0 WHERE id = ?", (webhook_id,)
        )
    return cur.rowcount > 0


def update_webhook_triggered(webhook_id: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        conn.execute(
            "UPDATE webhooks SET last_triggered = ? WHERE id = ?", (now, webhook_id)
        )


# ── Scan comparison helpers ────────────────────────────────────────

def save_scan_comparison(
    user_id: str,
    scan_a_id: str,
    scan_b_id: str,
    findings_resolved: int,
    findings_new: int,
    findings_worsened: int,
    score_improvement: float,
    comparison_data: dict,
) -> str:
    comparison_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO scan_comparison
               (id, user_id, scan_a_id, scan_b_id, created_at,
                findings_resolved, findings_new, findings_worsened,
                score_improvement, comparison_data)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (comparison_id, user_id, scan_a_id, scan_b_id, now,
             findings_resolved, findings_new, findings_worsened,
             score_improvement, json.dumps(comparison_data))
        )
    return comparison_id


def get_scan_comparison(comparison_id: str) -> Optional[dict]:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM scan_comparison WHERE id = ?", (comparison_id,)
        ).fetchone()
    if not row:
        return None
    d = dict(row)
    if d.get("comparison_data"):
        d["comparison_data"] = json.loads(d["comparison_data"])
    return d


def list_scan_comparisons_for_user(user_id: str) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT * FROM scan_comparison
               WHERE user_id = ? ORDER BY created_at DESC LIMIT 50""",
            (user_id,)
        ).fetchall()
    results = []
    for row in rows:
        d = dict(row)
        if d.get("comparison_data"):
            d["comparison_data"] = json.loads(d["comparison_data"])
        results.append(d)
    return results


# ── Internal ──────────────────────────────────────────────────────

def _deserialise(row: sqlite3.Row) -> dict:
    d = dict(row)
    for key in ("original_spec", "parsed_data", "report"):
        if d.get(key):
            d[key] = json.loads(d[key])
    return d
