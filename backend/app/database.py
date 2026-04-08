# backend/app/database.py
#
# SQLite persistence layer.
# Replaces the in-memory dict in SpecParser.
# Uses Python's built-in sqlite3 — no extra deps needed.

import sqlite3
import json
import uuid
from datetime import datetime
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
        """)


# ── CRUD helpers ──────────────────────────────────────────────────

def save_scan(
    name: str,
    original_spec: dict,
    parsed_data: dict,
) -> str:
    scan_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()

    with get_conn() as conn:
        conn.execute(
            """INSERT INTO scans
               (id, name, created_at, status, api_title, api_version,
                endpoint_count, original_spec, parsed_data)
               VALUES (?, ?, ?, 'parsed', ?, ?, ?, ?, ?)""",
            (
                scan_id,
                name,
                now,
                parsed_data.get("title", "Unnamed API"),
                parsed_data.get("version", ""),
                parsed_data.get("total_endpoints", 0),
                json.dumps(original_spec),
                json.dumps(parsed_data),
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


def list_scans(limit: int = 50) -> list[dict]:
    """Return recent scans, most recent first, without the heavy JSON blobs."""
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT id, name, created_at, status, api_title,
                      api_version, endpoint_count
               FROM scans
               ORDER BY created_at DESC
               LIMIT ?""",
            (limit,)
        ).fetchall()

    return [dict(r) for r in rows]


def delete_scan(scan_id: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    return cur.rowcount > 0


# ── Internal ──────────────────────────────────────────────────────

def _deserialise(row: sqlite3.Row) -> dict:
    d = dict(row)
    for key in ("original_spec", "parsed_data", "report"):
        if d.get(key):
            d[key] = json.loads(d[key])
    return d