"""SQLite persistence and Re-test Diff Engine for EGO Suite."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any

from .config import DB_PATH, ensure_directories


def _connect() -> sqlite3.Connection:
    ensure_directories()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db() -> None:
    """Initialize SQLite tables for projects, scan runs, and findings."""
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                target_url TEXT DEFAULT '',
                local_path TEXT DEFAULT '',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scan_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                mode TEXT NOT NULL,
                stack TEXT NOT NULL DEFAULT 'general',
                tools_used TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT DEFAULT '',
                summary_json TEXT DEFAULT '{}',
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                project_id INTEGER NOT NULL,
                fingerprint TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                source_tool TEXT NOT NULL,
                location TEXT NOT NULL,
                description TEXT NOT NULL,
                remediation TEXT DEFAULT '',
                status TEXT NOT NULL DEFAULT 'Open',
                FOREIGN KEY (scan_id) REFERENCES scan_runs(id) ON DELETE CASCADE,
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(project_id, fingerprint);
            """
        )
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(scan_runs)").fetchall()}
        if "stack" not in cols:
            conn.execute("ALTER TABLE scan_runs ADD COLUMN stack TEXT NOT NULL DEFAULT 'general'")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_or_create_project(name: str, target_url: str = "", local_path: str = "") -> int:
    with _connect() as conn:
        row = conn.execute(
            "SELECT id FROM projects WHERE target_url = ? AND local_path = ?",
            (target_url.strip(), local_path.strip()),
        ).fetchone()
        if row:
            return int(row["id"])
        cur = conn.execute(
            "INSERT INTO projects (name, target_url, local_path, created_at) VALUES (?, ?, ?, ?)",
            (name.strip() or "Unnamed Project", target_url.strip(), local_path.strip(), now_iso()),
        )
        return int(cur.lastrowid)


def create_scan_run(project_id: int, mode: str, tools_used: list[str], stack: str = "general") -> int:
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO scan_runs (project_id, mode, stack, tools_used, status, started_at) VALUES (?, ?, ?, ?, ?, ?)",
            (project_id, mode, stack, ",".join(tools_used), "running", now_iso()),
        )
        return int(cur.lastrowid)


def finish_scan_run(scan_id: int, status: str, summary_json: str) -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE scan_runs SET status = ?, finished_at = ?, summary_json = ? WHERE id = ?",
            (status, now_iso(), summary_json, scan_id),
        )


def save_findings(scan_id: int, project_id: int, findings: list[dict[str, Any]]) -> dict[str, int]:
    """Save normalized findings and compute Re-test Diff against previous scan."""
    with _connect() as conn:
        prev_scan = conn.execute(
            "SELECT id FROM scan_runs WHERE project_id = ? AND id < ? AND status = 'completed' ORDER BY id DESC LIMIT 1",
            (project_id, scan_id),
        ).fetchone()

        prev_fps: set[str] = set()
        if prev_scan:
            rows = conn.execute(
                "SELECT DISTINCT fingerprint FROM findings WHERE scan_id = ?",
                (prev_scan["id"],),
            ).fetchall()
            prev_fps = {r["fingerprint"] for r in rows}

        current_fps: set[str] = set()
        new_count = 0
        open_count = 0

        for item in findings:
            fp = item["fingerprint"]
            current_fps.add(fp)
            if prev_scan:
                state = "Open" if fp in prev_fps else "New"
                if state == "New":
                    new_count += 1
                else:
                    open_count += 1
            else:
                state = "Open"
                open_count += 1

            conn.execute(
                """
                INSERT INTO findings
                (scan_id, project_id, fingerprint, title, severity, category, source_tool, location, description, remediation, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    project_id,
                    fp,
                    item["title"],
                    item["severity"],
                    item["category"],
                    item["source_tool"],
                    item["location"],
                    item["description"],
                    item.get("remediation", ""),
                    state,
                ),
            )

        fixed_fps = prev_fps - current_fps if prev_scan else set()
        return {
            "total": len(findings),
            "open": open_count,
            "new": new_count,
            "fixed": len(fixed_fps),
        }


def list_scans() -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT s.*, p.name AS project_name, p.target_url, p.local_path
            FROM scan_runs s
            JOIN projects p ON p.id = s.project_id
            ORDER BY s.id DESC
            LIMIT 50
            """
        ).fetchall()
        return [dict(r) for r in rows]


def get_scan_detail(scan_id: int) -> dict[str, Any] | None:
    with _connect() as conn:
        scan = conn.execute(
            """
            SELECT s.*, p.name AS project_name, p.target_url, p.local_path
            FROM scan_runs s
            JOIN projects p ON p.id = s.project_id
            WHERE s.id = ?
            """,
            (scan_id,),
        ).fetchone()
        if not scan:
            return None
        findings = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END, id ASC",
            (scan_id,),
        ).fetchall()
        return {"scan": dict(scan), "findings": [dict(f) for f in findings]}


def update_finding_status(finding_id: int, status: str) -> bool:
    allowed = {"Open", "In Progress", "Fixed", "False Positive", "New"}
    if status not in allowed:
        return False
    with _connect() as conn:
        cur = conn.execute("UPDATE findings SET status = ? WHERE id = ?", (status, finding_id))
        return cur.rowcount > 0


def delete_scan(scan_id: int) -> bool:
    with _connect() as conn:
        cur = conn.execute("DELETE FROM scan_runs WHERE id = ?", (scan_id,))
        return cur.rowcount > 0


def get_dashboard_stats() -> dict[str, Any]:
    with _connect() as conn:
        projects_count = conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0]
        scans_count = conn.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0]
        latest = conn.execute("SELECT id, summary_json FROM scan_runs WHERE status = 'completed' ORDER BY id DESC LIMIT 1").fetchone()
        sev_rows = conn.execute(
            """
            SELECT severity, COUNT(*) AS cnt
            FROM findings
            WHERE scan_id = (SELECT id FROM scan_runs WHERE status = 'completed' ORDER BY id DESC LIMIT 1)
            GROUP BY severity
            """
        ).fetchall()
        return {
            "projects": projects_count,
            "scans": scans_count,
            "latest_summary": latest["summary_json"] if latest else "{}",
            "severity_breakdown": {r["severity"]: r["cnt"] for r in sev_rows},
        }

