"""Scan Orchestrator for EGO Suite (URL Mode, Local Mode, or Both)."""

from __future__ import annotations

import json
import threading
import time
from typing import Any

from .adapters import execute_tool, get_tools_status
from .db import create_scan_run, finish_scan_run, get_or_create_project, save_findings
from .github_client import clone_repo_for_scan
from .reporter import generate_reports

SCAN_PROGRESS: dict[int, dict[str, Any]] = {}


def get_scan_progress(scan_id: int) -> dict[str, Any] | None:
    """Return live progress and ETA for an active scan."""
    prog = SCAN_PROGRESS.get(scan_id)
    if not prog:
        return None
    elapsed = max(0.1, time.monotonic() - prog["start_ts"])
    total = max(1, prog["total_steps"])
    done = prog["completed_steps"]
    if done > 0:
        eta = round((elapsed / done) * (total - done))
    else:
        eta = total * 6
    pct = 100 if done >= total else max(5, int((done / total) * 100))
    return {
        "percent": pct,
        "completed_steps": done,
        "total_steps": total,
        "current_tool": prog["current_tool"],
        "elapsed_seconds": round(elapsed),
        "eta_seconds": max(0, eta),
        "tools": dict(prog["tools"]),
    }


def _run_scan_worker(
    scan_id: int,
    project_id: int,
    project_name: str,
    target_url: str,
    local_path: str,
    tool_ids: list[str],
    github_repo: str = "",
    stack: str = "general",
) -> None:
    all_findings: list[dict[str, Any]] = []
    tool_logs: dict[str, str] = {}
    has_gh = bool(github_repo and not local_path)
    total_steps = len(tool_ids) + (1 if has_gh else 0)

    SCAN_PROGRESS[scan_id] = {
        "start_ts": time.monotonic(),
        "total_steps": max(1, total_steps),
        "completed_steps": 0,
        "current_tool": "github-sync" if has_gh else (tool_ids[0] if tool_ids else "init"),
        "tools": tool_logs,
    }

    try:
        if has_gh:
            try:
                cloned = clone_repo_for_scan(github_repo)
                local_path = str(cloned)
                tool_logs["github-sync"] = f"cloned {github_repo}"
            except Exception as exc:  # noqa: BLE001
                tool_logs["github-sync"] = f"error: {exc}"
            SCAN_PROGRESS[scan_id]["completed_steps"] += 1

        for tid in tool_ids:
            SCAN_PROGRESS[scan_id]["current_tool"] = tid
            try:
                findings, status_note = execute_tool(tid, target_url, local_path, stack=stack)
                all_findings.extend(findings)
                tool_logs[tid] = f"{status_note} ({len(findings)} findings)"
            except Exception as exc:  # noqa: BLE001
                tool_logs[tid] = f"error: {exc}"
            SCAN_PROGRESS[scan_id]["completed_steps"] += 1

        diff_summary = save_findings(scan_id, project_id, all_findings)
        summary = {
            **diff_summary,
            "tools": tool_logs,
        }
        finish_scan_run(scan_id, "completed", json.dumps(summary, ensure_ascii=False))
        generate_reports(scan_id)
    except Exception as exc:  # noqa: BLE001
        finish_scan_run(scan_id, "failed", json.dumps({"error": str(exc)}, ensure_ascii=False))
    finally:
        SCAN_PROGRESS.pop(scan_id, None)


def start_scan(
    project_name: str,
    target_url: str = "",
    local_path: str = "",
    requested_tools: list[str] | None = None,
    github_repo: str = "",
    stack: str = "general",
) -> dict[str, Any]:
    """Plan and launch an asynchronous security scan."""
    target_url = target_url.strip()
    local_path = local_path.strip()
    github_repo = github_repo.strip()
    stack = stack if stack in ("general", "laravel", "wordpress") else "general"
    has_local = bool(local_path or github_repo)

    if target_url and has_local:
        mode = "both"
    elif target_url:
        mode = "url"
    else:
        mode = "local"

    installed_tools = get_tools_status()
    if requested_tools:
        tool_ids = list(requested_tools)
    else:
        tool_ids = [
            t["id"]
            for t in installed_tools
            if t["installed"]
            and t["id"] not in ("ego-laravel-audit", "ego-wp-audit")
            and (
                mode == "both"
                or t.get("mode") == mode
                or t.get("mode") == "both"
            )
        ]

    if mode in ("url", "both") and "ego-http-audit" not in tool_ids:
        tool_ids.insert(0, "ego-http-audit")

    if stack == "laravel":
        for lt in ("ego-laravel-audit", "composer-audit"):
            if lt not in tool_ids:
                tool_ids.insert(0, lt)
    elif stack == "wordpress":
        if "ego-wp-audit" not in tool_ids:
            tool_ids.insert(0, "ego-wp-audit")

    project_id = get_or_create_project(project_name, target_url, local_path or (f"github:{github_repo}" if github_repo else ""))
    scan_id = create_scan_run(project_id, mode, tool_ids, stack=stack)

    thread = threading.Thread(
        target=_run_scan_worker,
        args=(scan_id, project_id, project_name, target_url, local_path, tool_ids, github_repo, stack),
        daemon=True,
    )
    thread.start()

    return {
        "scan_id": scan_id,
        "project_id": project_id,
        "mode": mode,
        "stack": stack,
        "tools": tool_ids,
        "status": "running",
    }

