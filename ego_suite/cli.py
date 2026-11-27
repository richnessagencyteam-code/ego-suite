"""AI-friendly CLI interface for EGO Suite."""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any

from .adapters import get_tools_status
from .db import get_scan_detail, init_db, list_scans
from .orchestrator import get_scan_progress, start_scan


def build_ai_report(scan_id: int) -> dict[str, Any] | None:
    """Build a compact, structured, AI-readable report for a scan."""
    detail = get_scan_detail(scan_id)
    if not detail:
        return None
    scan = detail["scan"]
    findings = detail["findings"]
    try:
        summary = json.loads(scan.get("summary_json") or "{}")
    except json.JSONDecodeError:
        summary = {}

    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = f["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "scan_id": scan["id"],
        "project_name": scan["project_name"],
        "mode": scan["mode"],
        "status": scan["status"],
        "target_url": scan["target_url"],
        "local_path": scan["local_path"],
        "diff": {
            "total": summary.get("total", len(findings)),
            "open": summary.get("open", 0),
            "new": summary.get("new", 0),
            "fixed": summary.get("fixed", 0),
        },
        "severity_counts": severity_counts,
        "tools_execution": summary.get("tools", {}),
        "actionable_findings": [
            {
                "id": f["id"],
                "severity": f["severity"],
                "status": f["status"],
                "category": f["category"],
                "tool": f["source_tool"],
                "title": f["title"],
                "location": f["location"],
                "description": f["description"],
                "remediation": f["remediation"],
            }
            for f in findings
        ],
    }


def main(argv: list[str] | None = None) -> int:
    init_db()
    parser = argparse.ArgumentParser(prog="ego", description="EGO Suite AI-ready CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_tools = sub.add_parser("tools", help="List available tools and status")
    p_tools.add_argument("--json", action="store_true", help="Output JSON")

    p_scan = sub.add_parser("scan", help="Run a security scan")
    p_scan.add_argument("--name", required=True, help="Project name")
    p_scan.add_argument("--url", default="", help="Target live URL")
    p_scan.add_argument("--path", default="", help="Local project path")
    p_scan.add_argument("--repo", default="", help="GitHub repo (owner/repo)")
    p_scan.add_argument("--stack", default="general", choices=["general", "laravel", "wordpress"], help="Target framework stack")
    p_scan.add_argument("--tools", default="", help="Comma-separated tool IDs")
    p_scan.add_argument("--wait", action="store_true", help="Wait for scan completion")
    p_scan.add_argument("--json", action="store_true", help="Output AI-friendly JSON")

    p_rep = sub.add_parser("report", help="Fetch scan report")
    p_rep.add_argument("scan_id", type=int, help="Scan ID")
    p_rep.add_argument("--json", action="store_true", help="Output AI-friendly JSON")

    p_list = sub.add_parser("list", help="List recent scans")
    p_list.add_argument("--json", action="store_true", help="Output JSON")

    args = parser.parse_args(argv)

    if args.command == "tools":
        tools = get_tools_status()
        if args.json:
            print(json.dumps({"tools": tools}, ensure_ascii=False, indent=2))
        else:
            for t in tools:
                state = "READY" if t["installed"] else "MISSING"
                print(f"[{state}] {t['id']} ({t['category']} | {t['mode']})")
        return 0

    if args.command == "list":
        scans = list_scans()
        if args.json:
            print(json.dumps({"scans": scans}, ensure_ascii=False, indent=2))
        else:
            for s in scans:
                print(f"#{s['id']} | {s['project_name']} | {s['mode']} | {s['status']}")
        return 0

    if args.command == "scan":
        if not args.url and not args.path and not args.repo:
            print("Error: provide --url, --path, or --repo", file=sys.stderr)
            return 1
        req_tools = [x.strip() for x in args.tools.split(",") if x.strip()] or None
        res = start_scan(args.name, args.url, args.path, req_tools, args.repo, args.stack)
        scan_id = res["scan_id"]

        if args.wait:
            while True:
                detail = get_scan_detail(scan_id)
                if detail and detail["scan"]["status"] != "running":
                    break
                _ = get_scan_progress(scan_id)
                time.sleep(1.0)
            report = build_ai_report(scan_id)
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return 0

        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0

    if args.command == "report":
        report = build_ai_report(args.scan_id)
        if not report:
            print(json.dumps({"error": "Scan not found"}))
            return 1
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

