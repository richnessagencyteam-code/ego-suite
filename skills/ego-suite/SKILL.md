---
name: ego-suite
description: Run defensive security audits, SAST/DAST/SCA/Secret scans, and interpret AI-readable vulnerability reports using EGO Suite (`ego` CLI or HTTP API). Activate when the user asks an AI agent to scan a website URL, local project folder, or GitHub repository, analyze findings, fix vulnerabilities, and re-test to verify fixes.
---

# EGO Suite — AI Agent Security Auditing Skill

Use this skill to autonomously run security scans with **EGO Suite**, parse its structured AI-JSON reports, remediate findings in code, and re-test to verify fixes.

## Prerequisites & Safety
- Only scan websites, repositories, or local projects owned by the user or explicitly authorized for testing.
- Never attempt destructive exploitation; EGO Suite runs safe, defensive auditing tools.

## 1. Check Available Tools
Before running a scan, verify which tools are installed:
```bash
ego tools --json
```
Or via the local HTTP API (when the server is running on `http://127.0.0.1:8787`):
```bash
curl -s http://127.0.0.1:8787/api/tools
```

## 2. Run a Security Scan (Synchronous AI Mode)
Use `--wait --json` so the command blocks until completion and returns the full AI-readable JSON report directly:

- **Live URL (DAST + Headers + TLS + Ports):**
  ```bash
  ego scan --name "My Site" --url "https://example.com" --wait --json
  ```
- **Local Project (SAST + SCA + Secrets + IaC):**
  ```bash
  ego scan --name "My Project" --path "/path/to/project" --wait --json
  ```
- **GitHub Repository (requires GitHub linked in EGO Suite):**
  ```bash
  ego scan --name "My Repo" --repo "owner/repo" --wait --json
  ```
- **Combined (URL + Local/GitHub) or Specific Tools:**
  ```bash
  ego scan --name "Full Audit" --url "https://example.com" --path "/path/to/project" --tools "ego-http-audit,semgrep,trivy,gitleaks" --wait --json
  ```

### Alternative: HTTP API (Asynchronous)
- Start scan: `POST http://127.0.0.1:8787/api/scans` with JSON `{ "project_name", "target_url", "local_path", "github_repo", "tools" }`.
- Poll progress & ETA: `GET http://127.0.0.1:8787/api/scans/<scan_id>` (`progress.percent`, `progress.eta_seconds`).
- Fetch AI report: `GET http://127.0.0.1:8787/api/scans/<scan_id>/ai-report`.

## 3. How to Interpret the AI Report (`ai-report`)
The JSON output contains:
- `status`: `"completed"` or `"failed"`.
- `diff`: `{ "total", "open", "new", "fixed" }` — shows progress compared to the previous scan of the same project.
- `severity_counts`: breakdown of `Critical`, `High`, `Medium`, `Low`, `Info`.
- `tools_execution`: per-tool execution status (`ok (N findings)` vs `skipped`). Always verify the intended tools ran with `ok`.
- `actionable_findings`: ordered list of findings (`Critical` first), each with:
  - `id`, `severity`, `status`, `category`, `tool`
  - `title`, `location` (`file:line` or `URL`), `description`, `remediation`

## 4. Recommended AI Fix & Re-test Workflow
1. Run `ego scan ... --wait --json`.
2. Inspect `tools_execution` to confirm the expected scanners ran.
3. Group `actionable_findings` by `Critical` and `High` severity first.
4. For local/GitHub projects, open the exact `location` (`file:line`), apply the minimal secure fix following `remediation`, and avoid breaking existing functionality.
5. Re-run the exact same `ego scan` command with `--wait --json` and verify that `diff.fixed` increased and the resolved findings no longer appear in `actionable_findings`.
6. Summarize the results concisely for the user, including `scan_id`, what was fixed, and any remaining `Medium`/`Low` items.

