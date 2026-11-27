<div align="center">
  <img src="EGOicon.png" alt="EGO Suite Logo" width="110" />
  <h1>EGO Suite</h1>
  <p><strong>Unified Open-Source AppSec &amp; Vulnerability Auditing Orchestrator for Linux</strong></p>
  <p>
    A portable, AI-ready local security auditing platform that unifies 20 open-source security tools into one dashboard and CLI — supporting live URLs (DAST), local project folders (SAST/SCA/Secrets/IaC), and direct GitHub repository scanning with consolidated reporting and Re-test diffing.
  </p>
</div>

---

## Key Features

- **Three Scanning Modes in One Place:**
  - **Live URL Scanning (`URL / DAST`):** Audit deployed websites and APIs without needing local source code.
  - **Local Project Scanning (`Local / SAST + SCA + Secrets + IaC`):** Analyze source code, dependencies, leaked secrets, and Docker/IaC configurations on your machine.
  - **GitHub Account Integration (`GitHub Mode`):** Connect your GitHub account via Personal Access Token, browse your public and private repositories, and shallow-clone (`git clone --depth 1`) any repo for automated scanning without storing credentials in `.git/config`.
- **AI Agent Collaboration (`AI-Ready CLI, API & Skill`):**
  - Ships with a ready-to-use Agent Skill ([skills/ego-suite/SKILL.md](skills/ego-suite/SKILL.md)) so AI coding assistants (such as Antigravity) can autonomously run scans, read structured AI-JSON reports, fix vulnerabilities in code, and re-test to verify closure.
  - Includes synchronous AI CLI commands (`ego scan --wait --json`, `ego report <id> --json`) and a dedicated HTTP endpoint (`GET /api/scans/{id}/ai-report`).
- **Portable Linux Self-Bootstrapper (`ego-setup.sh`):**
  - Installs isolated Python (`.venv/`), Node.js (`.node_tools/`), and standalone CLI binaries (`bin/`) inside the project folder so you can move and sync across multiple Linux machines effortlessly.
- **Live Progress Bar & ETA:**
  - Real-time per-tool execution tracking, percentage progress, elapsed time, and dynamic estimated time remaining (ETA).
- **Unified Schema & Re-test Diffing:**
  - Normalizes `SARIF` and `JSON` outputs into SQLite with unique finding fingerprints, automatically tracking `New`, `Open`, and `Fixed` issues across repeat scans.
- **Consolidated Reports & Management:**
  - Exportable **HTML** and **Markdown** reports, finding status management (`Open`, `In Progress`, `Fixed`, `False Positive`), and one-click report deletion.
- **Distinct Yellow & Black UI + Linux Desktop Entry:**
  - High-contrast Yellow & Black web dashboard (`http://127.0.0.1:8787`) with an installed Linux `.desktop` launcher and `EGOicon.png`.

---

## Integrated Open-Source Tools (20 Tools)

| Category | Tools | Purpose |
| :--- | :--- | :--- |
| **DAST (Live URLs)** | `ego-http-audit` (Built-in), `OWASP ZAP`, `Nuclei`, `testssl.sh`, `Nikto`, `Nmap`, `Wapiti`, `httpx` | HTTP security headers, TLS/SSL ciphers, open ports, and web vulnerability checks |
| **SAST (Source Code)** | `Semgrep`, `Bandit`, `ESLint Security`, `Bearer CLI`, `SonarScanner` | Static code analysis for insecure patterns and sensitive data flows |
| **SCA (Dependencies)** | `Trivy`, `OSV-Scanner`, `Retire.js`, `pip-audit & npm audit` | Known CVE detection across package lockfiles and JS libraries |
| **Secrets Scanning** | `Gitleaks`, `TruffleHog` | Detection of leaked API keys, tokens, and credentials |
| **IaC & Containers** | `Checkov` | Security misconfiguration checks for `Dockerfile`, `Terraform`, `Kubernetes`, and CI/CD |

---

## Quick Start on Linux

### 1. Clone & Run the Portable Installer
```bash
git clone https://github.com/richnessagencyteam-code/ego-suite.git
cd ego-suite
chmod +x ego ego-setup.sh
./ego-setup.sh
```
`ego-setup.sh` automatically creates `.venv/`, installs Python & Node.js tools, downloads portable Linux binaries into `bin/`, installs the global `ego` command in `~/.local/bin/ego`, registers the desktop launcher with `EGOicon.png`, and installs the AI Skill into `~/.gemini/config/skills/ego-suite/SKILL.md`.

*(Optional) Pull Docker images for container-based scanners (`owasp-zap` & `sonarqube-scanner`):*
```bash
sudo docker pull ghcr.io/zaproxy/zaproxy:stable
sudo docker pull sonarqube:community
```

### 2. Launch EGO Suite
From any directory in your terminal:
```bash
ego
```
Or launch in the background and open your browser automatically:
```bash
ego --open
```
Then open `http://127.0.0.1:8787` (or search for **EGO Suite** in your Linux application launcher).

---

## Updating Across Multiple Machines
Because runtime data (`data/`), virtual environments (`.venv/`, `.node_tools/`), and downloaded binaries (`bin/`) are excluded via `.gitignore`, you can update any of your Linux machines in one command without losing scan history or settings:
```bash
ego update
```

---

## AI Agent Collaboration (Autonomous Audit -> Fix -> Re-test)

**EGO Suite** is designed to work hand-in-hand with AI coding agents:

1. **Agent Skill Discovery:** [skills/ego-suite/SKILL.md](skills/ego-suite/SKILL.md) teaches AI agents how to check tool readiness, invoke scans, interpret `ai-report` output, and verify fixes.
2. **AI-Optimized CLI:**
   ```bash
   # List available tools as JSON
   ego tools --json

   # Run a scan, wait for completion, and output a structured AI-JSON report
   ego scan --name "My App" --path "/path/to/project" --wait --json

   # Scan a GitHub repository directly
   ego scan --name "My Repo" --repo "owner/repo" --wait --json

   # Fetch an AI-readable report for any previous scan
   ego report 1 --json
   ```
3. **AI-Report HTTP Endpoint:**
   - `GET /api/scans/{scan_id}/ai-report` returns `diff` (`total`, `open`, `new`, `fixed`), `severity_counts`, `tools_execution` status per tool, and `actionable_findings` sorted by severity (`Critical` -> `Info`) with exact `location` (`file:line` or `URL`) and `remediation` guidance.

---

## Project Structure

```text
ego-suite/
├── ego                  # Global launcher & updater (ego / ego --open / ego update / CLI)
├── ego-setup.sh         # Portable Linux bootstrapper & AI skill installer
├── requirements.txt     # Server dependencies (FastAPI, Uvicorn, Pydantic)
├── selected-tools.json  # Selected tool registry
├── tools-catalog.html   # Standalone interactive tools catalog
├── skills/
│   └── ego-suite/
│       └── SKILL.md     # AI Agent Skill definition
├── ego_suite/
│   ├── server.py        # FastAPI backend & REST API
│   ├── cli.py           # AI-ready CLI (scan, report, tools, list)
│   ├── orchestrator.py  # Scan planner, runner & live progress/ETA tracker
│   ├── adapters.py      # Tool adapters & built-in HTTP security audit
│   ├── normalizer.py    # SARIF / JSON normalizer & finding fingerprinting
│   ├── github_client.py # GitHub PAT integration & safe shallow-cloning
│   ├── reporter.py      # Consolidated HTML & Markdown report generator
│   └── db.py            # SQLite persistence & Re-test diff engine
└── web/
    └── index.html       # Yellow & Black Web Dashboard
```

---

## Responsible Use
EGO Suite is intended strictly for **defensive security auditing, code review, and testing websites or repositories that you own or have explicit authorization to test**.

---

## License
Licensed under the [MIT License](LICENSE). External security scanners are invoked as independent tools and remain subject to their respective open-source licenses.
