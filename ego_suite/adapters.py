"""Tool registry, healthchecks, safe runners, and installers for EGO Suite."""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .config import BIN_DIR, NODE_BIN_DIR, VENV_BIN_DIR, load_selected_tools
from .normalizer import make_finding, parse_bandit_json, parse_nuclei_jsonl, parse_sarif


def _find_binary(name: str) -> str | None:
    """Locate a tool binary in portable dirs first, then system PATH."""
    for folder in (BIN_DIR, VENV_BIN_DIR, NODE_BIN_DIR):
        candidate = folder / name
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    return shutil.which(name)


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _docker_image_present(image: str) -> bool:
    if not _docker_available():
        return False
    res = subprocess.run(
        ["docker", "image", "inspect", image],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return res.returncode == 0


TOOL_SPECS: dict[str, dict[str, Any]] = {
    "ego-http-audit": {"bin": "builtin", "category": "DAST", "mode": "url", "builtin": True},
    "ego-laravel-audit": {"bin": "builtin", "category": "SAST/DAST", "mode": "both", "builtin": True},
    "ego-wp-audit": {"bin": "builtin", "category": "SAST/DAST", "mode": "both", "builtin": True},
    "composer-audit": {"bin": "composer", "category": "SCA", "mode": "local"},
    "wpscan": {"bin": "wpscan", "docker": "wpscanteam/wpscan:latest", "category": "DAST", "mode": "url"},
    "owasp-zap": {"bin": "zaproxy", "docker": "ghcr.io/zaproxy/zaproxy:stable", "category": "DAST", "mode": "url"},
    "nuclei": {"bin": "nuclei", "category": "DAST", "mode": "url"},
    "testssl": {"bin": "testssl.sh", "category": "DAST", "mode": "url"},
    "nikto": {"bin": "nikto", "category": "DAST", "mode": "url"},
    "nmap": {"bin": "nmap", "category": "DAST", "mode": "url"},
    "wapiti": {"bin": "wapiti", "category": "DAST", "mode": "url"},
    "httpx-headers": {"bin": "httpx", "category": "DAST", "mode": "url"},
    "semgrep": {"bin": "semgrep", "category": "SAST", "mode": "local"},
    "bandit": {"bin": "bandit", "category": "SAST", "mode": "local"},
    "eslint-security": {"bin": "eslint", "category": "SAST", "mode": "local"},
    "bearer": {"bin": "bearer", "category": "SAST", "mode": "local"},
    "sonarqube-scanner": {"bin": "sonar-scanner", "docker": "sonarqube:community", "category": "SAST", "mode": "local"},
    "trivy": {"bin": "trivy", "docker": "aquasec/trivy:latest", "category": "SCA", "mode": "local"},
    "osv-scanner": {"bin": "osv-scanner", "category": "SCA", "mode": "local"},
    "retirejs": {"bin": "retire", "category": "SCA", "mode": "both"},
    "pip-npm-audit": {"bin": "pip-audit", "category": "SCA", "mode": "local"},
    "gitleaks": {"bin": "gitleaks", "docker": "zricethezav/gitleaks:latest", "category": "Secrets", "mode": "local"},
    "trufflehog": {"bin": "trufflehog", "docker": "trufflesecurity/trufflehog:latest", "category": "Secrets", "mode": "local"},
    "checkov": {"bin": "checkov", "category": "IaC", "mode": "local"},
}


def get_tools_status() -> list[dict[str, Any]]:
    """Return all selected tools with live installation status."""
    selected = load_selected_tools()
    results: list[dict[str, Any]] = [
        {
            "id": "ego-http-audit",
            "name": "EGO Built-in HTTP & Security Headers Audit",
            "category": "DAST",
            "mode": "url",
            "installed": True,
            "runtime": "Built-in Python",
            "installCmd": "مدمج تلقائياً",
            "repoUrl": "",
        },
        {
            "id": "ego-laravel-audit",
            "name": "EGO Built-in Laravel Security Auditor",
            "category": "SAST/DAST",
            "mode": "both",
            "installed": True,
            "runtime": "Built-in Python (Laravel)",
            "installCmd": "مدمج تلقائياً",
            "repoUrl": "",
        },
        {
            "id": "ego-wp-audit",
            "name": "EGO Built-in WordPress Security Auditor",
            "category": "SAST/DAST",
            "mode": "both",
            "installed": True,
            "runtime": "Built-in Python (WordPress)",
            "installCmd": "مدمج تلقائياً",
            "repoUrl": "",
        },
    ]
    for tool in selected:
        tid = tool["id"]
        spec = TOOL_SPECS.get(tid, {})
        bin_name = spec.get("bin", tid)
        bin_path = _find_binary(bin_name)
        docker_img = spec.get("docker")
        has_docker = bool(docker_img and _docker_image_present(docker_img))

        if tid == "testssl" and not bin_path:
            local_testssl = BIN_DIR / "testssl.sh" / "testssl.sh"
            if local_testssl.exists():
                bin_path = str(local_testssl)

        if tid == "nikto" and not bin_path:
            local_nikto = BIN_DIR / "nikto" / "program" / "nikto.pl"
            if local_nikto.exists():
                bin_path = str(local_nikto)

        installed = bool(bin_path or has_docker)
        runtime = bin_path if bin_path else (f"Docker ({docker_img})" if has_docker else "غير مثبت")
        results.append(
            {
                **tool,
                "installed": installed,
                "runtime": runtime,
            }
        )
    return results


def install_tool(tool_id: str) -> dict[str, Any]:
    """Install a single tool into EGO Suite's portable workspace."""
    pip_bin = str(VENV_BIN_DIR / "pip") if (VENV_BIN_DIR / "pip").exists() else "pip3"
    npm_bin = shutil.which("npm")

    pip_packages = {
        "semgrep": "semgrep",
        "bandit": "bandit",
        "wapiti": "wapiti3",
        "checkov": "checkov",
        "pip-npm-audit": "pip-audit",
    }
    if tool_id in pip_packages:
        proc = subprocess.run(
            [pip_bin, "install", "--quiet", pip_packages[tool_id]],
            capture_output=True,
            text=True,
            check=False,
        )
        return {"ok": proc.returncode == 0, "output": (proc.stdout + "\n" + proc.stderr).strip()}

    if tool_id in ("eslint-security", "retirejs") and npm_bin:
        prefix = str(BIN_DIR.parent / ".node_tools")
        pkg = "retire" if tool_id == "retirejs" else "eslint eslint-plugin-security"
        proc = subprocess.run(
            f"{npm_bin} install --prefix {prefix} {pkg}",
            shell=True,
            capture_output=True,
            text=True,
            check=False,
        )
        return {"ok": proc.returncode == 0, "output": (proc.stdout + "\n" + proc.stderr).strip()}

    if tool_id == "testssl":
        dest = BIN_DIR / "testssl.sh"
        if dest.exists():
            return {"ok": True, "output": "testssl.sh already present"}
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", "https://github.com/drwetter/testssl.sh.git", str(dest)],
            capture_output=True,
            text=True,
            check=False,
        )
        return {"ok": proc.returncode == 0, "output": (proc.stdout + "\n" + proc.stderr).strip()}

    spec = TOOL_SPECS.get(tool_id, {})
    if spec.get("docker") and _docker_available():
        proc = subprocess.run(
            ["docker", "pull", spec["docker"]],
            capture_output=True,
            text=True,
            check=False,
        )
        return {"ok": proc.returncode == 0, "output": (proc.stdout + "\n" + proc.stderr).strip()}

    return {
        "ok": False,
        "output": f"Run ./ego-setup.sh or install '{tool_id}' manually for your OS ({platform.machine()}).",
    }


def run_builtin_http_audit(url: str) -> list[dict[str, Any]]:
    """Safe, read-only HTTP security headers & transport audit."""
    findings: list[dict[str, Any]] = []
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme == "http":
        findings.append(
            make_finding(
                title="Site uses unencrypted HTTP instead of HTTPS",
                severity="High",
                category="DAST",
                source_tool="ego-http-audit",
                location=url,
                description="الاتصال يتم عبر HTTP غير المشفر، مما يعرض البيانات والتوكنات للاعتراض.",
                remediation="قم بتفعيل HTTPS وإعادة توجيه كافة طلبات HTTP تلقائياً إلى HTTPS.",
            )
        )

    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "EGO-Suite-Auditor/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.URLError as exc:
        findings.append(
            make_finding(
                title="Target URL unreachable during HTTP audit",
                severity="Info",
                category="DAST",
                source_tool="ego-http-audit",
                location=url,
                description=f"تعذر الوصول إلى الرابط: {exc.reason}",
                remediation="تأكد من أن الموقع يعمل ومتاح من الشبكة المحلية.",
            )
        )
        return findings

    required_headers = [
        ("strict-transport-security", "Missing HSTS Header (Strict-Transport-Security)", "Medium", "أضف ترويسة Strict-Transport-Security: max-age=31536000; includeSubDomains"),
        ("content-security-policy", "Missing Content-Security-Policy (CSP)", "Medium", "أضف سياسة CSP لتقليل مخاطر هجمات XSS."),
        ("x-content-type-options", "Missing X-Content-Type-Options Header", "Low", "أضف X-Content-Type-Options: nosniff"),
        ("x-frame-options", "Missing X-Frame-Options / Clickjacking Protection", "Low", "أضف X-Frame-Options: DENY أو SAMEORIGIN (أو frame-ancestors في CSP)."),
        ("referrer-policy", "Missing Referrer-Policy Header", "Info", "أضف Referrer-Policy: strict-origin-when-cross-origin"),
    ]
    for h_key, title, sev, fix in required_headers:
        if h_key not in headers:
            findings.append(
                make_finding(
                    title=title,
                    severity=sev,
                    category="DAST",
                    source_tool="ego-http-audit",
                    location=url,
                    description=f"الترويسة الأمنية `{h_key}` غير موجودة في استجابة الخادم.",
                    remediation=fix,
                )
            )

    if headers.get("access-control-allow-origin") == "*":
        findings.append(
            make_finding(
                title="Wildcard CORS Policy (Access-Control-Allow-Origin: *)",
                severity="Medium",
                category="DAST",
                source_tool="ego-http-audit",
                location=url,
                description="الخادم يسمح بالوصول عبر CORS من أي نطاق خارجي.",
                remediation="قصر Access-Control-Allow-Origin على النطاقات الموثوقة فقط.",
            )
        )

    if "server" in headers or "x-powered-by" in headers:
        disclosed = ", ".join(f"{k}: {headers[k]}" for k in ("server", "x-powered-by") if k in headers)
        findings.append(
            make_finding(
                title="Server Technology Banner Disclosed",
                severity="Info",
                category="DAST",
                source_tool="ego-http-audit",
                location=url,
                description=f"يكشف الخادم عن تفاصيل التقنية المستخدمة ({disclosed}).",
                remediation="أخفِ ترويسة X-Powered-By وقلّل تفاصيل Server في إعدادات الخادم.",
            )
        )

    return findings


def _probe_url(url: str) -> tuple[int, str, dict[str, str]]:
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "EGO-Suite-Auditor/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = resp.read(8192).decode("utf-8", errors="replace")
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, body, headers
    except urllib.error.HTTPError as exc:
        return exc.code, "", {}
    except urllib.error.URLError:
        return 0, "", {}


def run_builtin_laravel_audit(target_url: str, local_path: str) -> list[dict[str, Any]]:
    """Safe, read-only Laravel security audit for live URLs and local projects."""
    findings: list[dict[str, Any]] = []
    if target_url:
        base = target_url.rstrip("/")
        checks = [
            ("/.env", "Exposed Laravel .env File", "Critical", "APP_KEY", "امنع الوصول إلى ملف .env عبر إعدادات Nginx/Apache فوراً وقم بتدوير المفاتيح."),
            ("/_ignition/health-check", "Laravel Ignition Debug Endpoint Exposed", "High", "", "عطّل APP_DEBUG في الإنتاج وأغلق مسارات Ignition."),
            ("/telescope", "Laravel Telescope Dashboard Exposed", "Medium", "Telescope", "قصر الوصول إلى Telescope على بيئة local أو بصلاحيات مشرفين."),
            ("/horizon", "Laravel Horizon Dashboard Exposed", "Medium", "Horizon", "فعّل Horizon::auth() لحماية لوحة Horizon في الإنتاج."),
            ("/storage/logs/laravel.log", "Exposed Laravel Log File", "High", "Stack trace", "احفظ السجلات خارج public/ أو امنع الوصول إلى /storage/logs/."),
        ]
        for path, title, sev, marker, fix in checks:
            status, body, _ = _probe_url(base + path)
            if status == 200 and (not marker or marker.lower() in body.lower()):
                findings.append(
                    make_finding(
                        title=title,
                        severity=sev,
                        category="DAST",
                        source_tool="ego-laravel-audit",
                        location=base + path,
                        description=f"المسار الحساس `{path}` متاح للعامة (HTTP 200).",
                        remediation=fix,
                    )
                )

    if local_path:
        root = Path(local_path)
        env_file = root / ".env"
        if env_file.exists():
            txt = env_file.read_text(encoding="utf-8", errors="replace")
            if "APP_DEBUG=true" in txt:
                findings.append(
                    make_finding(
                        title="APP_DEBUG=true enabled in .env",
                        severity="High",
                        category="SAST",
                        source_tool="ego-laravel-audit",
                        location=str(env_file),
                        description="تفعيل APP_DEBUG=true يكشف تتبع الأخطاء ومتغيرات البيئة عند حدوث خطأ.",
                        remediation="اجعل APP_DEBUG=false في بيئة الإنتاج.",
                    )
                )
            if "APP_KEY=" in txt and len(txt.split("APP_KEY=", 1)[1].splitlines()[0].strip()) < 16:
                findings.append(
                    make_finding(
                        title="Weak or Missing Laravel APP_KEY",
                        severity="Critical",
                        category="SAST",
                        source_tool="ego-laravel-audit",
                        location=str(env_file),
                        description="مفتاح التشفير APP_KEY مفقود أو قصير جداً.",
                        remediation="نفّذ `php artisan key:generate` لتوليد مفتاح قوي.",
                    )
                )
        gitignore = root / ".gitignore"
        if env_file.exists() and (not gitignore.exists() or ".env" not in gitignore.read_text(encoding="utf-8", errors="replace")):
            findings.append(
                make_finding(
                    title=".env not excluded in .gitignore",
                    severity="High",
                    category="Secrets",
                    source_tool="ego-laravel-audit",
                    location=str(gitignore),
                    description="ملف .env موجود ولا يظهر مستثنى داخل .gitignore.",
                    remediation="أضف `.env` إلى ملف `.gitignore` لمنع تسريب المفاتيح إلى Git.",
                )
            )
    return findings


def run_builtin_wp_audit(target_url: str, local_path: str) -> list[dict[str, Any]]:
    """Safe, read-only WordPress security audit for live URLs and local projects."""
    findings: list[dict[str, Any]] = []
    if target_url:
        base = target_url.rstrip("/")
        checks = [
            ("/wp-json/wp/v2/users", "WordPress User Enumeration via REST API", "Medium", '"slug"', "عطّل مسار /wp/v2/users لغير المسجلين أو قيّد REST API."),
            ("/xmlrpc.php", "WordPress XML-RPC Endpoint Enabled", "Medium", "XML-RPC", "عطّل xmlrpc.php إذا لم تكن تستخدمه لمنع هجمات التخمين وDDoS."),
            ("/wp-content/debug.log", "Exposed WordPress debug.log", "High", "PHP", "أوقف WP_DEBUG_LOG أو امنع الوصول العام إلى debug.log."),
            ("/readme.html", "WordPress Version Disclosed via readme.html", "Low", "WordPress", "احذف readme.html أو امنع الوصول إليه من الخادم."),
            ("/wp-content/uploads/", "Directory Listing Enabled on wp-content/uploads", "Low", "Index of", "أضف `Options -Indexes` في .htaccess أو Nginx لمنع استعراض الملفات."),
        ]
        for path, title, sev, marker, fix in checks:
            status, body, _ = _probe_url(base + path)
            if status in (200, 405) and (not marker or marker.lower() in body.lower()):
                findings.append(
                    make_finding(
                        title=title,
                        severity=sev,
                        category="DAST",
                        source_tool="ego-wp-audit",
                        location=base + path,
                        description=f"تم رصد نقطة ضعف أو كشف معلومات عبر `{path}` (HTTP {status}).",
                        remediation=fix,
                    )
                )

    if local_path:
        wp_cfg = Path(local_path) / "wp-config.php"
        if wp_cfg.exists():
            txt = wp_cfg.read_text(encoding="utf-8", errors="replace")
            if "define('WP_DEBUG', true)" in txt or 'define("WP_DEBUG", true)' in txt or "define( 'WP_DEBUG', true )" in txt:
                findings.append(
                    make_finding(
                        title="WP_DEBUG enabled in wp-config.php",
                        severity="High",
                        category="SAST",
                        source_tool="ego-wp-audit",
                        location=str(wp_cfg),
                        description="تفعيل WP_DEBUG في الإنتاج قد يكشف مسارات السيرفر وأخطاء PHP.",
                        remediation="اجعل WP_DEBUG مضبوطاً على false في الإنتاج.",
                    )
                )
            if "DISALLOW_FILE_EDIT" not in txt:
                findings.append(
                    make_finding(
                        title="DISALLOW_FILE_EDIT not set in wp-config.php",
                        severity="Medium",
                        category="SAST",
                        source_tool="ego-wp-audit",
                        location=str(wp_cfg),
                        description="محرر القوالب والإضافات داخل لوحة تحكم ووردبريس غير معطّل.",
                        remediation="أضف `define('DISALLOW_FILE_EDIT', true);` داخل wp-config.php.",
                    )
                )
            if "$table_prefix = 'wp_'" in txt or '$table_prefix = "wp_"' in txt:
                findings.append(
                    make_finding(
                        title="Default WordPress Table Prefix (wp_)",
                        severity="Low",
                        category="SAST",
                        source_tool="ego-wp-audit",
                        location=str(wp_cfg),
                        description="استخدام بادئة الجداول الافتراضية `wp_` يسهل تخمين أسماء الجداول.",
                        remediation="استخدم بادئة جداول مخصصة غير افتراضية.",
                    )
                )
    return findings


def execute_tool(tool_id: str, target_url: str, local_path: str, stack: str = "general") -> tuple[list[dict[str, Any]], str]:
    """Run an individual tool safely and return (findings, status_note)."""
    if tool_id == "ego-http-audit":
        if not target_url:
            return [], "skipped (no URL)"
        return run_builtin_http_audit(target_url), "ok"

    if tool_id == "ego-laravel-audit":
        return run_builtin_laravel_audit(target_url, local_path), "ok"

    if tool_id == "ego-wp-audit":
        return run_builtin_wp_audit(target_url, local_path), "ok"

    with tempfile.TemporaryDirectory(prefix="ego_") as tmp:
        out_file = Path(tmp) / "output.sarif"

        if tool_id == "semgrep" and local_path:
            bin_p = _find_binary("semgrep")
            if not bin_p:
                return [], "not installed"
            configs = ["--config", "auto"]
            if stack == "laravel":
                configs = ["--config", "p/php", "--config", "p/laravel", "--config", "auto"]
            elif stack == "wordpress":
                configs = ["--config", "p/php", "--config", "auto"]
            subprocess.run(
                [bin_p, "scan", *configs, "--sarif", "-o", str(out_file), local_path],
                capture_output=True,
                timeout=180,
                check=False,
            )
            return parse_sarif(out_file, "Semgrep", "SAST"), "ok"

        if tool_id == "composer-audit" and local_path:
            bin_p = _find_binary("composer")
            lock_file = Path(local_path) / "composer.lock"
            if not bin_p or not lock_file.exists():
                return [], "skipped (no composer.lock)"
            proc = subprocess.run(
                [bin_p, "audit", "--working-dir", local_path, "--format=json"],
                capture_output=True,
                text=True,
                timeout=90,
                check=False,
            )
            try:
                cdata = json.loads(proc.stdout or "{}")
            except json.JSONDecodeError:
                cdata = {}
            findings = []
            for pkg_name, advisories in (cdata.get("advisories") or {}).items():
                for adv in advisories:
                    findings.append(
                        make_finding(
                            title=f"{pkg_name}: {adv.get('title', adv.get('cve', 'Advisory'))}",
                            severity=adv.get("severity", "High"),
                            category="SCA",
                            source_tool="composer-audit",
                            location=str(lock_file),
                            description=f"CVE: {adv.get('cve', 'N/A')} | Affected: {adv.get('affectedVersions', '')}",
                            remediation=f"حدّث الحزمة `{pkg_name}` عبر `composer update {pkg_name}`.",
                        )
                    )
            return findings, "ok"

        if tool_id == "wpscan" and target_url:
            bin_p = _find_binary("wpscan")
            if not bin_p:
                return [], "not installed"
            proc = subprocess.run(
                [bin_p, "--url", target_url, "--format", "json", "--no-banner"],
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
            try:
                wdata = json.loads(proc.stdout or "{}")
            except json.JSONDecodeError:
                wdata = {}
            findings = []
            for item in wdata.get("interesting_findings", []):
                findings.append(
                    make_finding(
                        title=f"WPScan: {item.get('type', 'Finding')}",
                        severity="Info",
                        category="DAST",
                        source_tool="WPScan",
                        location=item.get("url", target_url),
                        description=item.get("to_s", ""),
                        remediation="راجع إعدادات ووردبريس وتأكد من إخفاء الملفات الحساسة.",
                    )
                )
            return findings, "ok"

        if tool_id == "bandit" and local_path:
            bin_p = _find_binary("bandit")
            if not bin_p:
                return [], "not installed"
            json_out = Path(tmp) / "bandit.json"
            subprocess.run(
                [bin_p, "-r", local_path, "-f", "json", "-o", str(json_out), "-q"],
                capture_output=True,
                timeout=120,
                check=False,
            )
            return parse_bandit_json(json_out), "ok"

        if tool_id == "trivy" and local_path:
            bin_p = _find_binary("trivy")
            if bin_p:
                subprocess.run(
                    [bin_p, "fs", "--format", "sarif", "-o", str(out_file), local_path],
                    capture_output=True,
                    timeout=180,
                    check=False,
                )
                return parse_sarif(out_file, "Trivy", "SCA"), "ok"
            return [], "not installed"

        if tool_id == "gitleaks" and local_path:
            bin_p = _find_binary("gitleaks")
            if bin_p:
                subprocess.run(
                    [bin_p, "detect", "--source", local_path, "--no-git", "--report-format", "sarif", "--report-path", str(out_file)],
                    capture_output=True,
                    timeout=120,
                    check=False,
                )
                return parse_sarif(out_file, "Gitleaks", "Secrets"), "ok"
            return [], "not installed"

        if tool_id == "checkov" and local_path:
            bin_p = _find_binary("checkov")
            if not bin_p:
                return [], "not installed"
            subprocess.run(
                [bin_p, "-d", local_path, "-o", "sarif", "--output-file-path", tmp, "--quiet"],
                capture_output=True,
                timeout=180,
                check=False,
            )
            sarif_files = list(Path(tmp).glob("*.sarif"))
            return (parse_sarif(sarif_files[0], "Checkov", "IaC"), "ok") if sarif_files else ([], "ok")

        if tool_id == "nuclei" and target_url:
            bin_p = _find_binary("nuclei")
            if not bin_p:
                return [], "not installed"
            jsonl_out = Path(tmp) / "nuclei.jsonl"
            extra_tags = []
            if stack == "laravel":
                extra_tags = ["-tags", "laravel,php"]
            elif stack == "wordpress":
                extra_tags = ["-tags", "wordpress,wp-plugin,wpscan"]
            subprocess.run(
                [bin_p, "-u", target_url, *extra_tags, "-etags", "dos,fuzz", "-rl", "20", "-jsonl", "-o", str(jsonl_out), "-silent"],
                capture_output=True,
                timeout=240,
                check=False,
            )
            return parse_nuclei_jsonl(jsonl_out), "ok"

        if tool_id == "nmap" and target_url:
            bin_p = _find_binary("nmap")
            if not bin_p:
                return [], "not installed"
            host = urllib.parse.urlparse(target_url).hostname or target_url
            proc = subprocess.run(
                [bin_p, "-F", "--open", host],
                capture_output=True,
                text=True,
                timeout=90,
                check=False,
            )
            findings = []
            for line in proc.stdout.splitlines():
                if "/tcp" in line and "open" in line:
                    findings.append(
                        make_finding(
                            title=f"Open Port Detected: {line.strip()}",
                            severity="Info",
                            category="DAST",
                            source_tool="Nmap",
                            location=host,
                            description=f"تم رصد منفذ مفتوح على الخادم: {line.strip()}",
                            remediation="تأكد من أن هذه الخدمة مطلوبة للعامة، وأغلق المنافذ غير الضرورية عبر الجدار الناري.",
                        )
                    )
            return findings, "ok"

        if tool_id == "wapiti" and target_url:
            bin_p = _find_binary("wapiti")
            if not bin_p:
                return [], "not installed"
            json_out = Path(tmp) / "wapiti.json"
            subprocess.run(
                [bin_p, "-u", target_url, "-f", "json", "-o", str(json_out), "--max-scan-time", "60", "--flush-session"],
                capture_output=True,
                timeout=90,
                check=False,
            )
            if not json_out.exists():
                return [], "ok"
            try:
                wdata = json.loads(json_out.read_text(encoding="utf-8", errors="replace"))
            except json.JSONDecodeError:
                return [], "ok"
            findings = []
            for cat_name, items in (wdata.get("vulnerabilities") or {}).items():
                for item in items or []:
                    findings.append(
                        make_finding(
                            title=cat_name,
                            severity="Medium" if item.get("level", 1) <= 2 else "High",
                            category="DAST",
                            source_tool="Wapiti",
                            location=item.get("path", target_url),
                            description=item.get("info", cat_name),
                            remediation="راجع تفاصيل الثغرة في Wapiti وأغلق نقطة الإدخال أو الإعداد غير الآمن.",
                        )
                    )
            return findings, "ok"

        if tool_id == "testssl" and target_url:
            bin_p = _find_binary("testssl.sh")
            if not bin_p:
                local_t = BIN_DIR / "testssl.sh" / "testssl.sh"
                bin_p = str(local_t) if local_t.exists() else None
            if not bin_p:
                return [], "not installed"
            json_out = Path(tmp) / "testssl.json"
            subprocess.run(
                [bin_p, "--quiet", "--fast", "--jsonfile", str(json_out), target_url],
                capture_output=True,
                timeout=120,
                check=False,
            )
            if not json_out.exists():
                return [], "ok"
            try:
                tdata = json.loads(json_out.read_text(encoding="utf-8", errors="replace"))
            except json.JSONDecodeError:
                return [], "ok"
            findings = []
            for item in tdata if isinstance(tdata, list) else []:
                sev = str(item.get("severity", "INFO")).upper()
                if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    findings.append(
                        make_finding(
                            title=f"TLS/SSL: {item.get('id', 'Issue')}",
                            severity=sev.title(),
                            category="DAST",
                            source_tool="testssl.sh",
                            location=target_url,
                            description=item.get("finding", ""),
                            remediation="حدّث إعدادات TLS/SSL لإلغاء البروتوكولات والتشفير الضعيف.",
                        )
                    )
            return findings, "ok"

        if tool_id == "pip-npm-audit" and local_path:
            bin_p = _find_binary("pip-audit")
            req_file = Path(local_path) / "requirements.txt"
            if bin_p and req_file.exists():
                proc = subprocess.run(
                    [bin_p, "-r", str(req_file), "-f", "json"],
                    capture_output=True,
                    text=True,
                    timeout=90,
                    check=False,
                )
                try:
                    pdata = json.loads(proc.stdout or "{}")
                except json.JSONDecodeError:
                    pdata = {}
                findings = []
                for dep in pdata.get("dependencies", []):
                    for vuln in dep.get("vulns", []):
                        findings.append(
                            make_finding(
                                title=f"{dep.get('name')} ({vuln.get('id')})",
                                severity="High",
                                category="SCA",
                                source_tool="pip-audit",
                                location=str(req_file),
                                description=vuln.get("description", ""),
                                remediation=f"Fix versions: {', '.join(vuln.get('fix_versions', []))}",
                            )
                        )
                return findings, "ok"
            return [], "skipped (no requirements.txt)"

        if tool_id == "retirejs" and (local_path or target_url):
            bin_p = _find_binary("retire")
            if not bin_p or not local_path:
                return [], "skipped"
            proc = subprocess.run(
                [bin_p, "--path", local_path, "--outputformat", "json"],
                capture_output=True,
                text=True,
                timeout=90,
                check=False,
            )
            try:
                rdata = json.loads(proc.stdout or "{}")
            except json.JSONDecodeError:
                rdata = {}
            findings = []
            for entry in rdata.get("data", []):
                for res in entry.get("results", []):
                    for v in res.get("vulnerabilities", []):
                        findings.append(
                            make_finding(
                                title=f"Outdated JS: {res.get('component')} {res.get('version')}",
                                severity=v.get("severity", "Medium"),
                                category="SCA",
                                source_tool="Retire.js",
                                location=entry.get("file", local_path),
                                description=v.get("identifiers", {}).get("summary", "Vulnerable JS library"),
                                remediation="قم بترقية مكتبة JavaScript إلى أحدث إصدار آمن.",
                            )
                        )
            return findings, "ok"

    return [], "skipped or not installed"

