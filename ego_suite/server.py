"""FastAPI backend server for EGO Suite."""

from __future__ import annotations

from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel

from .adapters import get_tools_status, install_tool
from .cli import build_ai_report
from .config import BASE_DIR, REPORTS_DIR
from .db import delete_scan, get_dashboard_stats, get_scan_detail, init_db, list_scans, update_finding_status
from .github_client import clear_github_token, get_github_status, list_user_repos, save_github_token
from .orchestrator import get_scan_progress, start_scan
from .reporter import generate_reports

app = FastAPI(title="EGO Suite", version="1.0.0")


class ScanRequest(BaseModel):
    project_name: str
    target_url: str = ""
    local_path: str = ""
    github_repo: str = ""
    stack: str = "general"
    tools: list[str] | None = None


class GitHubTokenRequest(BaseModel):
    token: str


class FindingStatusUpdate(BaseModel):
    status: str


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.get("/", response_class=HTMLResponse)
def serve_ui() -> HTMLResponse:
    ui_file = BASE_DIR / "web" / "index.html"
    if not ui_file.exists():
        raise HTTPException(status_code=404, detail="UI not found")
    return HTMLResponse(ui_file.read_text(encoding="utf-8"))


@app.get("/EGOicon.png")
def serve_logo():
    logo_file = BASE_DIR / "EGOicon.png"
    if not logo_file.exists():
        raise HTTPException(status_code=404, detail="Logo not found")
    return FileResponse(logo_file, media_type="image/png")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "app": "EGO Suite"}


@app.get("/api/stats")
def stats() -> dict:
    return get_dashboard_stats()


@app.get("/api/tools")
def tools_list() -> dict:
    return {"tools": get_tools_status()}


@app.post("/api/tools/{tool_id}/install")
def tools_install(tool_id: str) -> dict:
    return install_tool(tool_id)


@app.get("/api/scans")
def scans_list() -> dict:
    return {"scans": list_scans()}


@app.post("/api/scans")
def scans_create(req: ScanRequest) -> dict:
    if not req.target_url.strip() and not req.local_path.strip() and not req.github_repo.strip():
        raise HTTPException(status_code=400, detail="يجب إدخال رابط الموقع أو مسار المشروع المحلي أو مستودع GitHub.")
    if req.local_path.strip() and not Path(req.local_path.strip()).exists():
        raise HTTPException(status_code=400, detail="المسار المحلي غير موجود على الجهاز.")
    return start_scan(req.project_name, req.target_url, req.local_path, req.tools, req.github_repo, req.stack)


@app.get("/api/github/status")
def github_status() -> dict:
    return get_github_status()


@app.post("/api/github/config")
def github_save(body: GitHubTokenRequest) -> dict:
    try:
        return save_github_token(body.token)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"تعذر التحقق من التوكن: {exc}") from exc


@app.delete("/api/github/config")
def github_disconnect() -> dict:
    clear_github_token()
    return {"connected": False}


@app.get("/api/github/repos")
def github_repos() -> dict:
    try:
        return {"repos": list_user_repos()}
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"تعذر جلب المستودعات: {exc}") from exc


@app.get("/api/scans/{scan_id}")
def scans_detail(scan_id: int) -> dict:
    detail = get_scan_detail(scan_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Scan not found")
    detail["progress"] = get_scan_progress(scan_id)
    return detail


@app.get("/api/scans/{scan_id}/ai-report")
def scans_ai_report(scan_id: int) -> dict:
    report = build_ai_report(scan_id)
    if not report:
        raise HTTPException(status_code=404, detail="Scan not found")
    return report


@app.get("/api/scans/{scan_id}/report")
def scans_report(scan_id: int, fmt: str = "html"):
    ext = "md" if fmt == "md" else "html"
    report_path = REPORTS_DIR / f"ego-report-{scan_id}.{ext}"
    if not report_path.exists():
        generated = generate_reports(scan_id)
        if not generated:
            raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(report_path, filename=report_path.name)


@app.patch("/api/findings/{finding_id}")
def finding_patch(finding_id: int, body: FindingStatusUpdate) -> dict:
    ok = update_finding_status(finding_id, body.status)
    if not ok:
        raise HTTPException(status_code=400, detail="Invalid finding ID or status")
    return {"ok": True}


@app.delete("/api/scans/{scan_id}")
def scans_delete(scan_id: int) -> dict:
    ok = delete_scan(scan_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Scan not found")
    for ext in ("html", "md"):
        p = REPORTS_DIR / f"ego-report-{scan_id}.{ext}"
        if p.exists():
            p.unlink()
    return {"ok": True}

