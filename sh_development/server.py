from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse


BASE_DIR = Path(__file__).resolve().parent
DIST_DIR = BASE_DIR / "dist"
DATA_DIR = Path(os.environ.get("SCAN_SERVER_DATA_DIR", BASE_DIR / "data"))
REPORTS_FILE = DATA_DIR / "reports.jsonl"
API_TOKEN = os.environ.get("SCAN_API_TOKEN", "change-me")

app = FastAPI(
    title="scan.sh rule and report server",
    version="0.1.0",
    description="Serves static scanner rules and accepts optional scan report uploads.",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/dist/semgrep-rules.yml")
def semgrep_rules() -> FileResponse:
    return FileResponse(DIST_DIR / "semgrep-rules.yml", media_type="text/yaml")


@app.get("/dist/iac-rules.yml")
def iac_rules() -> FileResponse:
    return FileResponse(DIST_DIR / "iac-rules.yml", media_type="text/yaml")


def require_auth(authorization: str | None) -> None:
    expected = f"Bearer {API_TOKEN}"
    if not API_TOKEN or API_TOKEN == "change-me":
        raise HTTPException(status_code=500, detail="Server SCAN_API_TOKEN is not configured")
    if authorization != expected:
        raise HTTPException(status_code=401, detail="Invalid bearer token")


@app.post("/api/report")
async def post_report(request: Request, authorization: str | None = Header(default=None)) -> JSONResponse:
    require_auth(authorization)
    try:
        payload = await request.json()
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON report") from exc

    report_id = f"rpt_{uuid4().hex[:16]}"
    record = {
        "id": report_id,
        "received_at": datetime.now(timezone.utc).isoformat(),
        "client_host": request.client.host if request.client else None,
        "report": payload,
    }
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with REPORTS_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, separators=(",", ":")) + "\n")
    return JSONResponse({"ok": True, "id": report_id})


@app.get("/api/report/{report_id}")
def get_report(report_id: str, authorization: str | None = Header(default=None)) -> JSONResponse:
    require_auth(authorization)
    if not REPORTS_FILE.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    with REPORTS_FILE.open("r", encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            if record.get("id") == report_id:
                return JSONResponse(record)
    raise HTTPException(status_code=404, detail="Report not found")
