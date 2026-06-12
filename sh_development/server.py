from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse


BASE_DIR = Path(__file__).resolve().parent
DIST_DIR = BASE_DIR / "dist"
DATA_DIR = Path(os.environ.get("SCAN_SERVER_DATA_DIR", BASE_DIR / "data"))
REPORTS_FILE = DATA_DIR / "reports.jsonl"
API_TOKEN = os.environ.get("SCAN_API_TOKEN", "change-me")

app = FastAPI(
    title="scan.sh rule and report server",
    version="0.1.0",
    description="Serves static scanner rules, scanner scripts, and accepts optional scan report uploads.",
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


@app.get("/scan.sh")
def scan_script() -> FileResponse:
    return FileResponse(BASE_DIR / "scan.sh", media_type="text/x-shellscript")


@app.get("/merge_report.py")
def merge_report_script() -> FileResponse:
    return FileResponse(BASE_DIR / "merge_report.py", media_type="text/x-python")


@app.get("/find_exposed_files.sh")
def exposed_files_script() -> FileResponse:
    return FileResponse(BASE_DIR / "find_exposed_files.sh", media_type="text/x-shellscript")


def build_runner_script(base_url: str) -> str:
    base_url = base_url.rstrip("/")
    return f'''#!/usr/bin/env bash
set -u

BASE_URL="${{BASE_URL:-{base_url}}}"
RUNNER_DIR="${{SCAN_RUNNER_DIR:-.scan-sh-runner}}"
SCAN_ARGS="${{SCAN_ARGS:---fail-on never --clean}}"
SKIP_SEMGREP_INSTALL="${{SKIP_SEMGREP_INSTALL:-0}}"

log() {{
  printf '[scan.sh installer] %s\n' "$*" >&2
}}

have() {{
  command -v "$1" >/dev/null 2>&1
}}

find_python() {{
  for candidate in python3 python; do
    if have "$candidate" && "$candidate" -c "import sys" >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}}

download() {{
  url="$1"
  dest="$2"
  curl -fsSL "$url" -o "$dest"
}}

if ! have curl; then
  log "curl is required but was not found."
  exit 2
fi

PYTHON_BIN="$(find_python || true)"
if [ -z "$PYTHON_BIN" ]; then
  log "Python 3 is required but was not found."
  exit 2
fi

mkdir -p "$RUNNER_DIR"
download "$BASE_URL/scan.sh" "$RUNNER_DIR/scan.sh"
download "$BASE_URL/merge_report.py" "$RUNNER_DIR/merge_report.py"
download "$BASE_URL/find_exposed_files.sh" "$RUNNER_DIR/find_exposed_files.sh"
chmod +x "$RUNNER_DIR/scan.sh" "$RUNNER_DIR/find_exposed_files.sh"

if ! have semgrep && [ "$SKIP_SEMGREP_INSTALL" != "1" ]; then
  log "Semgrep not found. Trying user install with pip."
  "$PYTHON_BIN" -m pip install --user semgrep >/dev/null 2>&1 || log "Semgrep install failed; scan will continue with built-in checks."
  export PATH="$HOME/.local/bin:$PATH"
fi

log "Running scan in $(pwd)"
BASE_URL="$BASE_URL" "$RUNNER_DIR/scan.sh" $SCAN_ARGS
SCAN_EXIT=$?

rm -rf -- "$RUNNER_DIR"
exit "$SCAN_EXIT"
'''


@app.get("/run.sh")
def run_script(request: Request) -> PlainTextResponse:
    return PlainTextResponse(build_runner_script(str(request.base_url)), media_type="text/x-shellscript")


@app.get("/install.sh")
def install_script(request: Request) -> PlainTextResponse:
    return PlainTextResponse(build_runner_script(str(request.base_url)), media_type="text/x-shellscript")


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
