from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse


BASE_DIR = Path(__file__).resolve().parent
DIST_DIR = BASE_DIR / "dist"
DATA_DIR = Path(os.environ.get("SCAN_SERVER_DATA_DIR", BASE_DIR / "data"))
SCANS_DIR = DATA_DIR / "scans"
REPORTS_FILE = DATA_DIR / "reports.jsonl"
API_TOKEN = os.environ.get("SCAN_API_TOKEN", "change-me")
ALLOW_ORIGINS = [item.strip() for item in os.environ.get("SCAN_ALLOW_ORIGINS", "*").split(",") if item.strip()]

app = FastAPI(
    title="scan.sh rule and report server",
    version="0.2.0",
    description="Serves static scanner rules, scanner scripts, scan sessions, and accepts optional scan report uploads.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOW_ORIGINS or ["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_data_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SCANS_DIR.mkdir(parents=True, exist_ok=True)


def public_base_url(request: Request) -> str:
    proto = request.headers.get("x-forwarded-proto", request.url.scheme).split(",")[0].strip()
    host = request.headers.get("x-forwarded-host", request.headers.get("host", request.url.netloc)).split(",")[0].strip()
    return f"{proto}://{host}"


def scan_file_path(scan_id: str) -> Path:
    return SCANS_DIR / f"{scan_id}.json"


def load_json_file(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def write_json_file(path: Path, payload: Any) -> None:
    ensure_data_dirs()
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_scan(scan_id: str) -> dict[str, Any] | None:
    path = scan_file_path(scan_id)
    if not path.exists():
        return None
    return load_json_file(path, None)


def append_scan_event(session: dict[str, Any], stage: str, status: str, message: str, extra: dict[str, Any] | None = None) -> None:
    event = {
        "timestamp": iso_now(),
        "stage": stage or "scan",
        "status": status or "running",
        "message": message or "",
    }
    if extra:
        event.update(extra)
    session.setdefault("events", []).append(event)
    session["updated_at"] = event["timestamp"]
    normalized = (status or "").lower()
    if normalized in {"created", "pending"}:
        session["status"] = "pending"
    elif normalized in {"started", "running", "progress", "uploading", "skipped"}:
        session["status"] = "running"
    elif normalized in {"failed", "error"}:
        session["status"] = "failed"
    elif normalized in {"complete", "completed", "done"}:
        session["status"] = "completed"
    session["latest_event"] = event


def save_scan(session: dict[str, Any]) -> None:
    session["updated_at"] = iso_now()
    write_json_file(scan_file_path(session["id"]), session)


def build_scan_commands(base_url: str, scan_id: str, website_url: str = "") -> dict[str, str]:
    clean_url = website_url.replace('"', "")
    scan_token = API_TOKEN if API_TOKEN and API_TOKEN != "change-me" else "TOKEN"
    linux_lines = [
        f'export SCAN_API_TOKEN="{scan_token}"',
        f'export SCAN_ID="{scan_id}"',
    ]
    if clean_url:
        linux_lines.append(f'export SCAN_TARGET_URL="{clean_url}"')
    linux_lines.extend([
        f'url="{base_url}/run.sh"',
        'tmp="${TMPDIR:-/tmp}/scan-sh-runner.$$"',
        'if command -v curl >/dev/null 2>&1; then',
        '  curl -fsSL "$url" -o "$tmp"',
        'elif command -v wget >/dev/null 2>&1; then',
        '  wget -qO "$tmp" "$url"',
        'else',
        '  p="$(command -v python3 || command -v python)"',
        '  "$p" -c "import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], sys.argv[2])" "$url" "$tmp"',
        'fi',
        'bash "$tmp"',
        'status=$?',
        'rm -f "$tmp"',
        'exit "$status"',
    ])
    linux = "\n".join(linux_lines)
    powershell = (
        f'$env:SCAN_API_TOKEN="{scan_token}"; $env:SCAN_ID="{scan_id}";'
        + (f' $env:SCAN_TARGET_URL="{clean_url}";' if clean_url else "")
        + f' curl.exe -fsSL "{base_url}/run.sh" -o run.sh; bash run.sh; Remove-Item run.sh'
    )
    cmd = (
        f'set SCAN_API_TOKEN={scan_token}&& set SCAN_ID={scan_id}'
        + (f'&& set SCAN_TARGET_URL={clean_url}' if clean_url else "")
        + f'&& curl.exe -fsSL "{base_url}/run.sh" -o run.sh && bash run.sh && del run.sh'
    )
    return {
        "linux": linux,
        "git_bash": linux,
        "powershell": powershell,
        "cmd": cmd,
        "notes": "Production Linux/hosting servers should use the Linux command. It uses curl, wget, or Python 3 to download the runner. Windows commands require bash, such as Git Bash, plus curl.exe.",
    }


def report_summary(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "summary": payload.get("summary", {}),
        "report_file": payload.get("report_file"),
        "generated_at": payload.get("generated_at"),
        "root": payload.get("root"),
    }


def require_auth(authorization: str | None) -> None:
    expected = f"Bearer {API_TOKEN}"
    if not API_TOKEN or API_TOKEN == "change-me":
        raise HTTPException(status_code=500, detail="Server SCAN_API_TOKEN is not configured")
    if authorization != expected:
        raise HTTPException(status_code=401, detail="Invalid bearer token")


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
RUNNER_DIR="${{SCAN_RUNNER_DIR:-${{TMPDIR:-/tmp}}/scan-sh-runner.$$}}"
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
  if have curl; then
    curl -fsSL "$url" -o "$dest"
    return $?
  fi
  if have wget; then
    wget -qO "$dest" "$url"
    return $?
  fi
  "$PYTHON_BIN" - "$url" "$dest" <<'PY'
import sys
import urllib.request
urllib.request.urlretrieve(sys.argv[1], sys.argv[2])
PY
}}

PYTHON_BIN="$(find_python || true)"
if [ -z "$PYTHON_BIN" ]; then
  log "Python 3 is required but was not found."
  exit 2
fi

rm -rf -- "$RUNNER_DIR"
mkdir -p "$RUNNER_DIR"
download "$BASE_URL/scan.sh" "$RUNNER_DIR/scan.sh"
download "$BASE_URL/merge_report.py" "$RUNNER_DIR/merge_report.py"
download "$BASE_URL/find_exposed_files.sh" "$RUNNER_DIR/find_exposed_files.sh"
chmod +x "$RUNNER_DIR/scan.sh" "$RUNNER_DIR/find_exposed_files.sh"

if ! have semgrep && [ "$SKIP_SEMGREP_INSTALL" != "1" ]; then
  log "Semgrep not found. Trying user install with pip."
  install_log="$RUNNER_DIR/semgrep-install.log"
  if "$PYTHON_BIN" -m pip --version >/dev/null 2>&1 || "$PYTHON_BIN" -m ensurepip --upgrade >/dev/null 2>&1; then
    PIP_DISABLE_PIP_VERSION_CHECK=1 "$PYTHON_BIN" -m pip install --user semgrep >"$install_log" 2>&1 || log "Semgrep install failed; see $install_log. Scan will continue with built-in checks."
  else
    log "pip is not available for $PYTHON_BIN; scan will continue with built-in checks."
  fi
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
    return PlainTextResponse(build_runner_script(public_base_url(request)), media_type="text/x-shellscript")


@app.get("/install.sh")
def install_script(request: Request) -> PlainTextResponse:
    return PlainTextResponse(build_runner_script(public_base_url(request)), media_type="text/x-shellscript")


@app.post("/api/scans")
async def create_scan(request: Request) -> JSONResponse:
    payload = {}
    try:
        payload = await request.json()
    except json.JSONDecodeError:
        payload = {}
    except RuntimeError:
        payload = {}

    base_url = public_base_url(request)
    scan_id = f"scan_{uuid4().hex[:12]}"
    website_url = str(payload.get("website_url") or payload.get("target_url") or "").strip()
    session = {
        "id": scan_id,
        "website_url": website_url,
        "created_at": iso_now(),
        "updated_at": iso_now(),
        "status": "pending",
        "commands": build_scan_commands(base_url, scan_id, website_url),
        "report_id": None,
        "report": None,
        "events": [],
    }
    append_scan_event(session, "session", "created", "Scan session created.")
    save_scan(session)
    return JSONResponse({
        "ok": True,
        "scan": session,
        "poll_url": f"{base_url}/api/scans/{quote(scan_id)}",
    })


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str) -> JSONResponse:
    session = load_scan(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")
    return JSONResponse(session)


@app.post("/api/scans/{scan_id}/event")
async def post_scan_event(scan_id: str, request: Request, authorization: str | None = Header(default=None)) -> JSONResponse:
    require_auth(authorization)
    session = load_scan(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")
    try:
        payload = await request.json()
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid event payload") from exc

    if payload.get("website_url") and not session.get("website_url"):
        session["website_url"] = str(payload.get("website_url")).strip()
        session["commands"] = build_scan_commands(public_base_url(request), scan_id, session["website_url"])

    extra = {}
    for key in ("tool", "root", "report_file", "details"):
        if key in payload:
            extra[key] = payload[key]
    append_scan_event(
        session,
        str(payload.get("stage") or "scan"),
        str(payload.get("status") or "running"),
        str(payload.get("message") or "Progress update received."),
        extra,
    )
    save_scan(session)
    return JSONResponse({"ok": True, "scan_id": scan_id, "status": session.get("status")})


@app.post("/api/report")
async def post_report(
    request: Request,
    authorization: str | None = Header(default=None),
    x_scan_id: str | None = Header(default=None, alias="X-Scan-Id"),
) -> JSONResponse:
    require_auth(authorization)
    try:
        payload = await request.json()
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON report") from exc

    report_id = f"rpt_{uuid4().hex[:16]}"
    record = {
        "id": report_id,
        "scan_id": x_scan_id,
        "received_at": iso_now(),
        "client_host": request.client.host if request.client else None,
        "report": payload,
    }
    ensure_data_dirs()
    with REPORTS_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, separators=(",", ":")) + "\n")

    if x_scan_id:
        session = load_scan(x_scan_id)
        if session:
            session["report_id"] = report_id
            session["report"] = payload
            session["report_summary"] = report_summary(payload)
            append_scan_event(session, "report", "completed", "Final report uploaded.", {
                "report_id": report_id,
                "report_file": payload.get("report_file"),
            })
            save_scan(session)

    return JSONResponse({"ok": True, "id": report_id, "scan_id": x_scan_id})


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

