#!/usr/bin/env bash
set -u

VERSION="0.2.0"
BASE_URL="${BASE_URL:-http://localhost:8000}"
ASSET_BASE_URL="${SCAN_ASSET_BASE:-$BASE_URL}"
CACHE_DIR="${SCAN_CACHE_DIR:-$HOME/.cache/scan-sh}"
OUT_DIR="${SCAN_OUT_DIR:-.scan-sh}"
REPORT_STAMP="$(date +"%Y%m%d-%H%M%S")"
REPORT_FILE="${SCAN_REPORT_FILE:-security-report-${REPORT_STAMP}.json}"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
OFFLINE=0
SKIP_DOWNLOADS=0
SCAN_CLEAN="${SCAN_CLEAN:-0}"
FAIL_ON="${SCAN_FAIL_ON:-high}"
SCAN_ID="${SCAN_ID:-}"
SCAN_TARGET_URL="${SCAN_TARGET_URL:-}"
PYTHON_BIN=""

usage() {
  cat <<'EOF'
scan.sh - source-code-only security scanner

Usage:
  ./scan.sh [options]

Options:
  --offline              Do not download tools/rules or upload reports.
  --skip-downloads       Use cached tools/rules only.
  --base-url URL         Rule/report server URL. Defaults to BASE_URL or localhost:8000.
  --cache-dir DIR        Tool/rule cache directory. Defaults to ~/.cache/scan-sh.
  --out-dir DIR          Raw output directory. Defaults to .scan-sh.
  --fail-on LEVEL        CI gate: critical, high, medium, low, or never. Defaults to high.
  --clean                Delete raw .scan-sh output after the final report is created.
  --help                 Show this help.

Environment:
  BASE_URL               Server for /dist rules and optional /api/report upload.
  SCAN_API_TOKEN         Bearer token. If set, uploads the merged report.
  SCAN_ID                Optional scan session id for live progress updates.
  SCAN_TARGET_URL        Optional website URL label shown in the dashboard.
  SCAN_CACHE_DIR         Cache directory for tools and rules.
  SCAN_OUT_DIR           Raw scanner output directory.
  SCAN_CLEAN             Set to 1 to delete raw output after scan.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --offline) OFFLINE=1; SKIP_DOWNLOADS=1 ;;
    --skip-downloads) SKIP_DOWNLOADS=1 ;;
    --base-url) BASE_URL="${2:-}"; shift ;;
    --cache-dir) CACHE_DIR="${2:-}"; shift ;;
    --out-dir) OUT_DIR="${2:-}"; shift ;;
    --fail-on) FAIL_ON="${2:-high}"; shift ;;
    --clean) SCAN_CLEAN=1 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

mkdir -p "$CACHE_DIR/bin" "$CACHE_DIR/rules" "$OUT_DIR"

log() {
  printf '[scan.sh] %s\n' "$*" >&2
}

have() {
  command -v "$1" >/dev/null 2>&1
}

find_python() {
  for candidate in python python3; do
    if have "$candidate" && "$candidate" -c "import sys" >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

json_quote() {
  "$PYTHON_BIN" -c 'import json, sys; print(json.dumps(sys.argv[1]))' "$1"
}

notify_scan() {
  stage="$1"
  status="$2"
  message="$3"
  tool="${4:-}"

  [ "$OFFLINE" -eq 1 ] && return 0
  [ -z "$SCAN_ID" ] && return 0
  [ -z "${SCAN_API_TOKEN:-}" ] && return 0
  have curl || return 0
  [ -n "$PYTHON_BIN" ] || return 0

  root_json="$(json_quote "$(pwd)")"
  message_json="$(json_quote "$message")"
  target_json="$(json_quote "$SCAN_TARGET_URL")"
  tool_json="$(json_quote "$tool")"

  curl -fsSL -X POST "$BASE_URL/api/scans/$SCAN_ID/event" \
    -H "Authorization: Bearer $SCAN_API_TOKEN" \
    -H "Content-Type: application/json" \
    --data-binary @- >/dev/null 2>&1 <<EOF || true
{"stage":"$stage","status":"$status","message":$message_json,"tool":$tool_json,"root":$root_json,"website_url":$target_json}
EOF
}

detect_os_arch() {
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"
  case "$os" in
    linux) os="linux" ;;
    darwin) os="darwin" ;;
    mingw*|msys*|cygwin*) echo "Windows/Git Bash auto-download is not supported yet" >&2; return 1 ;;
    *) echo "Unsupported OS: $os" >&2; return 1 ;;
  esac
  case "$arch" in
    x86_64|amd64) arch="x64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) echo "Unsupported architecture: $arch" >&2; return 1 ;;
  esac
  printf '%s %s\n' "$os" "$arch"
}

download_file() {
  url="$1"
  dest="$2"
  tmp="${dest}.tmp"
  if [ "$SKIP_DOWNLOADS" -eq 1 ]; then
    return 1
  fi
  if have curl; then
    curl -fsSL "$url" -o "$tmp" && mv "$tmp" "$dest"
  elif have wget; then
    wget -qO "$tmp" "$url" && mv "$tmp" "$dest"
  elif [ -n "$PYTHON_BIN" ]; then
    "$PYTHON_BIN" - "$url" "$tmp" <<'PY' && mv "$tmp" "$dest"
import sys
import urllib.request

urllib.request.urlretrieve(sys.argv[1], sys.argv[2])
PY
  else
    return 1
  fi
}

upload_report() {
  report_path="$1"
  if have curl; then
    upload_args=()
    if [ -n "$SCAN_ID" ]; then
      upload_args+=( -H "X-Scan-Id: $SCAN_ID" )
    fi
    curl -fsSL -X POST "$BASE_URL/api/report" \
      -H "Authorization: Bearer $SCAN_API_TOKEN" \
      -H "Content-Type: application/json" \
      "${upload_args[@]}" \
      --data-binary "@$report_path" >/dev/null
    return $?
  fi

  [ -n "$PYTHON_BIN" ] || return 1
  "$PYTHON_BIN" - "$BASE_URL/api/report" "$SCAN_API_TOKEN" "$SCAN_ID" "$report_path" <<'PY'
import sys
import urllib.request

url, token, scan_id, report_path = sys.argv[1:]
with open(report_path, "rb") as handle:
    data = handle.read()

request = urllib.request.Request(url, data=data, method="POST")
request.add_header("Authorization", f"Bearer {token}")
request.add_header("Content-Type", "application/json")
if scan_id:
    request.add_header("X-Scan-Id", scan_id)

with urllib.request.urlopen(request, timeout=60) as response:
    response.read()
PY
}

refresh_rule() {
  name="$1"
  url="$2"
  dest="$CACHE_DIR/rules/$name"
  now="$(date +%s)"
  stale=1
  case "$BASE_URL" in
    http://localhost:*|http://127.0.0.1:*) stale=1 ;;
  esac
  if [ -f "$dest" ]; then
    mod="$(date -r "$dest" +%s 2>/dev/null || echo 0)"
    age=$((now - mod))
    case "$BASE_URL" in
      http://localhost:*|http://127.0.0.1:*) stale=1 ;;
      *) [ "$age" -lt 86400 ] && stale=0 ;;
    esac
  fi
  if [ "$stale" -eq 1 ] && [ "$OFFLINE" -eq 0 ]; then
    log "Refreshing $name"
    notify_scan "rules" "running" "Refreshing $name" "$name"
    download_file "$url" "$dest" || log "Could not refresh $name; using cached copy if available"
  fi
  [ -f "$dest" ] || return 1
  printf '%s\n' "$dest"
}

install_gitleaks() {
  if have gitleaks; then command -v gitleaks; return 0; fi
  tool="$CACHE_DIR/bin/gitleaks"
  [ -x "$tool" ] && { printf '%s\n' "$tool"; return 0; }
  [ "$SKIP_DOWNLOADS" -eq 1 ] && return 1
  detected="$(detect_os_arch)" || return 1
  read -r os arch <<EOF
$detected
EOF
  version="${GITLEAKS_VERSION:-8.24.2}"
  case "$arch" in
    x64) pkg_arch="x64" ;;
    arm64) pkg_arch="arm64" ;;
    *) return 1 ;;
  esac
  archive="$CACHE_DIR/gitleaks.tar.gz"
  url="https://github.com/gitleaks/gitleaks/releases/download/v${version}/gitleaks_${version}_${os}_${pkg_arch}.tar.gz"
  log "Downloading gitleaks $version"
  notify_scan "gitleaks" "running" "Downloading gitleaks binary" "gitleaks"
  download_file "$url" "$archive" || return 1
  tar -xzf "$archive" -C "$CACHE_DIR/bin" gitleaks >/dev/null 2>&1 || return 1
  chmod +x "$tool"
  printf '%s\n' "$tool"
}

install_osv_scanner() {
  if have osv-scanner; then command -v osv-scanner; return 0; fi
  tool="$CACHE_DIR/bin/osv-scanner"
  [ -x "$tool" ] && { printf '%s\n' "$tool"; return 0; }
  [ "$SKIP_DOWNLOADS" -eq 1 ] && return 1
  detected="$(detect_os_arch)" || return 1
  read -r os arch <<EOF
$detected
EOF
  version="${OSV_SCANNER_VERSION:-2.3.8}"
  case "$arch" in
    x64) pkg_arch="amd64" ;;
    arm64) pkg_arch="arm64" ;;
    *) return 1 ;;
  esac
  archive="$CACHE_DIR/osv-scanner"
  url="https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_${os}_${pkg_arch}"
  log "Downloading osv-scanner $version"
  notify_scan "osv" "running" "Downloading osv-scanner binary" "osv-scanner"
  download_file "$url" "$archive" || return 1
  mv "$archive" "$tool" || return 1
  chmod +x "$tool"
  printf '%s\n' "$tool"
}

find_semgrep() {
  if have semgrep; then command -v semgrep; return 0; fi
  return 1
}

run_or_note() {
  name="$1"
  shift
  log "Running $name"
  "$@" >"$OUT_DIR/${name}.json" 2>"$OUT_DIR/${name}.err"
  code=$?
  printf '{"tool":"%s","exit_code":%s}\n' "$name" "$code" >"$OUT_DIR/${name}.status.json"
  return "$code"
}

note_tool_result() {
  tool="$1"
  code="$2"
  if [ "$code" -eq 0 ]; then
    notify_scan "$tool" "completed" "$tool finished" "$tool"
  else
    notify_scan "$tool" "failed" "$tool finished with exit code $code" "$tool"
  fi
}

clean_output_dir() {
  case "$OUT_DIR" in
    ""|"."|"/"|"\\"|".."|"../"*|*".."*)
      log "Refusing to clean unsafe output directory: $OUT_DIR"
      return 1
      ;;
  esac
  if [ -d "$OUT_DIR" ]; then
    log "Cleaning raw output directory: $OUT_DIR"
    rm -rf -- "$OUT_DIR"
  fi
}

log "scan.sh $VERSION"
log "Scanning current directory: $(pwd)"

PYTHON_BIN="$(find_python || true)"
if [ -z "$PYTHON_BIN" ]; then
  log "Python was not found. Install Python 3 or make the 'python' command available in this terminal."
  exit 2
fi

notify_scan "scan" "started" "Scan started" "scan.sh"

SAST_RULES="$(refresh_rule semgrep-rules.yml "$ASSET_BASE_URL/dist/semgrep-rules.yml" || true)"
IAC_RULES="$(refresh_rule iac-rules.yml "$ASSET_BASE_URL/dist/iac-rules.yml" || true)"
GITLEAKS_BIN="$(install_gitleaks || true)"
OSV_BIN="$(install_osv_scanner || true)"
SEMGREP_BIN="$(find_semgrep || true)"

if [ -n "$GITLEAKS_BIN" ]; then
  notify_scan "gitleaks" "running" "Scanning current files and git history" "gitleaks"
  run_or_note gitleaks "$GITLEAKS_BIN" detect --source . --report-format json --redact --log-opts="--all"
  note_tool_result "gitleaks" "$?"
else
  log "Skipping gitleaks; binary unavailable"
  notify_scan "gitleaks" "skipped" "gitleaks unavailable on this system" "gitleaks"
  printf '[]\n' >"$OUT_DIR/gitleaks.json"
fi

if [ -n "$SEMGREP_BIN" ] && [ -n "$SAST_RULES" ]; then
  notify_scan "semgrep-sast" "running" "Running Semgrep SAST rules" "semgrep"
  run_or_note semgrep-sast "$SEMGREP_BIN" scan --config "$SAST_RULES" --json --no-git-ignore --exclude ".scan-sh" --exclude "security-report*.json" .
  note_tool_result "semgrep-sast" "$?"
else
  log "Skipping Semgrep SAST; semgrep or rules unavailable"
  notify_scan "semgrep-sast" "skipped" "Semgrep SAST unavailable" "semgrep"
  printf '{"results":[]}\n' >"$OUT_DIR/semgrep-sast.json"
fi

if [ -n "$SEMGREP_BIN" ] && [ -n "$IAC_RULES" ]; then
  notify_scan "semgrep-iac" "running" "Running Semgrep IaC rules" "semgrep"
  run_or_note semgrep-iac "$SEMGREP_BIN" scan --config "$IAC_RULES" --json --no-git-ignore --exclude ".scan-sh" --exclude "security-report*.json" .
  note_tool_result "semgrep-iac" "$?"
else
  log "Skipping Semgrep IaC; semgrep or rules unavailable"
  notify_scan "semgrep-iac" "skipped" "Semgrep IaC unavailable" "semgrep"
  printf '{"results":[]}\n' >"$OUT_DIR/semgrep-iac.json"
fi

if [ -n "$OSV_BIN" ]; then
  notify_scan "osv" "running" "Scanning dependencies with osv-scanner" "osv-scanner"
  run_or_note osv "$OSV_BIN" scan --recursive --format json .
  note_tool_result "osv" "$?"
else
  log "Skipping osv-scanner; binary unavailable"
  notify_scan "osv" "skipped" "osv-scanner unavailable on this system" "osv-scanner"
  printf '{}\n' >"$OUT_DIR/osv.json"
fi
if [ -x "$SCRIPT_DIR/find_exposed_files.sh" ]; then
  notify_scan "custom" "running" "Running custom file exposure checks" "custom"
  run_or_note custom "$SCRIPT_DIR/find_exposed_files.sh" .
  note_tool_result "custom" "$?"
else
  log "Skipping custom checks; find_exposed_files.sh missing or not executable"
  notify_scan "custom" "skipped" "Custom checks unavailable" "custom"
  printf '{"findings":[]}\n' >"$OUT_DIR/custom.json"
fi

notify_scan "merge" "running" "Building final report" "merge_report.py"
"$PYTHON_BIN" "$SCRIPT_DIR/merge_report.py" \
  --gitleaks "$OUT_DIR/gitleaks.json" \
  --semgrep-sast "$OUT_DIR/semgrep-sast.json" \
  --semgrep-iac "$OUT_DIR/semgrep-iac.json" \
  --osv "$OUT_DIR/osv.json" \
  --custom "$OUT_DIR/custom.json" \
  --output "$REPORT_FILE"
merge_code=$?
log "Report saved to $REPORT_FILE"

if [ "$merge_code" -eq 0 ]; then
  notify_scan "merge" "completed" "Final report created: $REPORT_FILE" "merge_report.py"
else
  notify_scan "merge" "failed" "Report generation failed" "merge_report.py"
fi

if [ "$OFFLINE" -eq 0 ] && [ -n "${SCAN_API_TOKEN:-}" ]; then
  notify_scan "upload" "running" "Uploading report to server" "upload"
  log "Uploading report to $BASE_URL/api/report"
  if upload_report "$REPORT_FILE"; then
    notify_scan "upload" "completed" "Report uploaded successfully" "upload"
  else
    log "Report upload failed"
    notify_scan "upload" "failed" "Report upload failed" "upload"
  fi
fi

if [ "$merge_code" -ne 0 ]; then
  if [ "$SCAN_CLEAN" = "1" ]; then
    clean_output_dir || true
  fi
  notify_scan "scan" "failed" "Scan failed during report generation" "scan.sh"
  exit "$merge_code"
fi

"$PYTHON_BIN" "$SCRIPT_DIR/merge_report.py" --gate "$REPORT_FILE" --fail-on "$FAIL_ON"
gate_code=$?

if [ "$gate_code" -eq 0 ]; then
  notify_scan "scan" "completed" "Scan completed successfully" "scan.sh"
else
  notify_scan "scan" "completed" "Scan completed and failed the CI severity gate" "scan.sh"
fi

if [ "$SCAN_CLEAN" = "1" ]; then
  clean_output_dir || true
fi

exit "$gate_code"
