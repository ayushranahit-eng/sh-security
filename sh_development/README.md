# scan.sh

`scan.sh` is a source-code-only security scanner. It is copied into a client codebase and run on the client server, CI runner, or cron job. It analyzes files at rest and does not test a live website.

## What It Does

| Category | Detection |
| --- | --- |
| Secrets | Hardcoded keys, `.env` files, `.git` directories, backup/temp files, SQL dumps, CI config secrets, Git history secrets via gitleaks |
| SCA | Vulnerable dependencies through `osv-scanner` for npm, Python, Go, Ruby, and other supported lockfiles |
| SAST | Semgrep rules for SQL injection, NoSQL injection, SSTI, insecure deserialization, command injection, eval/exec, path traversal, weak crypto, cookie flags, missing security headers, SMTP header injection |
| IaC | Semgrep rules for Terraform, Kubernetes, Dockerfile, and IAM-style misconfigurations |

## Explicitly Out Of Scope

| Area | Reason |
| --- | --- |
| XSS/CSRF/SSRF/open redirect/runtime CORS/JWT checks | Require live HTTP requests to a running app |
| Open ports, TLS/ciphers, DNS takeover, Shodan-style checks | Network/infra scanning |
| Actual AWS/GCP/Azure account posture | Requires cloud API access |
| Prompt injection or LLM runtime testing | Requires live endpoints and app context |
| Business logic and attack chaining | Requires active pentesting and human context |

## Client Usage

Run inside the client repository:

```bash
chmod +x scan.sh find_exposed_files.sh
./scan.sh
```

Offline mode:

```bash
./scan.sh --offline --skip-downloads
```

CI gating:

```bash
./scan.sh --fail-on high
```

The scanner writes:

```text
security-report-YYYYMMDD-HHMMSS.json
.scan-sh/
```

`.scan-sh/` is a temporary raw-output folder created by the scanner. If you delete it, the next scan creates it again. It is generated locally, not downloaded.

To remove `.scan-sh/` automatically after a scan:

```bash
./scan.sh --clean
```

or:

```bash
SCAN_CLEAN=1 ./scan.sh
```

## Optional Report Upload

Report upload happens only when `SCAN_API_TOKEN` is set:

```bash
BASE_URL="https://scanner.example.com" \
SCAN_API_TOKEN="client-token" \
./scan.sh
```

Without a token, the report stays local.

## Localhost Test

Start the local rule/report server:

```bash
cd sh_development
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export SCAN_API_TOKEN="dev-token"
uvicorn server:app --reload --port 8000
```

In another terminal:

```bash
cd sh_development/sample-vulnerable-repo
BASE_URL="http://localhost:8000" SCAN_API_TOKEN="dev-token" ../scan.sh --fail-on never
```

Open the generated `security-report-*.json` file to review merged findings.

## Server Deployment Notes

Railway test deployment:

```bash
SCAN_API_TOKEN="replace-with-long-random-token"
uvicorn server:app --host 0.0.0.0 --port "$PORT"
```

CloudPanel production deployment:

- Create a Python app/site.
- Set `SCAN_API_TOKEN` and `SCAN_SERVER_DATA_DIR`.
- Run `uvicorn server:app --host 127.0.0.1 --port 8000` behind the panel reverse proxy.
- Use HTTPS on the public domain before accepting uploaded reports.
- Treat uploaded reports as sensitive because they may contain filenames, package names, and secret evidence previews.

## Tool Notes

- `gitleaks` is downloaded/cached when missing unless `--offline` or `--skip-downloads` is used.
- `osv-scanner` is downloaded/cached when missing unless offline.
- `semgrep` is expected to be installed on the client machine or CI image.
- `merge_report.py` uses only the Python 3 standard library.
- `find_exposed_files.sh` uses Bash plus Python 3 standard library.
