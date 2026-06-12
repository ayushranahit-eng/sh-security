# Local Testing Guide

This guide is for testing on your machine before deploying.

## Terminal 1: Start Server

Use PowerShell:

```powershell
cd "H:\-- Ayush Rana 2 --\Security Testing\security-testing-with-script - Copy\sh_development"
.\.venv\Scripts\Activate.ps1
$env:SCAN_API_TOKEN="dev-token"
uvicorn server:app --port 8000
```

Keep this terminal open.

## Terminal 2: Run Scanner

Use Git Bash. If the sample repo is outside `sh_development`, use this path:

```bash
cd "/h/-- Ayush Rana 2 --/Security Testing/security-testing-with-script - Copy/sample-vulnerable-repo"
BASE_URL="http://localhost:8000" SCAN_API_TOKEN="dev-token" ../sh_development/scan.sh --fail-on never
```

If you keep the sample inside `sh_development`, use `../scan.sh` instead.

## Open Latest Report

List reports:

```bash
ls security-report-*.json
```

Open newest report:

```bash
cat security-report-YYYYMMDD-HHMMSS.json
```

Replace the filename with the newest generated file.

## Expected Result

The fake repo should show many findings across categories:

```text
secrets
auth
cicd
config
iac
sast
```

## What Is `.scan-sh/`?

After a scan, you will see this folder:

```text
.scan-sh/
```

This is normal.

It is created by `scan.sh` and contains raw scanner output.

The final readable file is:

```text
security-report-YYYYMMDD-HHMMSS.json
```

You can delete `.scan-sh/` during testing.

The next scan will create it again automatically.

It is not downloaded. It is generated locally by the scanner.

To auto-delete it after each scan:

```bash
BASE_URL="http://localhost:8000" SCAN_API_TOKEN="dev-token" ../sh_development/scan.sh --fail-on never --clean
```

## Common Problems

If only `secrets` appear:

```text
Semgrep may not be installed or rules may not have loaded.
```

If report files are scanned:

```text
Make sure latest scan.sh excludes security-report*.json.
```

If `.sh` does not run:

```text
Use Git Bash or Linux/WSL. Normal Windows Command Prompt cannot run .sh scripts.
```
