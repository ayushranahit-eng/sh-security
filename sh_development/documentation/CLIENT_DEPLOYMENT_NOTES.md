# Client Deployment Notes

## Basic Client Usage

Client SSHs into their server or CI runner and runs:

```bash
./scan.sh
```

The scanner runs inside the current directory.

## With Your Hosted Server

If you deploy `server.py` on your own server:

```bash
BASE_URL="https://scanner.example.com" SCAN_API_TOKEN="client-token" ./scan.sh
```

This allows:

```text
rule download
optional report upload
```

## Without Upload

If the client does not want to upload reports:

```bash
./scan.sh
```

or:

```bash
./scan.sh --offline
```

The report stays on their server.

## Output

The client receives:

```text
security-report-YYYYMMDD-HHMMSS.json
.scan-sh/
```

If the client does not want to keep raw scanner output, run:

```bash
BASE_URL="https://scanner.example.com" SCAN_API_TOKEN="client-token" ./scan.sh --clean
```

Then only the final report remains.

## Minimum Requirements

Recommended:

```text
bash
python 3
curl
semgrep
```

Optional but valuable:

```text
gitleaks
osv-scanner
```

## Linux Client Servers

Linux is the best target environment.

On Linux, `scan.sh` can automatically download/cache:

```text
gitleaks
osv-scanner
```

Git Bash on Windows is useful for local testing, but real client deployments should prefer Linux servers or CI runners.
