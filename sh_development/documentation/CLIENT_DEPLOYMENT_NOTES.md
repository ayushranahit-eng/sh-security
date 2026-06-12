# Client Deployment Notes

## Official Client Command

Tell the client:

```text
Go inside your project/repository folder and run this command.
```

```bash
SCAN_API_TOKEN="TOKEN" bash <(curl -fsSL SCANNER_URL/run.sh)
```

For our current Railway deployment:

```bash
SCAN_API_TOKEN="TOKEN" bash <(curl -fsSL https://sh-security-production.up.railway.app/run.sh)
```

Only one value changes per client:

```text
TOKEN
```

The scanner runs in the current folder, creates a dated JSON report, uploads it when the token is valid, and removes temporary runner files.
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

## Simple One-Command Client Flow

This is the easiest client workflow. The client only SSHs into the server, goes to the website/app folder, and runs one command.

CloudPanel example path:

```bash
cd /home/<site-user>/htdocs/<domain>
SCAN_API_TOKEN="client-token" bash <(curl -fsSL https://sh-security-production.up.railway.app/run.sh)
```

For example:

```bash
cd /home/siteuser/htdocs/example.com
SCAN_API_TOKEN="client-token" bash <(curl -fsSL https://sh-security-production.up.railway.app/run.sh)
```

The hosted `run.sh` script downloads the scanner files into `.scan-sh-runner/`, runs the scan, writes the dated JSON report, uploads it if a token is present, and removes `.scan-sh-runner/` at the end.

The client does not need to clone your GitHub repository. They only need `bash`, `curl`, and `python3`. Semgrep is installed automatically with `pip --user` when possible; if that fails, built-in checks still run.

Use this when you want high/critical findings to fail CI:

```bash
SCAN_API_TOKEN="client-token" SCAN_ARGS="--fail-on high --clean" bash <(curl -fsSL https://sh-security-production.up.railway.app/run.sh)
```

Use this when the client wants the report to stay only on their server:

```bash
bash <(curl -fsSL https://sh-security-production.up.railway.app/run.sh)
```
