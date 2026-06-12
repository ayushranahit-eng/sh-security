#!/usr/bin/env bash
set -u

ROOT="${1:-.}"

PYTHON_BIN=""
for candidate in python python3; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c "import sys" >/dev/null 2>&1; then
    PYTHON_BIN="$candidate"
    break
  fi
done

if [ -z "$PYTHON_BIN" ]; then
  echo '{"findings":[],"error":"Python was not found"}'
  exit 0
fi

"$PYTHON_BIN" - "$ROOT" <<'PY'
import json
import os
import re
import sys

root = os.path.abspath(sys.argv[1])
findings = []

def add(category, severity, title, path, description, remediation, evidence, line=1):
    rel = os.path.relpath(path, root).replace(os.sep, "/")
    findings.append({
        "tool": "custom",
        "severity": severity,
        "category": category,
        "file": rel,
        "line": line or 1,
        "title": title,
        "evidence": evidence,
        "description": description,
        "remediation": remediation,
    })

backup_suffixes = (".bak", ".old", ".orig", ".tmp", ".swp", "~")
manifest_names = {"package.json", "composer.json", "requirements.txt", "poetry.lock", "Pipfile", "Gemfile", "go.mod"}
web_dirs = {"public", "www", "wwwroot", "htdocs", "dist", "build", "static"}
private_key_names = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "private.key", "server.key"}
private_key_markers = [
    "-----BEGIN " + "PRIVATE KEY-----",
    "-----BEGIN " + "RSA PRIVATE KEY-----",
]
risky_config_names = {"config.php", "settings.py", "settings.json", "application.yml", "application.yaml", "web.config"}
text_suffixes = {
    ".env", ".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yml", ".yaml", ".toml",
    ".ini", ".conf", ".sh", ".tf", ".dockerfile", ".html", ".css", ".txt"
}
secret_patterns = [
    ("AWS access key", "critical", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("GitHub token", "critical", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,255}\b|\bgithub_pat_[A-Za-z0-9_]{20,255}\b")),
    ("Stripe secret key", "critical", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b")),
    ("Google API key", "high", re.compile(r"\bAIza[0-9A-Za-z\-_]{20,}\b")),
    ("Hardcoded secret assignment", "high", re.compile(r"(?i)(secret|token|password|api[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
]

def read_prefix(path, limit=4096):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            return handle.read(limit)
    except OSError:
        return ""

for current, dirs, files in os.walk(root):
    dirs[:] = [d for d in dirs if d not in {".scan-sh", "node_modules", ".venv", "venv", "__pycache__"}]

    if ".git" in dirs:
        add(
            "secrets",
            "high",
            ".git directory present",
            os.path.join(current, ".git"),
            "A Git metadata directory is present under the scanned tree.",
            "Do not deploy .git directories to web-servable or production paths.",
            "Directory named .git exists in the scanned tree.",
        )

    for name in files:
        path = os.path.join(current, name)
        lower = name.lower()
        if lower.startswith("security-report") and lower.endswith(".json"):
            continue
        parts = set(os.path.relpath(path, root).replace(os.sep, "/").split("/"))

        if lower == ".env" or lower.startswith(".env."):
            add(
                "secrets",
                "critical",
                "Environment file committed or deployed",
                path,
                "An environment file can contain application secrets and credentials.",
                "Remove it from the repository/deployment and rotate any exposed secrets.",
                f"File named {name} exists. Content is not printed to avoid exposing secrets.",
            )
        elif lower.endswith(".sql"):
            add(
                "secrets",
                "high",
                "Database dump file present",
                path,
                "SQL dump files often contain sensitive production or staging data.",
                "Remove database dumps from deployed/source paths and store backups securely.",
                f"File extension .sql found at {os.path.relpath(path, root).replace(os.sep, '/')}.",
            )
        elif lower.endswith(backup_suffixes):
            add(
                "secrets",
                "medium",
                "Backup or temporary file present",
                path,
                "Backup and temporary files can expose older code, config, or secrets.",
                "Delete backup files from source/deployment paths.",
                f"Backup/temp filename pattern matched: {name}.",
            )
        elif lower in manifest_names and parts.intersection(web_dirs):
            add(
                "secrets",
                "low",
                "Dependency manifest in web-servable directory",
                path,
                "Dependency manifests in public build directories may disclose stack details.",
                "Keep package manifests outside web-servable directories unless intentionally published.",
                f"Manifest file {name} found inside a web-servable style directory.",
            )

        content = read_prefix(path)
        if lower in private_key_names or any(marker in content for marker in private_key_markers):
            add(
                "secrets",
                "critical",
                "Private key file or content detected",
                path,
                "A private key was found in the scanned tree.",
                "Remove the key, rotate/reissue it, and store private keys outside source/deployment folders.",
                "Private key filename or PEM header matched. Key body is not printed.",
            )
        elif lower in risky_config_names and any(word in content.lower() for word in ("password", "secret", "api_key", "apikey", "token")):
            add(
                "config",
                "high",
                "Configuration file contains secret-looking keys",
                path,
                "A configuration file contains words commonly used for credentials.",
                "Move secrets to environment variables or a secret manager and keep config templates non-sensitive.",
                f"Config file {name} contains secret-like field names.",
            )
        elif "chmod 777" in content.lower() or "chmod -r 777" in content.lower():
            add(
                "config",
                "high",
                "Dangerous file permission command detected",
                path,
                "A command grants world-writable permissions.",
                "Avoid chmod 777 and grant only the specific permissions required.",
                "Matched chmod 777 style command.",
            )

        _, suffix = os.path.splitext(lower)
        if suffix in text_suffixes or lower in {".env", "dockerfile"}:
            for line_no, line_text in enumerate(content.splitlines(), start=1):
                for secret_name, severity, regex in secret_patterns:
                    match = regex.search(line_text)
                    if not match:
                        continue
                    add(
                        "secrets",
                        severity,
                        f"{secret_name} detected in source/config",
                        path,
                        "A credential-like value was found in a source or configuration file.",
                        "Move the secret to a protected secret store, rotate it, and remove it from code/history.",
                        f"{secret_name} pattern matched on this line. Secret value is not printed.",
                        line_no,
                    )
                    break

print(json.dumps({"findings": findings}, indent=2))
PY
