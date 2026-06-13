# Report Format

The scanner creates a timestamped JSON report.

Example filename:

```text
security-report-20260612-161114.json
```

## Top-Level Fields

```json
{
  "scanner": "scan.sh",
  "generated_at": "2026-06-12T10:41:26.118723+00:00",
  "root": "path/to/scanned/repo",
  "summary": {},
  "findings": [],
  "report_file": "security-report-20260612-161114.json"
}
```

## Summary

The summary shows counts:

```json
{
  "critical": 2,
  "high": 34,
  "medium": 23,
  "low": 6,
  "total": 65,
  "by_category": {
    "secrets": 5,
    "auth": 8,
    "cicd": 3,
    "config": 12,
    "iac": 15,
    "sast": 22
  }
}
```

## Finding Fields

Each finding has:

| Field | Meaning |
| --- | --- |
| `tool` | Which scanner found it |
| `severity` | Risk level |
| `category` | Type of issue |
| `file` | File where issue was found |
| `line` | Line number |
| `title` | Short issue name |
| `note` | Simple human explanation |
| `evidence` | What matched |
| `description` | Technical reason |
| `remediation` | How to fix |

## Example Finding

```json
{
  "tool": "semgrep",
  "severity": "high",
  "category": "sast",
  "file": "app/vulnerable.py",
  "line": 31,
  "title": "subprocess with shell=True can allow command injection when arguments contain user input.",
  "note": "User input may reach an operating-system command. Attackers can sometimes run commands on the server.",
  "evidence": "return subprocess.check_output(cmd, shell=True).decode()",
  "description": "Rule python-command-injection-shell-true matched this source location.",
  "remediation": "Pass an argument list with shell=False and validate inputs."
}
```


## Codebase Overview

Reports now start with a `codebase` section before vulnerability findings:

```json
"codebase": {
  "directories": ["frontend", "backend", "infra"],
  "important_files": ["package.json", "requirements.txt", "Dockerfile"],
  "languages": [{"name": "Python", "files": 6}],
  "project_type": ["Node.js", "Python", "Docker"],
  "detected_frameworks": ["React", "Express", "FastAPI"],
  "package_managers": ["npm/yarn/pnpm", "pip/poetry/pipenv"],
  "apis": [
    {"method": "GET", "path": "/api/users", "file": "backend/api/main.py", "line": 12, "framework_hint": "FastAPI"}
  ]
}
```

This is static best-effort detection. It reads source files and common route patterns, but it does not run the application and does not make HTTP requests.
