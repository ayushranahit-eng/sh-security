#!/usr/bin/env python3
"""Merge scanner outputs into one normalized JSON report."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from typing import Any

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
TOOL_ERRORS: list[dict[str, Any]] = []


def load_json(path: str, fallback: Any) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read().strip()
            return json.loads(text) if text else fallback
    except (OSError, json.JSONDecodeError):
        return fallback


def norm_severity(value: Any) -> str:
    raw = str(value or "unknown").lower()
    if raw in {"error", "critical"}:
        return "critical"
    if raw in {"warning", "warn", "high"}:
        return "high"
    if raw in {"medium", "moderate"}:
        return "medium"
    if raw in {"low", "note"}:
        return "low"
    if raw in {"info", "informational"}:
        return "low"
    return "medium"


def clean_rule_id(value: Any) -> str:
    raw = str(value or "unknown").replace("\\", "/")
    if ".rules." in raw:
        return raw.rsplit(".rules.", 1)[-1]
    if "/rules/" in raw:
        return raw.rsplit("/rules/", 1)[-1]
    return raw.rsplit("/", 1)[-1]


def source_line(path: str, line: int | None) -> str:
    if not path or not line:
        return ""
    normalized = path.replace("\\", os.sep).replace("/", os.sep)
    try:
        with open(normalized, "r", encoding="utf-8", errors="ignore") as handle:
            for current_line, content in enumerate(handle, start=1):
                if current_line == line:
                    snippet = " ".join(content.strip().split())
                    return snippet[:300]
    except OSError:
        return ""
    return ""


def is_generated_scanner_file(path: str) -> bool:
    normalized = (path or "").replace("\\", "/").lstrip("./")
    basename = normalized.rsplit("/", 1)[-1]
    return (
        normalized == ".scan-sh"
        or normalized.startswith(".scan-sh/")
        or (basename.startswith("security-report") and basename.endswith(".json"))
    )


def simple_note(title: str, category: str) -> str:
    text = title.lower()
    if "private key" in text:
        return "A private key file can allow direct access to servers, repositories, or signed systems. Treat it as compromised if it was exposed."
    if "dangerous file permission" in text or "world-writable" in text or "chmod 777" in text:
        return "World-writable permissions let too many users or processes change files. This can support tampering or privilege escalation."
    if "default credential" in text or "weak admin" in text:
        return "Default credentials are commonly tried by attackers. Admin accounts must use unique strong secrets."
    if "plaintext password" in text:
        return "Plaintext password checks usually mean passwords are not being safely hashed and verified. This can expose users if code or data leaks."
    if "logging" in text or "log secret" in text:
        return "Secrets written to logs can leak through log files, dashboards, backups, or support bundles."
    if "jwt" in text:
        return "JWT/session mistakes can let users stay authenticated too long or let attackers forge or misuse tokens."
    if "tls certificate verification" in text:
        return "Disabling TLS verification allows man-in-the-middle attacks against outbound HTTPS calls."
    if "cors" in text:
        return "Wildcard CORS can allow untrusted websites to read browser-accessible API responses in some setups."
    if "debug" in text:
        return "Debug mode may expose stack traces, environment details, secrets, or interactive consoles. It should be off in production."
    if "open redirect" in text:
        return "Redirecting to user-controlled URLs can support phishing and token theft in authentication flows."
    if "redirect target" in text:
        return "A redirect controlled by user input can send users to attacker-owned pages while starting from a trusted domain."
    if "ssrf" in text or "server-side request" in text:
        return "Server-side requests built from user input may let attackers reach internal services or metadata endpoints."
    if "file upload" in text:
        return "Unsafe uploads can store executable files, overwrite files, or expose malware/content risks."
    if "uploaded original filename" in text or "uploaded file name" in text:
        return "Using the filename supplied by the browser can allow path tricks, overwrites, or unsafe file types. Generate safe server-side names."
    if "yaml" in text or "xml" in text or "xxe" in text:
        return "Unsafe parsers can sometimes read local files, access network resources, or execute unexpected object loading behavior."
    if ".env" in text or "environment file" in text:
        return "This file often contains passwords, API keys, database URLs, and production secrets. If it is exposed or committed, attackers may be able to access real services."
    if ".git" in text:
        return "A .git folder can expose source history, old secrets, deleted files, branches, and commit metadata. It should never be web-accessible or deployed as part of a public app."
    if "database dump" in text or ".sql" in text:
        return "Database dump files may contain real user data, passwords, emails, tokens, or internal records. Leaving them in a code or web folder is high risk."
    if "manifest" in text:
        return "Public dependency files can reveal the technology stack and package versions, which helps attackers search for known vulnerabilities."
    if "secret detected" in text or "hardcoded" in text:
        return "A secret appears to be stored directly in code. Anyone with code access may be able to reuse it unless it is removed and rotated."
    if "sql" in text and "injection" in text:
        return "User input may be mixed directly into a database query. Attackers can sometimes change the query to read, change, or delete data."
    if "nosql" in text or "mongo" in text:
        return "Raw request data may be passed into a database query. Attackers can sometimes inject special operators to bypass filters or change query behavior."
    if "template" in text or "ssti" in text:
        return "User input may control template rendering. In some frameworks this can lead to server-side code execution or data exposure."
    if "pickle" in text or "deserialization" in text:
        return "Unsafe deserialization can execute code when attacker-controlled data is loaded. This is often a critical backend risk."
    if "command" in text or "shell=true" in text or "subprocess" in text:
        return "User input may reach an operating-system command. Attackers can sometimes run commands on the server."
    if "eval" in text or "exec" in text or "function constructor" in text:
        return "Dynamic code execution is dangerous when input can influence it. Attackers may be able to run their own code."
    if "path traversal" in text or "file path" in text:
        return "User input may control a file path. Attackers can sometimes read files outside the intended folder."
    if "md5" in text or "sha1" in text or "weak" in text:
        return "Weak hashing is not safe for passwords or sensitive security checks. Modern password hashing should be slow and salted."
    if "cookie" in text:
        return "Cookies without secure flags are easier to steal or abuse in browser attacks. Session cookies should be protected with HttpOnly, Secure, and SameSite."
    if "helmet" in text or "security headers" in text:
        return "Security headers add browser protections against common attacks. Missing headers do not always mean a breach, but they weaken defense."
    if "security group" in text or "0.0.0.0/0" in text:
        return "This configuration may expose a service to the whole internet. Public access should be limited to only what is truly required."
    if "s3" in text or "public access" in text:
        return "This storage policy may allow public access to files. Public buckets are a common cause of data leaks."
    if "privileged" in text or "securitycontext" in text:
        return "A container with too much privilege can make a compromise more damaging. Containers should run with least privilege."
    if "docker" in text or "root user" in text:
        return "Container settings can increase impact if the app is compromised. Avoid root users and avoid baking secrets into images."
    if "allowed_hosts" in text or "allows every host" in text:
        return "Allowing every host header can enable host-header attacks and broken password-reset or absolute-link behavior."
    if "not pinned" in text or "full commit sha" in text:
        return "Unpinned CI actions can change over time. Pinning to a commit reduces supply-chain risk."
    if category == "sca":
        return "A dependency version has a known vulnerability. Updating the package is usually the safest fix."
    if category == "iac":
        return "Infrastructure/configuration code appears risky. Review before deployment because this can create real cloud or server exposure."
    return "This finding marks a pattern that is commonly linked to security risk. Review the code and confirm whether user input or secrets are involved."


def finding(
    tool: str,
    severity: str,
    category: str,
    file: str,
    line: int | None,
    title: str,
    description: str,
    remediation: str,
    evidence: str = "",
) -> dict[str, Any]:
    title = title or "Security finding"
    category = category or "unknown"
    return {
        "tool": tool,
        "severity": norm_severity(severity),
        "category": category,
        "file": (file or "").replace("\\", "/"),
        "line": line or 1,
        "title": title,
        "note": simple_note(title, category),
        "evidence": evidence or "No direct evidence snippet was provided by this scanner.",
        "description": description or "",
        "remediation": remediation or "Review the finding and remove or fix the risky pattern.",
    }


def parse_gitleaks(path: str) -> list[dict[str, Any]]:
    data = load_json(path, [])
    if isinstance(data, dict):
        data = data.get("findings", data.get("Leaks", []))
    results = []
    for item in data if isinstance(data, list) else []:
        rule = item.get("RuleID") or item.get("Description") or "Secret detected"
        file_path = item.get("File") or item.get("file") or ""
        line = item.get("StartLine") or item.get("line") or 1
        results.append(finding(
            "gitleaks",
            "critical",
            "secrets",
            file_path,
            line,
            f"Secret detected: {rule}",
            "A credential-like value was found in source files or Git history.",
            "Remove the secret, rotate it at the provider, and purge it from Git history where required.",
            item.get("Match") or item.get("Secret") or "Gitleaks reported a secret-like value. Secret content may be redacted.",
        ))
    return results


def parse_semgrep(path: str, category: str, tool_name: str) -> list[dict[str, Any]]:
    data = load_json(path, {"results": []})
    results = []
    if isinstance(data, dict):
        for error in data.get("errors", []) or []:
            TOOL_ERRORS.append({
                "tool": tool_name,
                "category": category,
                "file": path,
                "message": error.get("message") or str(error),
            })
    for item in data.get("results", []) if isinstance(data, dict) else []:
        if is_generated_scanner_file(item.get("path", "")):
            continue
        extra = item.get("extra", {})
        metadata = extra.get("metadata", {})
        finding_category = metadata.get("category") or category
        severity = metadata.get("severity") or extra.get("severity") or "medium"
        title = extra.get("message") or item.get("check_id") or "Semgrep finding"
        remediation = metadata.get("remediation") or metadata.get("fix") or "Follow the rule guidance and replace the unsafe pattern."
        rule_id = clean_rule_id(item.get("check_id", "unknown"))
        file_path = item.get("path", "")
        line = item.get("start", {}).get("line", 1)
        evidence = source_line(file_path, line)
        if not evidence:
            evidence = extra.get("lines") or ""
            evidence = " ".join(str(evidence).strip().split())
        results.append(finding(
            tool_name,
            severity,
            finding_category,
            file_path,
            line,
            title,
            f"Rule {rule_id} matched this source location.",
            remediation,
            evidence,
        ))
    return results


def parse_osv(path: str) -> list[dict[str, Any]]:
    data = load_json(path, {})
    vulns = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            if "vulnerabilities" in value and isinstance(value["vulnerabilities"], list):
                for vuln in value["vulnerabilities"]:
                    vulns.append((value, vuln))
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(data)
    results = []
    for package_block, vuln in vulns:
        package = package_block.get("package", {}) if isinstance(package_block, dict) else {}
        package_name = package.get("name") or package_block.get("name") or "dependency"
        fixed = vuln.get("fixed_versions") or vuln.get("database_specific", {}).get("fixed_range") or []
        severity = "high" if vuln.get("severity") else "medium"
        remediation = "Upgrade the affected dependency."
        if fixed:
            remediation = f"Upgrade {package_name} to a fixed version: {fixed}."
        results.append(finding(
            "osv-scanner",
            severity,
            "sca",
            package_block.get("source", {}).get("path") or package_block.get("path") or "",
            1,
            f"Vulnerable dependency: {package_name}",
            vuln.get("summary") or vuln.get("id") or "A dependency vulnerability was reported by OSV.",
            remediation,
            vuln.get("id", ""),
        ))
    return results


def parse_custom(path: str) -> list[dict[str, Any]]:
    data = load_json(path, {"findings": []})
    return [finding(
        item.get("tool", "custom"),
        item.get("severity", "medium"),
        item.get("category", "secrets"),
        item.get("file", ""),
        item.get("line", 1),
        item.get("title", "Custom finding"),
        item.get("description", ""),
        item.get("remediation", ""),
        item.get("evidence", ""),
    ) for item in data.get("findings", [])]


def summarize(findings: list[dict[str, Any]]) -> dict[str, Any]:
    summary = {key: 0 for key in ("critical", "high", "medium", "low")}
    by_category: dict[str, int] = {}
    for item in findings:
        sev = item["severity"]
        if sev in summary:
            summary[sev] += 1
        by_category[item["category"]] = by_category.get(item["category"], 0) + 1
    summary["total"] = len(findings)
    summary["by_category"] = by_category
    return summary


def print_table(report: dict[str, Any]) -> None:
    summary = report["summary"]
    print("")
    print("Security scan summary")
    print(f"Total: {summary['total']} | Critical: {summary['critical']} | High: {summary['high']} | Medium: {summary['medium']} | Low: {summary['low']}")
    print("")
    for item in report["findings"][:20]:
        loc = item["file"] + (f":{item['line']}" if item.get("line") else "")
        print(f"{item['severity'].upper():8} {item['category']:8} {item['tool']:13} {loc} - {item['title']}")
    if len(report["findings"]) > 20:
        print(f"... {len(report['findings']) - 20} more findings in {report['report_file']}")
    if report.get("tool_errors"):
        print("")
        print("Tool warnings")
        for item in report["tool_errors"][:5]:
            print(f"{item['tool']} ({item['category']}): {item['message']}")
    print("")


def build_report(args: argparse.Namespace) -> int:
    findings = []
    findings.extend(parse_gitleaks(args.gitleaks))
    findings.extend(parse_semgrep(args.semgrep_sast, "sast", "semgrep"))
    findings.extend(parse_semgrep(args.semgrep_iac, "iac", "semgrep"))
    findings.extend(parse_osv(args.osv))
    findings.extend(parse_custom(args.custom))
    findings.sort(key=lambda item: (SEVERITY_ORDER.get(item["severity"], 9), item["category"], item["file"]))
    report = {
        "scanner": "scan.sh",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "root": os.getcwd(),
        "summary": summarize(findings),
        "tool_errors": TOOL_ERRORS,
        "findings": findings,
        "report_file": args.output,
    }
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    print_table(report)
    return 0


def gate(path: str, fail_on: str) -> int:
    if fail_on == "never":
        return 0
    report = load_json(path, {"summary": {}})
    threshold = SEVERITY_ORDER.get(fail_on, SEVERITY_ORDER["high"])
    for severity, rank in SEVERITY_ORDER.items():
        if rank <= threshold and report.get("summary", {}).get(severity, 0):
            return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gitleaks", default="")
    parser.add_argument("--semgrep-sast", default="")
    parser.add_argument("--semgrep-iac", default="")
    parser.add_argument("--osv", default="")
    parser.add_argument("--custom", default="")
    parser.add_argument("--output", default="security-report.json")
    parser.add_argument("--gate")
    parser.add_argument("--fail-on", default="high")
    args = parser.parse_args()
    if args.gate:
        return gate(args.gate, args.fail_on)
    return build_report(args)


if __name__ == "__main__":
    sys.exit(main())
