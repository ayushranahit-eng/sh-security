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
lockfile_names = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.lock", "poetry.lock", "Pipfile.lock", "Gemfile.lock"}
web_dirs = {"public", "www", "wwwroot", "htdocs", "dist", "build", "static"}
private_key_names = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "private.key", "server.key"}
private_key_markers = [
    "-----BEGIN " + "PRIVATE KEY-----",
    "-----BEGIN " + "RSA PRIVATE KEY-----",
]
risky_config_names = {"config.php", "settings.py", "settings.json", "application.yml", "application.yaml", "web.config"}
text_suffixes = {
    ".env", ".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yml", ".yaml", ".toml",
    ".ini", ".conf", ".sh", ".tf", ".dockerfile", ".html", ".htm", ".php", ".blade.php", ".xml", ".css", ".txt"
}
secret_patterns = [
    ("AWS access key", "critical", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("GitHub token", "critical", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,255}\b|\bgithub_pat_[A-Za-z0-9_]{20,255}\b")),
    ("Stripe secret key", "critical", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b")),
    ("Google API key", "high", re.compile(r"\bAIza[0-9A-Za-z\-_]{20,}\b")),
    ("Hardcoded secret assignment", "high", re.compile(r"(?i)(secret|token|password|api[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
]
static_patterns = [
    ("config", "high", "Production debug mode enabled", re.compile(r"(?i)^\s*APP_DEBUG\s*=\s*(true|1|yes)\s*$"), "Debug mode can expose stack traces, paths, config, SQL errors, or environment details.", "Set APP_DEBUG=false in production and clear framework config caches."),
    ("config", "medium", "Wildcard CORS origin configured", re.compile(r"(?i)(allowed_origins|allow_origins|cors_allowed_origins|cors|Access-Control-Allow-Origin).*(\*|all)"), "Wildcard CORS can expose browser-readable API responses to untrusted origins in some deployments.", "Restrict CORS origins to trusted domains and avoid credentials with wildcard origins."),
    ("web", "medium", "CSRF protection disabled for a route or middleware", re.compile(r"(?i)(withoutMiddleware\s*\([^)]*csrf|csrf\s*[:=]\s*false|csrfProtection\s*:\s*false|ignoreMethods.*csrf)"), "Disabling CSRF on state-changing endpoints can allow cross-site request abuse.", "Keep CSRF enabled unless the endpoint is stateless and protected another way."),
    ("web", "high", "Dangerous dynamic code execution", re.compile(r"(?i)\b(eval|exec|system|shell_exec|passthru|proc_open|popen)\s*\("), "Dynamic code or shell execution is dangerous when input can influence it.", "Replace dynamic execution with safe parsers or fixed allowlisted commands."),
    ("web", "high", "Unsafe PHP unserialize usage", re.compile(r"(?i)\bunserialize\s*\("), "Unserializing attacker-controlled data can lead to object injection or code execution in PHP apps.", "Use JSON for untrusted data or pass allowed_classes=false where appropriate."),
    ("web", "high", "Unsafe XML parser configuration", re.compile(r"(?i)(loadXML|simplexml_load|DOMDocument|xml2js|lxml|DocumentBuilderFactory|SAXParserFactory).*(LIBXML_NOENT|resolve_entities\s*=\s*True|setFeature\s*\([^)]*external|noent\s*=\s*True)"), "XML parsers that resolve external entities may allow XXE file disclosure or internal network access.", "Disable external entity resolution and DTD processing for untrusted XML."),
    ("web", "high", "SSRF-prone request from user input", re.compile(r"(?i)(requests\.(get|post)|Http::(get|post)|file_get_contents|curl_exec|http\.Get|urllib\.request).*(request|req\.|input|params|query|url)"), "Server-side HTTP requests influenced by user input may reach internal services or cloud metadata.", "Allowlist target hosts, block private/link-local IP ranges, and do not fetch arbitrary URLs."),
    ("web", "medium", "Open redirect pattern", re.compile(r"(?i)(redirect|RedirectResponse|res\.redirect|return redirect|header\s*\(\s*['\"]Location:).*(request|req\.|input|params|query|next|returnUrl|redirect)"), "Redirecting to user-controlled URLs can support phishing or token theft.", "Use relative redirects or validate redirect destinations against an allowlist."),
    ("web", "high", "Unsafe file upload handling", re.compile(r"(?i)(move_uploaded_file|storeAs|move\(|saveAs|multer|UploadedFile).*(getClientOriginalName|originalname|filename|request|req\.)"), "Using client-supplied filenames or weak upload handling can allow overwrites, unsafe extensions, or stored malicious files.", "Generate server-side filenames, validate MIME and extension, and store outside executable web roots."),
    ("auth", "high", "JWT accepts none algorithm", re.compile(r"(?i)(algorithms?\s*[:=]\s*\[[^\]]*['\"]none['\"]|algorithm\s*[:=]\s*['\"]none['\"])"), "Allowing the none JWT algorithm can let attackers bypass signature verification.", "Reject none and allowlist only the expected signed algorithm."),
    ("auth", "high", "Weak or hardcoded JWT secret", re.compile(r"(?i)(jwt_secret|JWT_SECRET|secretOrKey|signing[_-]?key)\s*[:=]\s*['\"][^'\"]{1,15}['\"]"), "Short or hardcoded JWT secrets can allow token forgery.", "Use a long random secret from a protected environment or secret manager."),
    ("auth", "medium", "JWT created without visible expiry", re.compile(r"(?i)(jwt\.sign|JWT::encode|createToken)\s*\("), "Tokens without expiry can remain valid too long if leaked.", "Set short expirations and rotate/ revoke tokens where possible."),
    ("auth", "medium", "Weak password policy configuration", re.compile(r"(?i)(min(?:imum)?[_-]?password|password[_-]?min|Password::min)\s*[:(=]\s*[\"']?[0-7]\b"), "Short password minimums weaken account security.", "Require at least 8-12 characters and consider breached-password checks."),
    ("auth", "medium", "Default credentials in seed/config", re.compile(r"(?i)(admin|root|test|demo).{0,80}(password|passwd|pwd)\s*[:=]\s*['\"](admin|password|123456|changeme|secret|test|demo)['\"]"), "Default credentials are commonly abused after deployment.", "Remove default accounts or force unique credentials before production."),
    ("config", "medium", "Host header trust may be too broad", re.compile(r"(?i)(ALLOWED_HOSTS\s*=\s*\[[^\]]*['\"]\*['\"]|TrustProxies::at\(\s*['\"]\*['\"]|trusted_hosts.*\*)"), "Trusting every host/proxy can enable host-header attacks or bad absolute URLs.", "Allowlist expected hosts and trusted proxy ranges."),
    ("config", "medium", "TLS certificate verification disabled", re.compile(r"(?i)(verify\s*[:=]\s*False|CURLOPT_SSL_VERIFYPEER\s*,\s*false|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true)"), "Disabling certificate validation allows man-in-the-middle attacks.", "Keep TLS verification enabled and fix trust store/certificate issues."),
    ("web", "low", "Missing Subresource Integrity on external script", re.compile(r"(?i)<script[^>]+src=[\"']https?://(?![^\"']*integrity=)[^\"']+[\"']"), "External scripts without SRI can be risky if the third-party asset is compromised.", "Add integrity and crossorigin attributes or self-host trusted assets."),
    ("ai", "medium", "LLM prompt includes untrusted user input", re.compile(r"(?i)(system|developer|prompt|messages).{0,120}(request|user_input|input|req\.|params|query)"), "Untrusted input in LLM prompts can cause prompt injection or tool misuse.", "Separate instructions from user data and add tool/output validation."),
    ("ai", "medium", "LLM output rendered without sanitization", re.compile(r"(?i)(innerHTML|dangerouslySetInnerHTML|v-html|mark_safe|safe).{0,120}(llm|openai|completion|assistant|model_output)"), "Rendering model output as HTML can create XSS if output is attacker-influenced.", "Render model output as text or sanitize with a strict allowlist."),
]
route_exposure_patterns = [
    ("secrets", "medium", "API documentation route exposed", re.compile(r"(?i)(swagger|openapi|api-docs|redoc|docs)"), "API documentation routes can disclose endpoints and schemas.", "Protect API docs in production or restrict them to trusted users/networks."),
    ("config", "medium", "Debug or actuator route exposed", re.compile(r"(?i)(__debug|debug|actuator|health|metrics|env|phpinfo)"), "Debug and actuator routes can expose operational details.", "Disable or protect debug/actuator routes in production."),
    ("web", "medium", "GraphQL route may expose introspection", re.compile(r"(?i)(graphql|graphiql|playground)"), "GraphQL endpoints often need production introspection and playground controls.", "Disable introspection/playground in production unless explicitly required."),
]

def read_prefix(path, limit=120000):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            return handle.read(limit)
    except OSError:
        return ""

for current, dirs, files in os.walk(root):
    dirs[:] = [d for d in dirs if d not in {".scan-sh", ".scan-sh-runner", "node_modules", "vendor", ".venv", "venv", "__pycache__"}]

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
        rel_path = os.path.relpath(path, root).replace(os.sep, "/")
        if lower.startswith("security-report") and lower.endswith(".json"):
            continue
        parts = set(rel_path.split("/"))

        is_env_template = lower in {".env.example", ".env.sample", ".env.template", ".env.dist", ".env.local.example"}
        if (lower == ".env" or lower.startswith(".env.")) and not is_env_template:
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
        elif lower.endswith(".map") and parts.intersection(web_dirs):
            add(
                "secrets",
                "medium",
                "JavaScript source map in web-servable directory",
                path,
                "Source maps can expose original application source code and comments.",
                "Do not publish production source maps unless access is controlled.",
                f"Source map file found at {rel_path}.",
            )
        elif lower in {"swagger.json", "openapi.json", "api-docs.json"} or ("swagger" in lower and parts.intersection(web_dirs)):
            add(
                "secrets",
                "medium",
                "API documentation artifact present",
                path,
                "API documentation artifacts can reveal endpoints, schemas, and internal models.",
                "Restrict API documentation in production or remove generated docs from public deployments.",
                f"API documentation-like file found at {rel_path}.",
            )

        generated_content = (
            rel_path.startswith("storage/framework/")
            or rel_path.startswith("bootstrap/cache/")
            or (rel_path.startswith("public/build/assets/") and not lower.endswith(".map"))
        )
        if generated_content:
            continue

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

        if lower in {".env", ".env.production", ".env.prod"}:
            for line_no, line_text in enumerate(content.splitlines(), start=1):
                if re.match(r"(?i)^\s*APP_DEBUG\s*=\s*(true|1|yes)\s*$", line_text):
                    add(
                        "config",
                        "high",
                        "Production debug mode enabled",
                        path,
                        "Debug mode can expose stack traces, SQL errors, paths, and environment details.",
                        "Set APP_DEBUG=false in production and clear framework config caches.",
                        "APP_DEBUG is enabled in an environment file. Secret values are not printed.",
                        line_no,
                    )
                if re.match(r"(?i)^\s*(APP_ENV|NODE_ENV|ENV)\s*=\s*(local|development|dev)\s*$", line_text):
                    add(
                        "config",
                        "medium",
                        "Development environment configured",
                        path,
                        "Development mode can enable unsafe defaults in production deployments.",
                        "Use production environment settings on public deployments.",
                        "Development environment marker found. Secret values are not printed.",
                        line_no,
                    )

        _, suffix = os.path.splitext(lower)
        should_run_static_patterns = lower not in lockfile_names and not is_env_template and not lower.startswith(".env")
        route_like_file = (
            rel_path.lower().startswith("routes/")
            or rel_path.lower().endswith(("urls.py", "router.py", "routes.py"))
            or "/routes/" in rel_path.lower()
        )

        if suffix in text_suffixes or lower.startswith(".env") or lower == "dockerfile":
            for line_no, line_text in enumerate(content.splitlines(), start=1):
                if should_run_static_patterns:
                    for category, severity, title, regex, description, remediation in static_patterns:
                        if regex.search(line_text):
                            if title == "JWT created without visible expiry" and re.search(r"(?i)(exp|expiresIn|ttl|expiration)", line_text):
                                continue
                            add(
                                category,
                                severity,
                                title,
                                path,
                                description,
                                remediation,
                                f"Static pattern matched on line {line_no}. Sensitive values are not printed.",
                                line_no,
                            )
                            break
                if route_like_file:
                    for category, severity, title, regex, description, remediation in route_exposure_patterns:
                        if regex.search(line_text):
                            add(
                                category,
                                severity,
                                title,
                                path,
                                description,
                                remediation,
                                f"Route/debug exposure pattern matched on line {line_no}.",
                                line_no,
                            )
                            break
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
