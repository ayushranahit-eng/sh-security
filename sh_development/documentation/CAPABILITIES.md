# Capabilities

This scanner detects vulnerabilities that can be found from source code, dependency files, Git data, and configuration files.

## 1. Secrets

Finds secret exposure risks.

Examples:

```text
.env
private.key
AWS keys
API tokens
hardcoded session secrets
database passwords in config files
```

Why it matters:

Secrets can allow attackers to access cloud accounts, databases, APIs, or servers.

## 2. Risky Files

Finds files that should not be deployed or committed.

Examples:

```text
.git/
backup.sql
*.bak
*.old
public/package.json
```

Why it matters:

These files can expose source history, database data, or technology details.

## 3. SAST Code Patterns

Finds risky code without running the app.

Examples:

```python
eval(request.args.get("expression"))
subprocess.check_output(cmd, shell=True)
pickle.loads(request.data)
yaml.load(request.data)
```

Why it matters:

These patterns can lead to code execution, command injection, deserialization attacks, or unsafe parsing.

## 4. Auth And Session Mistakes

Finds weak authentication/session logic.

Examples:

```javascript
session({ secret: "hardcoded-session-secret" })
jwt.verify(token, "secret", { ignoreExpiration: true })
password === "password123"
```

Why it matters:

Auth mistakes can allow account takeover, weak sessions, or token misuse.

## 5. Debug And Framework Config

Finds risky framework settings.

Examples:

```python
DEBUG = True
ALLOWED_HOSTS = ["*"]
app.run(debug=True)
```

Why it matters:

Debug settings can expose stack traces, environment details, and internal behavior.

## 6. Logging Secrets

Finds code that logs sensitive values.

Examples:

```python
logging.info("using api token %s", token)
```

```javascript
console.log("password", req.body.password)
```

Why it matters:

Secrets in logs can leak through log dashboards, backups, support exports, or server files.

## 7. SSRF And Open Redirect Patterns

Finds risky user-controlled URLs.

Examples:

```python
requests.get(request.args.get("url"))
redirect(request.args.get("next"))
```

Why it matters:

SSRF can reach internal systems. Open redirects can help phishing and auth-flow abuse.

## 8. File Upload Risks

Finds unsafe upload filename usage.

Example:

```python
uploaded.save(os.path.join("uploads", uploaded.filename))
```

Why it matters:

User-supplied filenames can cause path tricks, overwrites, or unsafe file storage.

## 9. Docker

Finds risky Dockerfile patterns.

Examples:

```dockerfile
ARG API_TOKEN=secret-build-token
ADD . /app
RUN chmod 777 /app
```

Why it matters:

Containers should avoid secrets in images, root execution, and world-writable permissions.

## 10. Kubernetes

Finds risky Kubernetes settings.

Examples:

```yaml
privileged: true
runAsUser: 0
hostPath:
image: app:latest
```

Why it matters:

Bad Kubernetes security context can make container compromise much more damaging.

## 11. Terraform / Cloud IaC

Finds risky infrastructure definitions.

Examples:

```hcl
cidr_blocks = ["0.0.0.0/0"]
publicly_accessible = true
storage_encrypted = false
acl = "public-read"
```

Why it matters:

IaC mistakes can expose databases, storage, servers, or cloud resources.

## 12. CI/CD

Finds workflow security risks.

Examples:

```yaml
- run: echo "API_TOKEN=hardcoded_ci_token"
- uses: actions/checkout@v4
on: pull_request_target
```

Why it matters:

CI/CD workflows often have access to secrets and deployment permissions.

## 13. SCA / Dependency CVEs

`osv-scanner` support is wired in.

It can scan files like:

```text
package.json
package-lock.json
requirements.txt
poetry.lock
go.mod
Gemfile.lock
```

Why it matters:

Old dependencies may contain known public vulnerabilities.

## 14. Git History Secrets

`gitleaks` support is wired in.

It can scan current files and Git history for leaked secrets.

Why it matters:

Removing a secret from the latest file is not enough if it still exists in old commits.

