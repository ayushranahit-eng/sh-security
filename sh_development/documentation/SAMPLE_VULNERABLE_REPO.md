# Sample Vulnerable Repo

`sample-vulnerable-repo/` is a fake full-stack application used to test scanner coverage.

Recommended setup: keep this sample outside the clean scanner package and do not commit it to the public scanner repository.

Example local layout:

```text
security-testing-with-script - Copy/
  sh_development/
  sample-vulnerable-repo/
```

It is intentionally unsafe.

Do not use it as production app code.

## Structure

```text
sample-vulnerable-repo/
  backend/
    api/
    config/
    services/
  frontend/
    src/
    public/
  config/
  database/
  infra/
  k8s/
  scripts/
  public/
  .github/workflows/
```

## Backend

The backend simulates a Python API.

It contains examples for:

```text
hardcoded secrets
debug mode
SQL injection
command injection
eval()
pickle deserialization
SSRF
open redirect
unsafe YAML/XML parsing
unsafe file upload
insecure cookies
JWT mistakes
default admin credentials
logging secrets
```

## Frontend

The frontend simulates a React app.

It contains examples for:

```text
frontend API keys
GitHub-style token
debug frontend config
dangerouslySetInnerHTML
client-side redirect
Math.random token generation
old npm dependencies
```

## Config

The config files contain examples for:

```text
debug: true
wildcard CORS
admin/admin defaults
hardcoded API token
nginx autoindex
```

## Infrastructure

The IaC files contain examples for:

```text
Terraform 0.0.0.0/0 security group
public S3 policy
public S3 ACL
unencrypted RDS
public RDS
disabled deletion protection
Kubernetes privileged container
runAsUser: 0
hostPath volume
latest image tag
Docker chmod 777
Docker ARG secret
Docker ADD usage
```

## CI/CD

The GitHub Actions workflow contains examples for:

```text
hardcoded secrets in workflow commands
pull_request_target
unpinned checkout action
```

## Risky Files

The repo also includes:

```text
.env
.git/config
backup.sql
private.key
database/seed.sql
public/package.json
```

These are used to test file exposure and secret detection.

## Generated Files After Testing

When you run `scan.sh` inside this sample repo, it creates:

```text
.scan-sh/
security-report-YYYYMMDD-HHMMSS.json
```

These are scanner outputs, not part of the sample application.

`.scan-sh/` contains raw scanner data.

`security-report-*.json` is the final merged report.

You can manually delete them anytime.

They will be created again on the next scan.
