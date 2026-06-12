# Scope And Limitations

## In Scope

This scanner checks files at rest.

It can scan:

```text
source code
config files
Dockerfile
Kubernetes YAML
Terraform HCL
CI/CD workflows
dependency manifests
Git metadata/history when gitleaks is available
```

## Out Of Scope

This scanner does not actively attack or browse a website.

It does not do:

```text
live XSS testing
live CSRF testing
live SSRF testing
open port scanning
TLS/cipher scanning
DNS takeover checks
cloud account API checks
business logic testing
authenticated user-flow testing
browser automation
```

## Important Limitation

Source-code scanning finds risk patterns.

It cannot always prove exploitability.

Example:

```text
The scanner may find redirect(request.args.get("next")).
That is a risky open redirect pattern.
But a developer still needs to confirm whether validation happens elsewhere.
```

## Best Use

Use this scanner as:

```text
pre-deployment source review
CI/CD security gate
server-side code audit
early warning system
client security health check
```

It should complement, not replace:

```text
manual pentesting
external web scanning
cloud security review
secure code review
runtime testing
```

