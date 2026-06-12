# System Overview

`scan.sh` is a source-code-only security scanner.

It is designed to be copied into a client's codebase and run on the client's own server, CI runner, or cron job.

It does not scan a live website from the outside. It reads files that already exist in the codebase or server folder.

## Main Goal

The goal is to find security problems that are visible from source code and configuration files.

Examples:

```text
.env files
.git folders
backup SQL files
private keys
hardcoded secrets
dangerous code patterns
vulnerable dependencies
Docker/Kubernetes/Terraform mistakes
CI/CD secrets
debug mode
weak auth/session logic
```

## Why This Is Useful

Many security problems happen before an attacker even touches the website.

For example:

```text
A developer leaves a .env file on the server.
A backup.sql file is accidentally deployed.
A Dockerfile runs as root.
A GitHub Actions workflow prints secrets.
Code uses eval() or shell=True with user input.
Terraform exposes a database to the internet.
```

`scan.sh` helps catch these issues early.

## How It Fits With Other Security Tools

This scanner protects from the source-code side.

```text
External scanner:
  Tests what a hacker can see from the internet.

Script tracking:
  Confirms installed script behavior and activity.

scan.sh:
  Checks the actual source code, config files, dependencies, and deployment files.
```

Together, these layers provide broader protection.

