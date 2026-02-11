# Security Policy

## Supported versions

Security fixes are applied to `main` for pre-1.0 releases.

## Reporting vulnerabilities

Use GitHub Security Advisories for private disclosure.

Please include:

- impact
- reproduction
- affected component
- optional patch suggestion

## Security posture in this repo

- deterministic triage path (no arbitrary code execution)
- strict JSON request parsing in API layer
- no sensitive payload leakage in metrics
- test coverage for high-risk logic paths
