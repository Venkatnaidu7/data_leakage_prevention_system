# Security Policy

## Supported Versions

Only the current main development branch and the latest released tags receive security patches.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

The DLP System team takes defensive security and product integrity seriously. If you identify a security vulnerability in this software:

1. **Do not disclose the issue publicly.** Do not open a public GitHub issue or discuss vulnerabilities in public forums.
2. Submit your vulnerability report privately to the security contact designated by your organization or via email to `security@example.com` (replace with operational security inbox).
3. Include the following details to facilitate rapid triage:
   - Vulnerability category (e.g., authentication bypass, injection, IDOR, sensitive data leakage in logs, rate limit evasion).
   - Step-by-step reproduction instructions or a minimal proof of concept script using synthetic data only.
   - Potential impact assessment.
   - Any proposed remediation or patches.

## Incident Response & Remediation SLA

- **Acknowledgment:** Within 24-48 business hours.
- **Triage & Confirmation:** Within 5 business days.
- **Remediation & Advisory:** Security fixes will be backported and released in coordinated disclosure cycles.

## Development & Deployment Security Guidelines

- Never commit real secrets, private keys, API tokens, or customer data to this repository.
- Use synthetic or masked test data exclusively.
- All code changes undergo automated static analysis (`ruff`, `bandit`) and vulnerability scanning prior to merge.
