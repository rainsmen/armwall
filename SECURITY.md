# Security Policy

## Supported Versions

Security fixes are released on the latest minor version series.

| Version | Supported          |
| ------- | ------------------ |
| 0.8.x   | :white_check_mark: |
| < 0.8.0 | :x:                |

## Built-in Security Boundaries

- Web management defaults to private LAN access (`ARMWALL_WEB_ACCESS=lan`) with strict CIDR allowlists, constant-time Bearer Token verification, per-IP rate limiting, and strict CSP (`default-src 'self'`).
- Core updates and installations enforce HTTPS (including redirects), SHA256 checksum verification, ELF architecture checks, and safe archive extraction.
- Sensitive node credentials are masked on `/api/state` and stored in SQLite / `/etc/armwall/armwall.env` with restrictive file permissions (`0600`).

## Reporting a Vulnerability

If you discover a security vulnerability within ArmWall, please report it privately:

1. **Do not disclose the issue publicly** in GitHub issues or discussions.
2. Email the maintainers directly or use GitHub Private Vulnerability Reporting.
3. Include detailed steps to reproduce the issue, proof of concept, and affected environment.

We take security issues seriously and will review and respond as quickly as possible.
