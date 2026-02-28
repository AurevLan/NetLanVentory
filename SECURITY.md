# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.4.x   | Yes — current stable |
| < 0.4   | No — please upgrade |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report security issues privately via **[GitHub Security Advisories](https://github.com/AurevLan/NetLanVentory/security/advisories/new)**.

Include in your report:
- Description of the vulnerability and its potential impact
- Steps to reproduce (proof of concept if possible)
- Affected version(s)
- Suggested fix if you have one

You will receive an acknowledgement within **48 hours** and a status update within **7 days**.

## Security standards

This project targets compliance with:
- [ANSSI — Guide de sécurité du développement logiciel](https://www.ssi.gouv.fr/)
- [OWASP Top 10](https://owasp.org/Top10/)
- [OWASP API Security Top 10](https://owasp.org/API-Security/)

## Security features

- JWT authentication with `sub`, `exp`, `iss` claim validation
- Bcrypt password hashing
- Fernet-encrypted SSH credentials at rest
- HTTP security headers on every response (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- Rate limiting (slowapi): 10 req/min on login, 5 req/min on SSH scan, 200 req/min global
- Input validation at API boundary (IP, MAC, FQDN, URL scheme)
- CORS configurable via `CORS_ALLOWED_ORIGINS`; no wildcard with credentials
