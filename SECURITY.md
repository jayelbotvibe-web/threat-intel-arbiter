# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| main branch | ✅ Active development |
| Tagged releases | ✅ Supported |

## Reporting a Vulnerability

**Do not open a public issue.** Email the maintainer directly. Include:

- A clear description of the vulnerability
- Steps to reproduce
- Affected versions
- Any potential mitigations you've identified

You should receive a response within 72 hours. We aim to patch critical vulnerabilities within 7 days.

## Security Model

Threat Intel Arbiter is a **threat prioritization engine** deployed as a single binary on internal infrastructure. Its attack surface consists of:

### Trust boundaries

1. **MISP API (outbound)** — the arbiter pulls events from a trusted MISP instance. Compromised MISP events are the primary threat vector (see XSS mitigations below).
2. **Web dashboard (:8080)** — authenticated web UI accessible to SOC analysts. Multi-user with admin/reader roles.
3. **Admin API (:8080)** — write operations require admin role or `X-Arbiter-Key` header.
4. **SQLite database** — single file on disk. Contains all alerts, user credentials (Argon2id hashed), session tokens (SHA-256 hashed), and tech stack inventory. Treat this file as sensitive.

### Mitigations in place

| Threat | Mitigation |
|---|---|
| Feed-derived XSS | All MISP event content rendered via `escapeHTML()` before DOM insertion. `Content-Security-Policy` header planned. |
| Credential brute-force | Rate limiting: 10 attempts/account/5min, 20 attempts/IP/5min. |
| Session hijacking | Cookies: `HttpOnly`, `Secure` (when TLS), `SameSite=Strict`. Session tokens hashed at rest (SHA-256). |
| Password database leak | Argon2id with 64MB memory, 3 iterations, 4 threads. Legacy SHA-256 hashes transparently upgraded on login. |
| Default credentials | First-run admin password is randomly generated (16 chars, printed to stdout once). No hardcoded defaults. |
| Information disclosure | `/health` returns liveness only. Detailed status at `/api/status` (requires auth). |
| API key compromise | Key stored as env var. Hashing and scoping planned for future release. |

### Recommendations for deployers

- **Run behind a TLS reverse proxy** (nginx, Caddy) or enable TLS directly.
- **Restrict port 8080** to localhost or trusted network only.
- **Set restrictive file permissions** on `data/arbiter.db` (0600). This file is a map of your vulnerabilities.
- **Rotate `ARBITER_ADMIN_KEY`** regularly.
- **Change the default admin password** on first login.

### Dependencies

- `modernc.org/sqlite` — pure Go SQLite driver
- `golang.org/x/crypto` — Argon2id password hashing (Go team extended library)

Vulnerability scanning via `govulncheck` is recommended on each build.
