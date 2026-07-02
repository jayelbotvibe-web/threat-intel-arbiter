# Threat Intel Arbiter

**Org-context-aware threat prioritization with SSVC actions and ATT&CK tagging.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go)](https://go.dev/)
[![CI](https://github.com/jayelbotvibe-web/threat-intel-arbiter/actions/workflows/test.yml/badge.svg)](https://github.com/jayelbotvibe-web/threat-intel-arbiter/actions/workflows/test.yml)

Single Go binary. One dependency (SQLite driver). Deploy in 60 seconds with Go 1.25+.

Threat Intel Arbiter transforms raw threat intelligence from MISP and CISA KEV into organisation-specific, scored, and explained actions. It answers one question:

> **Should this organisation care about this threat right now?**

Every alert includes: **Severity** + **Confidence** + **Action** + **Explanation** with full risk score breakdown.

---

## What It Is

- ✅ **Threat prioritization engine** — scores threats against your tech stack, sector, and exposure
- ✅ **Multi-source** — MISP + CISA KEV today, NVD + GitHub Advisory on roadmap
- ✅ **SSVC triage** — action cards (Track / Act / Monitor / Snooze) with keyboard navigation
- ✅ **ATT&CK tagging** — automatically maps threats to MITRE ATT&CK techniques
- ✅ **EDR integration** — pushes IOCs to CrowdStrike Falcon in real-time
- ✅ **Multi-user dashboard** — admin/reader roles, inline editing, CSV import from CMDB
- ✅ **Pull-all, filter-local** — fetches everything from MISP, matches against your context internally

## What It Is NOT

- ❌ A threat intelligence platform — [MISP](https://www.misp-project.org/) does that
- ❌ A vulnerability scanner — Nessus, Qualys, etc. do that
- ❌ A SIEM or SOAR
- ❌ A CMDB — it imports from one

---

## Quick Start

```bash
# Prerequisites: Go 1.25+, a running MISP instance
go build -o arbiter ./cmd/arbiter/

# Set up your tech stack
cp config/techstack.csv.example config/techstack.csv

# Run
export MISP_API_KEY="your-misp-api-key"
export ARBITER_ADMIN_KEY="your-admin-key"
./arbiter --config ./config/
```

Open **http://localhost:8080** — login with username `admin` and the password printed to stdout on first start.

---

## How It Works

```
                    ┌──────────────────────────────────────────────────────┐
                    │         Threat Intel Arbiter (single binary)           │
                    │                                                       │
  MISP (pull ALL) ──┤──► Normalize ──► Filter ──► Match ──► Score          │
  CISA KEV         ──┤       │                                   │         │
                    │       │  CVEs · CVSS · tags · actors        ▼         │
                    │       │  IOCs (IPs · domains · hashes)  Explain ──► Route
                    │       │                                        │      │
                    │       │                                        ├──► Slack
                    │       │                                        ├──► Teams
                    │       │                                        ├──► Email
                    │       │                                        └──► CrowdStrike
                    │       │                                               │
                    │       └──► EDR Pipeline ───────► Falcon API           │
                    │              extract · filter · dedup · batch          │
                    │                                                       │
                    │  SQLite: events · alerts · techstack                  │
                    │           users · sessions · dedup                    │
                    │                                                       │
                    │  Web dashboard on :8080 (multi-user auth)              │
                    └───────────────────────────────────────────────────────┘
```

1. **Pull** — fetches ALL events from MISP (no galaxy/tag/CVE pre-filter). MISP acts as an aggregation channel for peers, ISACs, OSINT feeds, commercial, and government sources. Filtering happens locally against your context.
2. **Normalize** — extracts CVEs, CVSS, tags, threat actors, references, AND IOCs (IPs, domains, hashes) for EDR integration. Canonical ThreatEvent model is source-agnostic.
3. **Filter** — drops TLP:RED, disputed CVEs, known false positives via MISP warning lists.
4. **Match** — pluggable matchers: CVEMatcher (version-aware), SectorMatcher (taxonomy tags), KEVMatcher (active exploitation).
5. **Score** — 4 dimensions: Likelihood × Impact × Exposure ÷ max, with Confidence as a separate dimension.
6. **Explain** — human-readable breakdown from the same struct that computed the score. No separate code path.
7. **Route** — by severity + confidence. Critical+high → #sec-alerts. Medium → weekly digest. Low → log only. IOCs → CrowdStrike Falcon EDR.
8. **Feedback** — false positives marked by analysts feed back into risk calibration.

### Why Pull-All, Filter-Local

The arbiter does **not** query MISP by galaxy, tag, or CVE. It calls:

```
GET /events/restSearch?returnFormat=json&limit=100
```

Pre-filtering at the MISP API level misses threats: an untracked actor exploiting a CVE in your stack, an event without galaxy tags but with sector-relevant taxonomies, or a feed you don't subscribe to that still contains relevant CVEs. MISP is a threat intel aggregation channel, not a filtering gate.

### Why MISP-First

Leading with MISP means v1 ships with the full product experience — all four risk dimensions have data to work with. SectorMatcher uses MISP taxonomies. Confidence scoring uses sightings and community trust. The explainability engine has something to explain beyond "CVSS is high," which every tool already does.

NVD-only would produce a thinner product indistinguishable from a CVSS filter. MISP data gives us the differentiation. v2 adds NVD and GitHub Advisory to reach orgs without MISP.

---

## Web Dashboard

Built-in single-page application — no framework, no build step, pure HTML/CSS/JS served from the binary.

| Screen | Description |
|---|---|
| **Alerts** | Searchable/filterable table. Click any row for full risk breakdown with explanation, CVSS, matched apps, and action labels. |
| **Tech Stack** | Inline-editable. Version (click to edit), criticality (dropdown), internet-facing (dropdown). Add/delete apps with custom confirmation dialog. |
| **Import CSV** | Drag-and-drop bulk upload from CMDB (ServiceNow, Ivanti, Snipe-IT, etc.). Delta detection shows what was added/removed. |
| **Users** | Admin-only. Create/edit/delete user accounts with admin/reader roles. |
| **Settings** | Configure admin API key, Slack/Teams/Email webhook URLs, CrowdStrike credentials. |

### User Accounts

| Role | Permissions |
|---|---|
| **admin** | Full access: alerts, tech stack CRUD, CSV import, user management, settings |
| **reader** | View-only: alerts list, alert details, tech stack view. No write access. |

- Session cookie auth (HttpOnly, SameSite=Strict), 12-hour expiry
- Password hashing: Argon2id with legacy SHA-256 upgrade on login
- Session tokens: SHA-256 hashed at rest in SQLite
- Default admin seeded on first start with random password (printed to stdout once)
- Programmatic access via `X-Arbiter-Key` header (API key always has admin privileges)

---

## Deployment

```bash
go build -o arbiter ./cmd/arbiter/
# → ~16MB static binary
# → Copy to any Linux/macOS/Windows machine
# → Set 4 env vars. Run. Done.
```

- Zero infrastructure: no Docker, Postgres, Redis, Python, Node
- SQLite is a single file — backup = `cp data/arbiter.db data/arbiter.db.bak`
- Cross-compile: `GOOS=linux GOARCH=amd64 go build`

---

## Further Reading

| Document | Covers |
|---|---|
| [System Design](docs/design.md) | Full architecture, scoring formula, database schema, positioning strategy |
| [EDR — CrowdStrike Falcon](docs/edr-crowdstrike.md) | IOC extraction, OAuth2, batching, dedup, mock mode |
| [Architecture Diagram](docs/architecture.html) | Interactive SVG of the full pipeline |
| [API Reference](#api) | Complete endpoint reference (below) |
| [Security Policy](SECURITY.md) | Threat model, mitigations, vulnerability reporting |

---

## v1 Sources

- **MISP** ★ primary — REST API, HMAC-SHA256 auth. Pulls every 15 minutes. Tracks NEW/MODIFIED/DELETED events. All galaxy, taxonomy, and sighting data extracted.
- **CISA KEV** ★ secondary — public JSON, no auth. Pulls daily. Every entry is a confirmed actively-exploited vulnerability.

v2 roadmap: NVD API, GitHub Advisory, vendor feeds, RSS connectors.

---

## Design Decisions

| Decision | Why |
|---|---|
| Pull-all, filter-local | Pre-filtering at MISP would miss threats. Match engine has full org context. |
| Canonical ThreatEvent from day 1 | Adding a source = 1 normalizer. Without this = rewrite engine. |
| Multi-user auth with admin/reader roles | SOC teams need separate logins. Self-contained in SQLite, no external IdP. |
| Argon2id over bcrypt | golang.org/x/crypto is the closest thing to stdlib for a slow KDF. Self-describing hash format with legacy SHA-256 transparent upgrade. |
| Single binary, one per org | Deploy in minutes. Multi-tenancy is v2. |
| EDR integration via IOCs, not just alerts | Close the loop from detection to prevention. Feed IOCs to CrowdStrike Falcon in real-time. |

---

## Technology Stack

| Component | Technology | Why |
|---|---|---|
| Language | Go 1.25+ | Single binary, stdlib covers ~95% |
| HTTP | net/http | Standard library |
| Database | SQLite (modernc.org/sqlite) | Pure Go, zero-config, file-based |
| Auth | golang.org/x/crypto/argon2 + crypto/sha256 | Argon2id password hashing + session tokens |
| **Dependencies** | **1** | modernc.org/sqlite (and its transitive deps) |

---

## File Structure

```
threat-intel-arbiter/
├── cmd/arbiter/main.go          # Entry point
├── internal/
│   ├── source/                  # MISP + KEV connectors + normalizers
│   ├── model/                   # Canonical ThreatEvent, Match, Alert, OrgContext
│   ├── filter/                  # Warning list filter
│   ├── match/                   # CVEMatcher, SectorMatcher, KEVMatcher + version subsystem
│   ├── risk/                    # 4-dim scoring + explainability + dedup
│   ├── notify/                  # Slack, Teams, Email, Webhook, CrowdStrike routers
│   ├── api/                     # HTTP server, auth, dashboard
│   ├── store/                   # SQLite layer
│   └── config/                  # JSON config loading + CSV parsing
├── config/                      # Example config files
├── docs/                        # Design document, architecture diagrams, EDR docs
└── data/                        # SQLite database (created at runtime)
```

---

## API Reference

All endpoints require authentication (session cookie or `X-Arbiter-Key`). `/health` is the only public endpoint.

### Auth

| Endpoint | Method | Description |
|---|---|---|
| `/login` | GET | Login page (HTML) |
| `/auth/login` | POST | `{username, password}` → session cookie + `{role, username}` |
| `/auth/logout` | POST | Clear session |
| `/auth/session` | GET | Current `{username, role}` |

### Alerts & Data

| Endpoint | Method | Description |
|---|---|---|
| `/api/alerts` | GET | List alerts. Query: `?severity=`, `?status=`, `?q=`, `?app=` |
| `/api/alerts/:id` | GET | Single alert with explanation, action, routed_to |
| `/api/techstack` | GET | Full tech stack with all fields |
| `/api/stats` | GET | Alert counts by severity + apps tracked |
| `/health` | GET | Public. MISP status, KEV entries, alert counts |

### Admin (admin role or API key required)

| Endpoint | Method | Description |
|---|---|---|
| `/admin/ack/:id` | POST | Update alert status: `acked`, `false_pos`, `resolved` |
| `/admin/import` | POST | Upload techstack.csv, delta detection |
| `/admin/pull` | POST | Trigger immediate pull from all sources |
| `/admin/techstack` | POST | Add single app |
| `/admin/techstack` | PUT | Update single app |
| `/admin/techstack` | DELETE | Remove single app `{name}` |
| `/admin/users` | GET | List all users |
| `/admin/users` | POST | Create user `{username, password, role}` |
| `/admin/users` | PUT | Update user role/password |
| `/admin/users` | DELETE | Remove user (cannot delete last admin) |

---

## License

MIT — see [LICENSE](LICENSE) for full text.
