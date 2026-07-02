# Threat Intel Arbiter — Threat Prioritization Engine

**Deploy in 60 seconds. Single Go binary. One dependency (SQLite driver).**

Threat Intel Arbiter transforms raw threat intelligence from MISP and CISA KEV into organisation-specific, scored, and explained actions. It answers one question:

> **Should this organisation care about this threat right now?**

Every alert includes: **Severity** + **Confidence** + **Action** + **Explanation** with full risk score breakdown.

---

## How it works

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
                    │       │                                        └──► Crowdstrike
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
5. **Score** — 4 dimensions: Likelihood × Impact × Exposure ÷ max, with Confidence as a separate dimension. Raw-points/max-points formula with exposure baseline to prevent internal threats from collapsing to zero.
6. **Explain** — human-readable breakdown from the same struct that computed the score. No separate code path.
7. **Route** — by severity + confidence. Critical+high → #sec-alerts. Medium → weekly digest. Low → log only. IOCs → Crowdstrike Falcon EDR (mock-first, OAuth2, dedup, batching).
8. **Feedback** — false positives marked by analysts feed back into risk calibration. The moat: months of operational data produce tuning a competitor can't replicate.

---

## Quick Start

```bash
# Build
go build -o arbiter ./cmd/arbiter/

# Set up your tech stack
cp config/techstack.csv.example config/techstack.csv

# Run
export MISP_API_KEY="your-misp-api-key"
export ARBITER_ADMIN_KEY="your-admin-key"
./arbiter --config ./config/
```

Open **http://localhost:8080** — login with the username `admin` and the password printed to stdout on first start.

---

## Web Dashboard

Built-in single-page application. No framework, no build step — pure HTML/CSS/JS served from the binary.

| Screen | Description |
|---|---|
| **Alerts** | Searchable/filterable table. Click any row for full risk breakdown with explanation, CVSS, matched apps, and action labels. |
| **Tech Stack** | Inline-editable. Version (click to edit), criticality (dropdown), internet-facing (dropdown). Add/delete apps with custom confirmation dialog. |
| **Import CSV** | Drag-and-drop bulk upload from CMDB (ServiceNow, Ivanti, Snipe-IT, etc.). Delta detection shows what was added/removed. |
| **Users** | Admin-only. Create/edit/delete user accounts with admin/reader roles. |
| **Settings** | Configure admin API key, Slack/Teams/Email webhook URLs. |

### User Accounts

Multi-user with role-based access control:

| Role | Permissions |
|---|---|
| **admin** | Full access: alerts, tech stack CRUD, CSV import, user management, settings |
| **reader** | View-only: alerts list, alert details, tech stack view. No write access. |

- Session cookie auth (HttpOnly, SameSite=Strict), 12-hour expiry
- Password hashing: Argon2id (golang.org/x/crypto/argon2) with legacy SHA-256 upgrade on login
- Session tokens: SHA-256 hashed at rest in SQLite
- Default admin seeded on first start with random password (printed to stdout once)
- Programmatic access via `X-Arbiter-Key` header (API key always has admin privileges)

---

## Architecture

![Architecture Overview](docs/architecture-overview.png)

> [Architecture diagram →](docs/architecture.svg)
> [Complete design document →](docs/design.md)

### Pull-All, Filter-Local

The arbiter does **not** query MISP by galaxy, tag, or CVE. It calls:

```
GET /events/restSearch?returnFormat=json&limit=100
```

The only filter is `timestamp` for incremental polling. Every event MISP returns is pulled — regardless of which galaxy cluster or taxonomy tag it carries. All filtering happens inside the arbiter against the organisation's context:

- **CVEMatcher** — "does this CVE match an app in our stack?"
- **SectorMatcher** — "do the taxonomy tags match our sector?"
- **KEVMatcher** — "is this CVE actively exploited?"

Pre-filtering at the MISP API level would miss threats: an untracked actor exploiting a CVE in your stack, an event without galaxy tags but with sector-relevant taxonomies, or a feed you don't subscribe to that still contains relevant CVEs.

### MISP as Aggregation Channel

MISP ingests from peers, ISACs, OSINT feeds, commercial providers, government sources, and internal tools. The arbiter doesn't connect to these directly — MISP is the single integration point. The arbiter benefits from all upstream enrichment without per-feed connectors.

### Scoring Formula

```
risk_score = (likelihood × impact × exposure) / (5 × 5 × 3)

severity: ≥0.50 → critical, ≥0.25 → high, ≥0.10 → medium, <0.10 → low
confidence: ≥3 → HIGH, ≥2 → MEDIUM, <2 → LOW
```

Every threshold and weight is configurable in `risk.json`.

### Database

SQLite (pure Go, no CGO). 12 tables:

| Table | Purpose |
|---|---|
| `sources` | Registered threat sources |
| `events` | Normalized ThreatEvent JSON |
| `alerts` | Generated alerts with severity, confidence, explanation |
| `tech_stack` | Application inventory |
| `routing_rules` | Severity+confidence → channel mapping |
| `risk_config` | Dimension weights and thresholds |
| `matchers_config` | Enabled matchers |
| `dedup_hashes` | 7-day TTL dedup cache |
| `sighting_cache` | Recent sighting counts per CVE |
| `notification_targets` | Slack/Teams/Email config |
| `users` | User accounts (password hash, role) |
| `sessions` | Active login sessions (token, expiry) |

**Alert state machine:** `new → acked → false_pos → resolved`

---

## Technology Stack

| Component | Technology | Why |
|---|---|---|
| Language | Go 1.25+ | Single binary, stdlib covers ~95% |
| HTTP | net/http | Standard library |
| Database | SQLite (modernc.org/sqlite) | Pure Go, zero-config, file-based |
| Auth | golang.org/x/crypto/argon2 + crypto/sha256 | Argon2id password hashing + session tokens |
| JSON | encoding/json | Standard library |
| SMTP | net/smtp | Standard library |
| TLS | crypto/tls | Built into net/http |
| HMAC | crypto/hmac + crypto/sha256 | MISP API auth |
| **Dependencies** | **1** | modernc.org/sqlite (and its transitive deps) |

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
| Custom confirm over browser confirm() | Chrome/Edge permanently suppress native confirm() — breaks delete flows. |
| Tech stack deletion stops future, not past | Alerts are evidence. Users bulk-resolve existing alerts for removed apps. |
| Single binary, one per org | Deploy in minutes. Multi-tenancy is v2. |
| EDR integration via IOCs, not just alerts | Close the loop from detection to prevention. Feed IOCs to Crowdstrike Falcon in real-time. |

## EDR Integration — Crowdstrike Falcon

Threat Intel Arbiter closes the loop from detection to prevention by forwarding extracted IOCs (IPs, domains, hashes) to your EDR platform. **Crowdstrike Falcon** is the first supported integration, with the architecture ready for SentinelOne, Microsoft Defender, and others.

### How it works

```
MISP Event → Normalizer → Extract IOCs → Severity filter → Crowdstrike API
                   │
        ip-src/dst → ipv4
        domain/hostname → domain
        sha256/md5 → hash
```

1. **Pull event** from MISP with IOC attributes (ip-dst, domain, sha256, md5)
2. **Extract IOCs** — map MISP attribute types to Crowdstrike IOC types
3. **Filter by severity** — only send IOCs from events meeting minimum severity (default: medium)
4. **Deduplicate** — track sent IOCs in-memory, never re-send the same value
5. **Batch** — collect IOCs, flush every 30 seconds or at 100-batch size
6. **Send** — POST to Crowdstrike Falcon API with OAuth2 authentication

### Supported IOC types

| MISP Attribute Type | Crowdstrike IOC Type |
|---|---|
| `ip-src`, `ip-dst`, `ip` | `ipv4` |
| `ipv6` | `ipv6` |
| `domain`, `hostname` | `domain` |
| `sha256` | `hash_sha256` |
| `md5` | `hash_md5` |

### Crowdstrike API format

Each IOC is sent in Falcon's standard format:

```json
{
  "source": "misp",
  "action": "detect",
  "expiration": "2026-08-01T16:58:41Z",
  "type": "ipv4",
  "value": "45.153.241.187",
  "description": "C2 server - HTTP listener (MISP Event: Cobalt Strike C2)",
  "severity": "high",
  "platforms": ["windows", "mac", "linux"],
  "tags": ["tlp:amber", "eu-nis-oes:manufacturing", "CVE-2024-3400"]
}
```

### Configuration

| Env Variable | Default | Description |
|---|---|---|
| `CROWDSTRIKE_CLIENT_ID` | *(empty — mock mode)* | Falcon API client ID |
| `CROWDSTRIKE_CLIENT_SECRET` | *(empty)* | Falcon API client secret |
| `CROWDSTRIKE_BASE_URL` | `https://api.crowdstrike.com` | Falcon API base URL |
| `CROWDSTRIKE_ACTION` | `detect` | `detect` or `prevent` |
| `CROWDSTRIKE_SEVERITY` | `medium` | Minimum severity: `critical`, `high`, `medium`, `low` |
| `CROWDSTRIKE_EXPIRATION` | `30` | Days until IOC expires in Falcon |

### Mock mode

When `CROWDSTRIKE_CLIENT_ID` is not set (default), the integration runs in **mock mode** — it logs what would be sent without making any network calls:

```
crowdstrike [MOCK]: would send 6 IOCs from event misp:8842:a1f0 (6 total sent)
```

The dashboard health bar shows `EDR mock` with a yellow dot. When credentials are set, it switches to `EDR online` with a green dot and sends real API calls.

### Authentication

Crowdstrike Falcon uses **OAuth2**:
1. POST `/oauth2/token` with `client_id` + `client_secret`
2. Receive `access_token` (valid ~30 minutes)
3. Use `Authorization: Bearer <token>` for IOC API calls
4. Token auto-refreshes when expired (60-second buffer)

### Deduplication

IOCs are tracked in-memory by `type:value` key (e.g., `ipv4:45.153.241.187`). Once sent, the same IOC is never re-sent — avoiding duplicate entries in Falcon and reducing API calls.

### Batching

IOCs are collected across multiple events and sent in batches:
- **Flush interval:** 30 seconds
- **Batch size:** up to 100 IOCs per POST (Falcon limit: 500)
- **Failure recovery:** failed batches are re-queued for the next flush

### Health dashboard

The EDR status is visible in the header health bar:
- 🟡 **EDR mock** — mock mode active (no credentials)
- 🟢 **EDR online** — connected with real credentials

Settings → ⚙ → API & Webhooks → EDR — Crowdstrike Falcon section for configuring Client ID, Secret, and Base URL.

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
│   ├── notify/                  # Slack, Teams, Email, Webhook, Crowdstrike routers
│   │   └── crowdstrike.go        # OAuth2, IOC batching/dedup, mock mode
│   ├── api/                     # HTTP server, auth, dashboard
│   │   ├── server.go
│   │   ├── auth.go              # Login, sessions, middleware
│   │   └── dashboard.html       # Embedded web UI
│   ├── store/                   # SQLite layer
│   │   ├── db.go                # Migrations, admin seed
│   │   ├── users.go             # User CRUD + password hashing + sessions
│   │   ├── techstack.go         # Import, list, find
│   │   ├── alerts.go, events.go, sources.go, config.go
│   ├── config/                  # JSON config loading + CSV parsing
│   └── health/                  # /health + /metrics
├── config/                      # Example config files
├── docs/                        # Design document + architecture diagram
│   ├── design.md                # Complete system spec
│   └── architecture.html        # Interactive SVG diagram
└── data/                        # SQLite database (created at runtime)
```

### Changelog

- **Jul 2026** — Crowdstrike Falcon EDR integration: IOC extraction from MISP attributes, OAuth2 auth, batching (30s/100), dedup, mock mode, EDR health dot
- **Jul 2026** — Security hardening: Argon2id password hashing, session token hashing, XSS fixes, CSP headers, login rate limiting, username enumeration fix, TRUSTED_PROXY flag, MISP pagination fix, cursor skip fix, freshness scoring fix
- **Jul 2026** — SSVC triage console: action cards, severity-colored rows, side drawer, keyboard shortcuts (j/k/enter/a/f/r), Inter + JetBrains Mono fonts
- **Jul 2026** — Multi-user auth: admin/reader roles, session cookies, password management, login page
- **Jul 2026** — GitHub Pages: architecture diagram, SVG/PNG exports, design document
- **Jun 2026** — Initial release: KEV + MISP ingestion, CVEMatcher, risk scoring, Slack/Teams/Email routing

---

## License

MIT
