# Threat Intel Arbiter — Complete System Design Document (Foundation-First)

## What Threat Intel Arbiter Is

Threat Intel Arbiter is a **threat prioritization engine**. It transforms raw threat intelligence
from multiple sources into organisation-specific, scored, and explained actions.

It answers one question:

> **Should this organisation care about this threat right now?**

Every alert includes:
- **Severity** — how urgent is this? (critical, high, medium, low)
- **Confidence** — how sure are we? (high, medium, low)
- **Explanation** — exactly why, with evidence and score breakdown

## What threatlib Is NOT

- It is NOT a threat intelligence platform (MISP does that)
- It is NOT a vulnerability scanner (Nessus/Qualys do that)
- It is NOT a SIEM or SOAR
- It is NOT a CMDB — it imports from one

## Target Audience

| Audience | What they get | Channel |
|----------|--------------|---------|
| SOC Analysts | Critical + high severity, real-time | Slack, Teams |
| IT Operations | High severity, actionable patch alerts | Slack, Teams |
| CISO / IR Team | Medium severity, digest summary | Email |
| Security Engineers | Confidence scores, false positive feedback loop | Dashboard |

**v1 scope:** Organisations running MISP (or willing to set it up). CISA KEV provides
an immediate second source with zero setup. Broader audience reach (orgs without MISP)
comes in v2 with GitHub Advisory and generic feed connectors.

---

## Product Identity & Positioning

| Layer | Decision |
|-------|----------|
| **Product** | Threat prioritization engine |
| **Initial wedge** | Multi-source (MISP + KEV) prioritization with explainable scoring |
| **Day-one differentiator** | Deploy in minutes. Single binary. Combined MISP + KEV in one alert. |
| **Defensibility over time** | Calibration quality from operational feedback loop. Normalizer library depth. |
| **Architecture** | Multi-source from day 1. Sources are connectors, not the foundation. |
| **Deployment** | Single Go binary. One binary per organisation in v1. |

**Honest assessment:** Explainable scoring with weighted dimensions is a good feature
but not structurally hard to copy (Recorded Future, ThreatConnect, and others already
do prioritization + explanation). The moat develops over time: after months of
production data, the false-positive feedback loop produces calibration that a new
competitor cannot replicate without the same operational history. Similarly, the
normalizer library (one per source) is individually easy but collectively expensive
to replicate. The day-one differentiator is deployment simplicity — single binary,
zero infrastructure — not the scoring math itself.

### v1 Source Strategy: MISP-First (Path A)

**Decision:** v1 ships with MISP + CISA KEV as threat sources. v2 adds NVD/GitHub
Advisory to reach organisations without MISP.

**Why MISP-first:**

| Factor | MISP | NVD / GitHub Advisory |
|--------|------|----------------------|
| Data richness | Tags, taxonomies, galaxies, sightings, sector tags, actor attribution | CVE ID + CVSS + description only |
| Risk engine leverage | SectorMatcher uses sector taxonomies. Confidence uses sightings + community trust. | Both matchers inert. Confidence flat-lined. |
| Buyer intent | Already invested in threat intel — high motivation to prioritize | Anyone consumes CVEs, but low switching cost = low commitment |
| Product differentiation | Explainability shows rich evidence: "KEV + MISP sightings + sector match" | Explainability shrinks to "CVSS 9.8 + app is critical" — indistinguishable from a CVSS filter |
| Addressable market | Smaller (~5,000-10,000 MISP deployments) | Larger (any security team) |

Leading with MISP means v1 ships with the full product experience. All four risk
dimensions have data to work with. The explainability engine has something to explain.
SectorMatcher and KEVMatcher are active from day one.

NVD-first would produce a thinner product — CVE matching without context, confidence
scores that never vary, explanations that say "CVSS is high" which every tool already
does. The product wouldn't be differentiated enough to justify switching from whatever
spreadsheet or RSS feed the team already uses.

**v2 Path B:** Add NVD API and GitHub Advisory API as sources. These are free,
no-auth JSON endpoints. Each requires one normalizer (~30 lines). By v2 the risk
engine has months of calibration data and the product can genuinely claim multi-source
for both MISP and non-MISP users.

---

## System Architecture — Foundation View

```
┌─────────────────────────────────────────────────────────────┐
│                    THREAT SOURCES (connectors)               │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐               │
│  │  MISP    │  │ CISA KEV │  │ Future:      │               │
│  │ REST API │  │ JSON GET │  │ GitHub Adv.  │               │
│  │ HMAC sig │  │ no auth  │  │ Vendor feeds │               │
│  └────┬─────┘  └────┬─────┘  │ RSS · VulnCk │               │
│       │             │        └──────────────┘               │
│       ▼             ▼                                       │
│  ┌──────────────────────────────────────────────────────┐   │
│  │            NORMALIZATION LAYER                        │   │
│  │                                                       │   │
│  │  Each source → Normalizer → Canonical ThreatEvent     │   │
│  │                                                       │   │
│  │  ThreatEvent {                                        │   │
│  │    ID, Source, Title, CVEs[], CVSS,                   │   │
│  │    Tags[], Description, Timestamp,                    │   │
│  │    SourceConfidence, AffectedProducts[],              │   │
│  │    ThreatActors[], References[]                       │   │
│  │  }                                                    │   │
│  └───────────────────────┬───────────────────────────────┘   │
│                          │                                   │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │         WARNING LIST FILTER (all sources)             │   │
│  │  Drop: TLP:RED · Disputed CVEs · Known false pos.    │   │
│  └───────────────────────┬───────────────────────────────┘   │
│                          │                                   │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              MATCHING ENGINE (pluggable)              │   │
│  │                                                       │   │
│  │  Matchers:                                            │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐              │   │
│  │  │CVE Match │ │Sector    │ │KEV Match │ future...    │   │
│  │  │CVE↔Stack │ │Tag↔Org   │ │CVE in    │              │   │
│  │  │+version  │ │Profile   │ │KEV list  │              │   │
│  │  │+match_   │ │          │ │          │              │   │
│  │  │confidence│ │          │ │          │              │   │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘              │   │
│  │       └─────────────┼───────────┘                     │   │
│  │                     ▼                                 │   │
│  │              Combined Match Results                   │   │
│  └───────────────────────┬───────────────────────────────┘   │
│                          │                                   │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              RISK PRIORITIZATION ENGINE               │   │
│  │                                                       │   │
│  │  Likelihood  ─┐                                      │   │
│  │  Impact      ─┼──► Weighted geom. mean               │   │
│  │  Exposure    ─┤       → Severity + Confidence         │   │
│  │  Confidence  ─┘       → Explanation                  │   │
│  │                                                       │   │
│  │  ⚠ Thresholds are initial values. Must be calibrated  │   │
│  │    against production data via the feedback loop.     │   │
│  └───────────────────────┬───────────────────────────────┘   │
│                          │                                   │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              EXPLAINABILITY ENGINE                    │   │
│  │                                                       │   │
│  │  "CRITICAL (confidence: HIGH) because:                │   │
│  │   Likelihood 5.0/5.0: active exploitation + KEV      │   │
│  │   Impact 5.0/5.0: CVSS 9.8 + app is critical         │   │
│  │   Exposure 3.0/3.0: internet-facing                  │   │
│  │   Confidence 3.0/4.0: CISA KEV + 2 MISP feeds        │   │
│  │   Score: (5.0×5.0×3.0)/(5×5×3) = 1.00 → CRITICAL"   │   │
│  └───────────────────────┬───────────────────────────────┘   │
│                          │                                   │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Dedup → Notification Router → Slack/Teams/Email/WH  │   │
│  │  Router keys on (severity + confidence)              │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  SQLite: sources · events · tech_stack · alerts      │   │
│  │          matchers · risk_config · dedup_hashes       │   │
│  │          alert state: new→acked→false_pos→resolved   │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  GET /health · GET /metrics · Graceful shutdown             │
│  Deployment: one binary per organisation (v1)               │
└─────────────────────────────────────────────────────────────┘
```

### What the foundation enables

| Future addition | What it requires with this foundation |
|-----------------|--------------------------------------|
| New threat source (GitHub Advisory) | 1 normalizer file (~30 lines) |
| New matcher (SBOM) | 1 matcher implementing the interface |
| New risk factor | 1 field in risk config + 1 compute function |
| New notification channel | 1 notifier implementing the interface |
| Learning / adaptive scores | Historical alert data already structured |
| Multi-tenancy | org_id columns already in schema; add auth per org |

---

## Component Details

### 1. Threat Sources (connectors)

Every source produces `ThreatEvent` structs via a normalizer.

**Source: MISP (v1)**
- Connects via REST API with HMAC-SHA256 authentication
- Pulls events every 15 minutes (configurable)
- Tracks NEW, MODIFIED, and DELETED events via timestamp cursor
- Cold start: process all events from the last 7 days. Apply the full pipeline (normalize → filter → match → score). Suppress alerts with final severity below "high". This ensures sector intel, actor reports, and non-CVE events reach the matchers and build the historical baseline, even if they don't generate immediate alerts.
- Fetches warninglists and noticelists on startup for filtering
- Maps: MISP Event → ThreatEvent

**Source: CISA Known Exploited Vulnerabilities (v1)**
- Public JSON file, no authentication required
- URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- Pulls daily (KEV updates once per day)
- Each entry is a confirmed actively-exploited vulnerability
- Maps: KEV entry → ThreatEvent
- Source confidence: HIGH (CISA is authoritative)

### 2. Normalization Layer

Every source has a normalizer that produces a canonical `ThreatEvent`:

```go
type ThreatEvent struct {
    ID               string    // unique within source
    Source           string    // "misp", "cisa-kev", "github-advisory"
    SourceConfidence string    // source-reported: "high", "medium", "low"
    Title            string    // human-readable summary
    CVEs             []string  // CVE-YYYY-NNNNN
    CVSS             float64   // 0.0-10.0
    Tags             []string  // taxonomy tags, TLP, sectors, exploit markers
    Description      string    // full text
    Timestamp        time.Time // publication or modification time
    AffectedProducts []AffectedProduct
    ThreatActors     []string  // from MISP galaxies or source metadata
    References       []string  // URLs to advisories, patches, analysis
}

type AffectedProduct struct {
    Vendor       string
    Product      string
    VersionStart string
    VersionEnd   string
    VersionScheme string // detected: "semver", "date", "sap", "windows_build", "linux_kernel", "unknown"
}
```

The normalizer for each source is a pure function: `SourceEvent → ThreatEvent`.

**Why canonical from day 1:** Every component downstream (matchers, risk engine, router)
operates on `ThreatEvent`. They never import a source-specific type. Adding a new source
means writing one normalizer — zero changes to the engine, matchers, or router.

### 3. Warning List Filter

Runs BEFORE events enter the matching engine. Applies to all sources.

Filters applied:
- Known false positive IOCs (MISP warninglists, loaded at startup)
- Admin-suppressed entries (MISP noticelists)
- TLP:RED events (not distributable)
- Disputed or withdrawn CVEs
- Events older than configurable threshold (default: 30 days)

Filtered events are logged but not processed further.

### 4. Event Queue

Buffered Go channel between ingestion and matching.
- Decouples source pollers from the matching engine
- FIFO ordering
- Drained on SIGTERM (graceful shutdown)
- Configurable buffer size

### 5. Matching Engine (pluggable)

The engine accepts a list of matchers and runs them against every `ThreatEvent`.

```go
type Matcher interface {
    Name() string
    Match(event ThreatEvent, org OrgContext) []Match
}

type Match struct {
    Matcher         string  // which matcher produced this
    CVE             string
    AppName         string  // from tech stack
    AppVersion      string
    VersionAffected bool
    MatchConfidence string  // "exact_version_match", "product_only_match", "unparseable_version"
    Details         string  // human-readable match reason
}

type OrgContext struct {
    OrgID      string
    Sector     string   // eu-nis-oes-energy, dhs-ciip-finance, etc.
    Country    string
    TechStack  []App
}
```

**v1 Matchers:**

| Matcher | What it does | Input |
|---------|-------------|-------|
| **CVEMatcher** | Cross-references CVE IDs against the organisation's tech stack. Normalizes vendor names via alias map. Compares affected version ranges against installed versions using scheme-aware comparison. | ThreatEvent.CVEs + OrgContext.TechStack |
| **SectorMatcher** | Checks event tags against sector taxonomies (eu-nis-oes, dhs-ciip, nis2, targeted-threat-index). Cross-references with organisation's sector from Org Profile. Works on events with and without CVEs. | ThreatEvent.Tags + ThreatEvent.ThreatActors + OrgContext.Sector |
| **KEVMatcher** | Checks whether any CVE in the event appears in the CISA KEV catalog. If yes, marks the event as actively exploited. | ThreatEvent.CVEs + KEV cache |

**Adding a matcher in v2:** Implement the `Matcher` interface, register it in the engine. Zero changes to the engine itself.

#### Version Matching Subsystem

Version comparison is a subsystem with vendor-specific parsers, not a generic comparator.
CVE version ranges and CMDB version strings use inconsistent schemes.

**Scheme detection:** The version string is analyzed to determine its scheme:
- `semver` — 2.4.57, 1.2.3
- `date` — 2023-07-15, 2022-05
- `sap` — 7.5 SPS22, SPS22
- `windows_build` — 10.0.20348, 20348
- `linux_kernel` — 5.10.0, 5.10.0-26-generic
- `unknown` — free text, unparseable

**Per-scheme normalizer:** Each scheme has a normalizer that converts to a canonical ordered form (integer tuple or date) for comparison.

**Range comparison:** Handles "≤ 2.4.56", "2.4.0 through 2.4.56", "< 2023-07-15", "all versions before X".

**Vendor alias map:** Normalizes vendor names across sources:
- "Apache Software Foundation" → "Apache"
- "Microsoft Corporation" → "Microsoft"
- "httpd" → "Apache HTTP Server"
- etc.

**Match confidence:** Each match carries a `match_confidence` field:
- `exact_version_match` — version parsed, compared, and confirmed affected
- `product_only_match` — vendor+product matched, version unparseable or missing (conservative: assumes affected)
- `unparseable_version` — version present but scheme not recognized (conservative: assumes affected)

The risk engine can weight matches differently based on confidence (e.g., `product_only_match` reduces confidence dimension by 1).

### 6. Risk Prioritization Engine

Replaces flat additive scoring with four risk dimensions. Each dimension is computed independently using raw point scales, then combined.

#### Scoring Formula

```
raw_score = likelihood_raw × impact_raw × exposure_raw
max_score = likelihood_max × impact_max × exposure_max

risk_score = raw_score / max_score   (range: 0.0–1.0)
```

The dimensions use their natural point scales. The denominator normalizes at the end. This preserves explainability — "Likelihood: 5.0/5.0" is clearer than "Likelihood: 0.83" — while keeping the math internally consistent.

**Why not pure multiplicative?** Pure `a × b × c` with independent 0–1 factors is too aggressive. On a 0–1 scale: `0.6 × 0.6 × 0.6 = 0.216` (high) but `0.4 × 0.4 × 0.4 = 0.064` (low) — yet "moderate on all axes" is exactly the case you'd want as medium, not low. The raw-points-divided-by-max approach is a weighted product that preserves the zero-sensitivity (if any dimension is 0, score is 0) without the collapse problem.

**⚠ Calibration note:** The thresholds below are initial values derived from heuristics, not empirical data. After deployment, they must be calibrated against production data using the false-positive feedback loop. The risk.yaml configuration file makes all weights and thresholds tunable without code changes.

#### Dimension: Likelihood
> How likely is this threat to affect us?

Scale: 0–5

| Factor | Weight |
|--------|--------|
| Active exploitation confirmed (KEV or exploit tag) | +3 |
| Weaponization evidence (PoC available, malware samples) | +2 |
| Known threat actor activity (MISP galaxy, actor tags) | +1 |
| Freshness (published within 7 days) | +1 |
| Stale (published > 90 days, no recent activity) | −1 |

#### Dimension: Impact
> If this hits us, how bad is it?

Scale: 0–5

| Factor | Weight |
|--------|--------|
| CVSS ≥ 9.0 | +3 |
| CVSS 7.0–8.9 | +2 |
| CVSS 4.0–6.9 | +1 |
| App marked "critical" in tech stack | +2 |
| App marked "high" in tech stack | +1 |
| App handles sensitive data (PII, financial, health) | +1 |

#### Dimension: Exposure
> How exposed are we to this threat?

Scale: 0–3

| Factor | Weight |
|--------|--------|
| Internet-facing application | +2 |
| Reachable from untrusted networks | +1 |
| Identity/credential exposure (phishing targets, leaked creds) | +1 |
| SaaS platform with shared responsibility | +1 |

#### Dimension: Confidence
> How reliable is this intelligence?

Scale: 0–4

| Factor | Weight |
|--------|--------|
| Source is CISA KEV or national CERT | +3 |
| Source is trusted MISP community | +2 |
| Vendor-confirmed advisory | +2 |
| ≥3 independent sightings from partners | +2 |
| ≥1 independent sighting | +1 |
| Single low-trust feed | 0 |
| Disputed or unverified | −1 |

#### Final Score Mapping

```
risk_score = (likelihood × impact × exposure) / (5 × 5 × 3)

severity:
  ≥ 0.50 → critical
  ≥ 0.25 → high
  ≥ 0.10 → medium
  < 0.10 → low

confidence_label (from Confidence dimension):
  ≥ 3 → HIGH
  ≥ 2 → MEDIUM
  < 2 → LOW
```

**Configurable:** Every weight, threshold, scale, and the dimension max values are defined in `risk.yaml`, not hardcoded. Calibration is a configuration change, not a code change.

**Calibration via feedback loop:** When an analyst marks an alert as `false_pos`, the system records the event's full risk state (all dimension scores, source, matcher, match_confidence). After sufficient data, operators can analyze patterns ("CVEMatcher with product_only_match over-alerts on medium severity") and adjust weights in `risk.yaml`.

### 7. Explainability Engine

Every alert carries a human-readable explanation built from the risk engine's internal state. The formula used in the explanation must match the actual scoring formula exactly.

```
CRITICAL (confidence: HIGH)

CVE-2024-38472 — Apache HTTP Server 2.4.57

Likelihood: 5.0/5.0
  • Active exploitation (+3) — confirmed by KEV + exploit:in-the-wild tag
  • Weaponization evidence (+2) — PoC available in the wild

Impact: 5.0/5.0
  • CVSS 9.8 (+3) — critical severity
  • App is critical infrastructure (+2) — marked "critical" in tech stack

Exposure: 3.0/3.0
  • Internet-facing (+2) — exposed on lb-01, lb-02
  • Sensitive data (+1) — app handles PII

Confidence: 3.0/4.0 (HIGH)
  • Source: CISA KEV (+3) — authoritative
  • Also reported by MISP — CIRCL, NCSC-NL

Score: (5.0 × 5.0 × 3.0) / (5 × 5 × 3) = 75/75 = 1.00 → CRITICAL
```

The explanation is generated automatically from the same struct that produced the score. No separate code path. If the score changes, the explanation updates automatically.

### 8. Dedup + Suppression

- Hash: `SHA256(CVE + app + source + tag_set)`
- 7-day TTL cache in SQLite
- Same threat from 2 sources → 1 alert (dedup merges sources into the explanation)
- Suppression reasons:
  - Event deleted at source
  - App removed from tech stack
  - Version not affected (CVE version range vs. installed version confirmed safe)
  - TLP:RED
  - Disputed CVE

### 9. Notification Router

Fan-out by **severity + confidence**, based on `routing.yaml`:

```yaml
rules:
  # Critical + high confidence → immediate escalation
  - severity: critical
    confidence: [high]
    channels: [slack, email]
    slack_channel: "#sec-alerts"
    email_to: "soc@company.com"
    format: realtime

  # Critical + medium confidence → still immediate, flag for review
  - severity: critical
    confidence: [medium]
    channels: [slack, email]
    slack_channel: "#sec-alerts"
    email_to: "soc@company.com"
    format: realtime

  # Critical + low confidence → flag for human review, don't auto-escalate
  - severity: critical
    confidence: [low]
    channels: [slack]
    slack_channel: "#sec-review"
    format: realtime

  # High confidence alerts → ops channels
  - severity: high
    confidence: [high, medium]
    channels: [slack]
    slack_channel: "#it-ops"
    format: realtime

  # High severity, low confidence → digest, not realtime
  - severity: high
    confidence: [low]
    channels: [email]
    email_to: "soc-lead@company.com"
    format: daily_digest

  # Medium → weekly digest to CISO
  - severity: medium
    channels: [email]
    email_to: "ciso@company.com"
    format: weekly_digest

  # Low → log only
  - severity: low
    channels: []
```

Rules are evaluated top-to-bottom. First match on `(severity AND confidence IN [...])` wins.

Channels:
- **Slack** — incoming webhook, formatted message with severity color + explanation
- **Microsoft Teams** — incoming webhook, Adaptive Card format
- **Email** — SMTP with TLS, net/smtp from Go stdlib
- **Generic Webhook** — HTTP POST with JSON payload

Retry: 3 attempts with exponential backoff (1s, 4s, 16s). Dead letter on final failure.

### 10. Dead Letter

Undeliverable alerts after retry exhaustion are written to the dead letter log and trigger a health alert. Stored in SQLite for operator review.

### 11. SQLite Database

Pure Go driver (modernc.org/sqlite). Tables from migration 001:

| Table | Purpose | Multi-source ready? |
|-------|---------|---------------------|
| **sources** | Registered threat sources with type, name, confidence, config | Yes — foundation for multi-source |
| **events** | Normalized ThreatEvent JSON + source_id + source_event_id | Yes — source-agnostic |
| **alerts** | Generated alerts with severity, confidence, explanation, state | Yes |
| **tech_stack** | Application inventory with criticality, exposure, team, version | Yes — org_id column |
| **routing_rules** | Severity+confidence → channel mapping | Yes |
| **risk_config** | Risk dimension weights, thresholds, max scales | Yes |
| **matchers_config** | Enabled matchers and their config | Yes |
| **dedup_hashes** | TTL cache for dedup | Yes |
| **sighting_cache** | Recent sighting counts per CVE | Yes |
| **notification_targets** | Slack/Teams/Email/webhook connection config | Yes |

**Alert State Machine:**
```
new → acked → false_pos → resolved
```
False positives feed back into risk tuning: the system records the full risk state at alert time, enabling calibration analysis after sufficient data accumulates.

**Deployment model (v1):** One binary per organisation. OrgContext is a singleton.
`org_id` columns exist in all tables for future multi-tenancy, hardcoded to a default
in v1. No per-tenant auth, no tenant isolation, no org-switching in the API. If you
need to serve multiple orgs, run multiple binaries.

### 12. Configuration Files

All user-configurable. No database UI required for setup.

| File | Purpose | Format |
|------|---------|--------|
| `sources.yaml` | Threat source connections (MISP URL, KEV enabled, etc.) | YAML |
| `techstack.csv` | Application inventory from CMDB | CSV |
| `routing.yaml` | Alert routing rules (severity + confidence → channel) | YAML |
| `risk.yaml` | Risk dimension weights, thresholds, max scales | YAML |
| `matchers.yaml` | Enabled matchers and their config | YAML |

### 13. Organisation Profile

Static configuration used across all matchers and the risk engine:

```yaml
org:
  name: "Acme Corp"
  sector: "energy"           # eu-nis-oes-energy
  country: "BE"
  timezone: "Europe/Brussels"
  data_sensitivity: "high"   # influences Impact dimension
```

One org profile per binary in v1. Multi-tenancy (multiple org profiles per binary) is a v2 feature — the schema supports it, the deployment model doesn't.

### 14. Tech Stack Import (CMDB)

Supported CMDB tools for CSV export: ServiceNow, Ivanti, BMC Helix, Snipe-IT, GLPI, NetBox, Device42, Jira Assets.

Canonical CSV format:
```csv
name,version,vendor,category,criticality,owner_team,internet_facing,hosts,data_sensitivity
"Apache HTTP Server","2.4.57","Apache","Web Server","critical","web-ops","true","lb-01,lb-02","low"
"PostgreSQL","15.3","PostgreSQL","Database","high","data-eng","false","db-primary","high"
"SAP NetWeaver","7.5 SPS22","SAP","ERP","critical","sap-team","false","sap-app-01","high"
```

On import: delta detection — new apps trigger re-scan of recent events, removed apps suppress future alerts, modified apps (criticality change) re-score open alerts.

### 15. REST API (GET, port 8080)

- `GET /api/alerts` — list alerts with filters (severity, confidence, status, team, source, date range)
- `GET /api/alerts/:id` — single alert with full explanation
- `GET /api/techstack` — current tech stack
- `GET /api/sources` — configured sources and their status
- `GET /health` — MISP reachable? KEV updated? Queue depth? Last pull? Dead letter count?
- `GET /metrics` — Prometheus-format metrics

### 16. Admin API (POST/PUT, port 8080, auth required)

- `POST /admin/import` — upload techstack.csv, triggers delta detection
- `PUT /admin/routing` — update routing.yaml
- `PUT /admin/risk` — update risk.yaml
- `PUT /admin/sources` — update sources.yaml
- `PUT /admin/matchers` — enable/disable matchers
- `POST /admin/ack/:alert_id` — acknowledge alert
- `POST /admin/resolve/:alert_id` — resolve (patched or false_pos)
- `POST /admin/pull` — trigger immediate pull from all sources

Auth: `X-Threatlib-Key` header. Server binds localhost by default.

### 17. Health & Observability

- `GET /health` — JSON status of all sources, queue depth, pending alerts, dead letter count
- `GET /metrics` — Prometheus metrics: events pulled (by source), matches (by matcher), alerts generated (by severity+confidence), alerts delivered (by channel), alerts failed, queue depth, pull duration
- stdout logging with timestamp, level, component, source

### 18. Graceful Shutdown

SIGTERM/SIGINT:
1. Stop all source pollers
2. Drain event queue (process remaining items)
3. Close HTTP server (finish in-flight requests)
4. Close SQLite
5. Exit

Timeout: 30 seconds. If not drained, log remaining count.

---

## Data Flow — Step by Step

### 1. Startup
Load config files → Connect to sources → Fetch MISP warninglists + CISA KEV catalog → Open SQLite → Apply migrations → Start goroutines (poller per source, HTTP server, health checker)

### 2. Periodic Pull (configurable per source)
- MISP Poller (every 15 min): pulls NEW + MODIFIED + DELETED events since cursor
- KEV Poller (every 24 hours): pulls KEV JSON, updates cache
- Each source normalizer maps raw events → `ThreatEvent`
- Warning List Filter drops false positives, TLP:RED, disputed CVEs
- Cleaned events enter Event Queue

### 3. Matching (triggered by queue)
- Engine dequeues `ThreatEvent`
- Runs all enabled matchers (CVE, Sector, KEV)
- CVEMatcher applies version scheme detection and vendor alias normalization
- Produces combined match results with match_confidence per match

### 4. Risk Scoring
- Risk engine computes likelihood, impact, exposure (raw points)
- Computes risk_score = (likelihood_raw × impact_raw × exposure_raw) / (max × max × max)
- Computes confidence dimension score
- Maps to severity label and confidence label
- Generates explanation from dimension scores

### 5. Routing
- Notification router matches on (severity + confidence level) against routing rules
- Retry 3× with backoff
- Dead letter on final failure

### 6. Event Lifecycle
- MODIFIED events: re-run full pipeline. New tags may change scoring.
- DELETED events: suppress existing alerts, annotate with deletion reason.
- Alert states: new → acked → false_pos → resolved

### 7. Cold Start (first run against MISP)
- Pull last 7 days of events — ALL events, no CVSS floor at ingest
- Run through full pipeline: normalize → filter → match → score
- Suppress alerts with final severity below "high" (post-scoring suppression)
- This ensures sector intel, actor reports, and non-CVE events reach the matchers, populate the database, and build the historical baseline
- After cold start: switch to incremental mode (cursor-based)

---

## Technology Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Language | Go 1.25+ | Single binary, stdlib, goroutines |
| HTTP | net/http | Standard library |
| Database | SQLite (modernc.org/sqlite) | Pure Go, zero-config |
| JSON | encoding/json | Standard library |
| SMTP | net/smtp | Standard library |
| TLS | crypto/tls | Built into net/http |
| HMAC | crypto/hmac + crypto/sha256 | MISP API auth |
| Signals | os/signal | Graceful shutdown |

**Dependencies: 1** (modernc.org/sqlite — pure Go SQLite driver)

Everything else is Go standard library.

---

## Deployment

```bash
# Build
go build -o threatlib ./cmd/threatlib/

# Run
export MISP_API_KEY="xxx"
export THREATLIB_ADMIN_KEY="yyy"
export SMTP_PASSWORD="zzz"
export SLACK_WEBHOOK_URL="https://hooks.slack.com/..."

./threatlib --config ./config/
```

Requirements:
- Linux, macOS, or Windows (cross-compiled)
- Single static binary (~15-20 MB)
- No runtime dependencies (no Python, Node, Docker)
- Outbound HTTPS to MISP, CISA KEV, Slack, Teams
- Outbound SMTP to mail server
- Local port 8080 (configurable)
- ~50 MB disk, ~30 MB RAM
- **One binary per organisation in v1**

### Why Single Binary Matters

Most threat intelligence platforms require substantial infrastructure:

| Tool | Infrastructure required |
|------|------------------------|
| MISP | PHP, MySQL/MariaDB, Redis, Apache/Nginx, Python (misp-modules), optional ZMQ/Kafka |
| OpenCTI | Node.js, PostgreSQL, Redis, ElasticSearch, MinIO, RabbitMQ, Python workers |
| ThreatConnect | SaaS platform, or heavy on-prem Java/Elasticsearch stack |
| Yeti | Python, MongoDB, Redis, Node.js frontend |
| **threatlib** | **One Go binary. Nothing else.** |

This means:
- **Deploy in under 60 seconds.** Download binary, set 4 environment variables, run.
- **No database to install.** SQLite is a single file embedded in the binary (pure Go driver, no C compiler). Back up by copying the file.
- **No message queue to manage.** Go channels provide in-process buffering between pollers and the matching engine.
- **No runtime to pin.** Statically compiled binary. No Python version, no Node LTS, no JVM.
- **Patching means replacing one file.** No migration scripts, no dependency updates, no config drift.
- **Runs on anything.** Cross-compile for Linux (amd64/arm64), macOS, Windows from a single `go build` command. Same binary runs on a Raspberry Pi or an EC2 instance.

This is a genuine differentiator against the threat intel platform category, which
universally requires multi-service infrastructure. For SOC teams managing 20+ tools,
another one that requires a dedicated database server is a non-starter. A single
binary that runs in their existing environment is an easy yes.

---

## Design Decisions

| Decision | Why |
|----------|-----|
| Canonical ThreatEvent from day 1 | Adding a source later = 1 normalizer. Without this = rewrite engine. |
| Sources table in migration 001 | Multi-source is the foundation, not a v2 feature. |
| Matcher interface (pluggable) | Adding a matcher later = 1 file. Without this = modify engine. |
| Raw-points / max-points formula (not pure multiplicative) | Preserves zero-sensitivity without the collapse problem. Internally consistent with explainability output. |
| Confidence as first-class output, wired into routing | Routes "high severity, low confidence" differently from "high severity, high confidence." |
| Explainability on every alert | Analyst trust requires transparency. Formula in explanation matches actual score computation. |
| Version matching as subsystem with scheme detection | "7.5 SPS22" ≠ semver. Conservative matching for unrecognized schemes. |
| Cold start: severity floor after scoring, not CVSS floor before processing | Non-CVE intel (actor reports, sector tags) must reach matchers. |
| SQLite (not PostgreSQL) | Zero-config deployment. Upgrade path documented. |
| Configuration files (not UI-first) | Version-controllable, diffable, reviewable. Admin API for programmatic updates. |
| Single binary, one per org (v1) | Deploy in minutes. Multi-tenancy is a v2 feature; schema supports it already. |
| Initial thresholds are uncalibrated guesses | Config-file tunable. Calibration requires production data. |

---

## Scope Boundaries

**threatlib does:**
- Pull threat intelligence from multiple sources
- Normalize into a canonical model
- Filter false positives
- Match against organisation tech stack and sector via pluggable matchers
- Score risk using weighted dimensions
- Explain every decision
- Route by severity AND confidence
- Track alert lifecycle with false positive feedback
- Expose health and metrics
- Shut down gracefully

**threatlib does NOT:**
- Ingest threat feeds (sources do that)
- Correlate IOCs (MISP does that)
- Scan for vulnerabilities (Nessus/Qualys do that)
- Manage assets (CMDB does that)
- Replace MISP — it consumes MISP's output
- Serve multiple organisations from one binary (v1 limitation)

---

## Known Limitations & Risks

| Limitation | Mitigation |
|------------|-----------|
| Scoring thresholds uncalibrated (initial guesses) | All configurable in risk.yaml. Calibration via feedback loop after deployment. |
| Version matching fails for unrecognized schemes | Falls back to product-only match with conservative assumption. Match confidence field flags this. |
| Transitive/bundled vulnerabilities not detected | Documented. SBOM integration planned for v2. |
| Multiplicative scoring punishes moderate-on-all-axes threats | Raw-points/max-points formula with calibrated max values mitigates this. |
| v1 audience limited to MISP users | KEV provides immediate second source. v2 roadmap: GitHub Advisory + generic connectors for non-MISP orgs. |
| One binary per org (no multi-tenancy) | Schema supports it. Deployment model is a v1 simplification. |

---

## File Structure

```
threatlib/
├── cmd/threatlib/main.go
├── internal/
│   ├── source/                    # Threat source connectors
│   │   ├── source.go              # Source interface + registry
│   │   ├── misp.go                # MISP REST client + normalizer
│   │   └── kev.go                 # CISA KEV fetcher + normalizer
│   ├── model/                     # Canonical data model
│   │   └── threat_event.go        # ThreatEvent + OrgContext + Match
│   ├── filter/                    # Warning list filter
│   │   └── filter.go              # Applies to all sources
│   ├── match/                     # Matching engine (pluggable)
│   │   ├── engine.go              # Orchestrator, runs all matchers
│   │   ├── cve_matcher.go         # CVE ↔ tech stack
│   │   ├── sector_matcher.go      # Sector/tag ↔ org profile
│   │   ├── kev_matcher.go         # CVE in KEV list
│   │   └── version/               # Version comparison subsystem
│   │       ├── detect.go          # Scheme detection
│   │       ├── semver.go          # Semver parser + comparator
│   │       ├── date.go            # Date-based version parser
│   │       ├── sap.go             # SAP SPS version parser
│   │       ├── windows.go         # Windows build number parser
│   │       └── aliases.go         # Vendor/product alias map
│   ├── risk/                      # Risk prioritization
│   │   ├── engine.go              # 4-dimension scoring + formula
│   │   ├── likelihood.go          # Likelihood computation
│   │   ├── impact.go              # Impact computation
│   │   ├── exposure.go            # Exposure computation
│   │   ├── confidence.go          # Confidence computation
│   │   ├── explain.go             # Explainability engine
│   │   └── dedup.go               # Dedup + suppression
│   ├── notify/                    # Notification router
│   │   ├── router.go              # Fan-out by severity+confidence
│   │   ├── slack.go               # Slack webhook
│   │   ├── teams.go               # Teams webhook
│   │   ├── email.go               # SMTP sender
│   │   └── webhook.go             # Generic webhook
│   ├── api/                       # HTTP handlers
│   │   ├── server.go              # Server setup
│   │   ├── rest.go                # GET endpoints
│   │   ├── admin.go               # POST/PUT endpoints (auth)
│   │   └── middleware.go           # Auth, logging, CORS
│   ├── store/                     # SQLite database layer
│   │   ├── db.go                  # Connection, migrations
│   │   ├── sources.go             # Sources CRUD
│   │   ├── events.go              # Event CRUD
│   │   ├── alerts.go              # Alert CRUD + state machine
│   │   ├── techstack.go           # Tech stack + delta detection
│   │   └── config.go              # Risk/routing/matchers config
│   ├── config/                    # Configuration loading
│   │   └── config.go              # Parse YAML + CSV, validate
│   └── health/                    # Health + metrics
│       └── health.go              # /health and /metrics
├── config/                        # Example config files
│   ├── sources.yaml
│   ├── techstack.csv
│   ├── routing.yaml
│   ├── risk.yaml
│   └── matchers.yaml
├── docs/
│   ├── threatlib-architecture.html
│   └── threatlib-design.md
├── go.mod
├── go.sum
└── README.md
```

---

## Success Metrics (post-deployment)

| Metric | What we measure |
|--------|----------------|
| Mean time to awareness | Time from threat publication to alert in SOC channel |
| Alert volume reduction | Threats processed vs. alerts sent (filter ratio) |
| Analyst time saved | Alerts acknowledged vs. alerts requiring investigation |
| False positive rate | Alerts marked false_pos / total alerts |
| Source coverage | Threats matched by MISP only, KEV only, both |
| Confidence gap | Alerts with LOW confidence that were actually real |
| Calibration drift | Distribution of scores over time (are thresholds still correct?) |

---

## Summary

threatlib is a **threat prioritization engine** that:

1. Connects to multiple threat sources (MISP + CISA KEV in v1)
2. Normalizes everything into a canonical event model
3. Filters false positives via warning lists
4. Matches against the organisation's tech stack and sector profile via pluggable matchers
5. Scores risk using weighted dimensions with a consistent formula
6. Explains every decision with evidence and score breakdown
7. Routes by severity AND confidence
8. Tracks alert lifecycle with false positive feedback for calibration
9. Exposes health and metrics
10. Shuts down gracefully

Deploy as a single binary. Configure with YAML and CSV. One binary per organisation in v1.
