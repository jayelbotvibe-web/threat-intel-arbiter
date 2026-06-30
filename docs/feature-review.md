# Feature Adoption Review — threat-intel-arbiter

Analysis of 6 similar open-source projects for features worth adopting.
Prepared: 2026-07-01

---

## Projects analyzed

| # | Project | Stars | Stack | Relevance |
|---|---------|-------|-------|-----------|
| 1 | **ExploitRank** (rinz0x0cruz/exploitrank) | 0 | Go + SQLite, single binary | Closest match — same architecture, CVE-focused |
| 2 | **OpenCTI** (OpenCTI-Platform/opencti) | 9.6K | Node/PG/Redis/ES/RabbitMQ | Threat intel platform — connector ecosystem, STIX2 |
| 3 | **IntelOwl** (intelowlproject/IntelOwl) | 4.6K | Python/Django/PG/Redis | Observable analyzer — plugin model, playbooks |
| 4 | **TheHive** (TheHive-Project/TheHive) | 3.9K | Scala/ES | Incident response — alert lifecycle, case mgmt |
| 5 | **SSVC** (CERTCC/SSVC) | 184 | Python | Methodology — decision-tree prioritization |
| 6 | **daily-patch** (castroaj/daily-patch) | 1 | Go+Python/PG | Personal vuln digest — AI scoring, multi-service |

---

## Feature 1: SSVC-style Action Labels
**Source:** ExploitRank + CERT/CC SSVC
**Effort:** Low
**Impact:** High

Current arbiter output: CRITICAL / HIGH / MEDIUM / LOW severity labels.
Proposed: Add action verbs that tell the analyst *what to do*.

```
Action mapping:
  critical + HIGH confidence     → Act Now
  critical + LOW confidence      → Schedule (review needed)
  high     + HIGH/MED confidence → Schedule
  high     + LOW confidence      → Track
  medium                         → Track
  low                            → Monitor
```

Why: Every tool says "CRITICAL." Nobody says "Act Now." The explainability engine
already has the evidence — it just needs to map to behavioral directives. The
SSVC methodology (CERT/CC) is the industry standard here. ExploitRank simplifies
it to a 4-level decision.

Implementation: Post-scoring overlay. After severity + confidence are computed,
map to action label. Add `action` field to alert model. Show in notifications.

---

## Feature 2: Offline Threat Tagging (ATT&CK + Threat Actors)
**Source:** ExploitRank (internal/threat/threat.go)
**Effort:** Low
**Impact:** Medium

What: Pure Go function that scans text for MITRE ATT&CK technique keywords and
threat actor aliases. No API, no network, trivially testable. 40+ technique
keywords, 80+ actor aliases. Runs offline.

```
Input:  "APT28 exploited CVE-2024-12345 via SQL injection in public-facing app"
Output: techniques=["T1190"], actors=["APT28 (Fancy Bear)"]
```

Why arbiter needs it: MISP events carry tags and galaxies (rich metadata).
CISA KEV entries do not. KEV entries are bare JSON with vendor/product/description.
Tagging them with ATT&CK + actors gives the explainability engine more evidence
and makes SectorMatcher work better for KEV-only events.

Where it plugs in: Normalization layer. After a KEV entry becomes a ThreatEvent,
run Tag() on its Description field. Store in ThreatEvent.Tags. The matching
engine and explainability engine both consume tags.

---

## Feature 3: Graceful Source Degradation
**Source:** ExploitRank (internal/feeds/feeds.go)
**Effort:** Low
**Impact:** High

Current arbiter design: Sequential source polling. If MISP is down → entire run
fails. No KEV data flows.

Proposed: Parallel goroutine-per-source with individual error isolation.

```
sources := []Source{mispSource, kevSource}
results := make(chan FetchResult, len(sources))
for _, src := range sources {
    go func(s Source) {
        events, err := s.Fetch(ctx)
        results <- FetchResult{Source: s.Name(), Events: events, Err: err}
    }(src)
}
// One failure logs warning, doesn't block others
// Cursors only advance on success (retry next cycle)
// Health endpoint shows per-source status
```

Why: Production resilience. MISP auth expiry or network blip shouldn't take down
the whole pipeline. KEV can continue flowing independently.

---

## Feature 4: Watchlists / Keyword Boosting
**Source:** ExploitRank (config.json → watchlist section)
**Effort:** Low
**Impact:** Medium

What: User-configurable list of vendors, products, keywords. Any event matching
a watchlist entry gets a configurable score boost.

```yaml
# config.yaml addition
watchlist:
  vendors: ["Cisco", "Palo Alto"]
  products: ["ASA", "PAN-OS", "FortiOS"]
  keywords: ["VPN", "firewall", "edge device"]
  boost: 10  # points added to final score
```

Why: CVEMatcher requires formal tech stack entries (name, version, vendor,
criticality). A watchlist is lighter — just keywords. Solves "we care more about
Cisco than JetBrains" without full CMDB entries. The explainability engine notes:
"Watchlist match: Cisco ASA (+10 points)."

Implementation: During scoring, after 4-dimension computation, check event
description + products against watchlist. Apply boost. Display in explanation.

---

## Feature 5: On-Demand Single-CVE Lookup
**Source:** ExploitRank (exploitrank lookup CVE-XXXX-XXXXX)
**Effort:** Low
**Impact:** Medium

What: CLI command that runs the full pipeline for ONE CVE on demand.

```
arbiter lookup CVE-2024-38472
→ fetches from sources (MISP + KEV)
→ normalizes to ThreatEvent
→ matches against org tech stack
→ scores on 4 dimensions
→ explains with full breakdown
→ outputs verdict immediately
```

Why: When a new CVE drops and Slack lights up, analyst wants to know "does this
affect us?" NOW — not in 15 minutes when the next poll cycle runs. Same pipeline
code, single-CVE scope. No persistence needed (or optionally cache in SQLite).

---

## Feature 6: Offline HTML Dashboard
**Source:** ExploitRank (internal/render/render.go — 20KB)
**Effort:** Medium
**Impact:** Medium

What: Generate a self-contained HTML file from SQLite. Inline CSS, inline JS,
zero external dependencies. Open in any browser. ExploitRank's shows: ranked
CVE cards with score/tier/action/rationale, threat-actor feed, attack technique
feed, clickable detail views.

Why: Arbiter has REST API + notification routing but no visual output. A
self-contained dashboard gives SOC analysts a zero-setup UI. More useful than
a REST API for a "deploy in 60 seconds" tool — no frontend, no npm, no build
step. Just an HTML file that gets regenerated after each pipeline run.

```
arbiter dashboard --open   # generate + open in browser
arbiter serve --open        # host REST API + serve dashboard
```

Arbiter's dashboard would show: alerts by severity+confidence, score breakdown
per alert, alert lifecycle state, source coverage (MISP vs KEV), threat actor
activity, and "what's new since yesterday."

---

## Feature 7: Daily Brief / What-Changed Diff
**Source:** ExploitRank (cmd/exploitrank/brief.go)
**Effort:** Medium
**Impact:** Medium

What: Deterministic report of "what changed in the last 24 hours" generated from
SQLite. New KEV entries, new Act-Now items, threat actor activity, attack
technique trends. Overwritten daily (single file). Optional PDF export.
Optional AI upgrade for natural-language prose.

```
arbiter brief                    # markdown to stdout
arbiter brief --pdf --email      # PDF + email
arbiter diff                     # what's new since last run
```

Arbiter's brief would include: top 5 Act-Now alerts with score breakdown, new
MISP events matched to org stack, KEV entries touching your sector, confidence
gaps (high severity + low confidence → needs review), false positives marked
this week (calibration signal), source coverage stats (MISP-only vs KEV-only vs
both).

Why: Answers the CISO's Monday morning question: "What threats should I care
about this week?" Arbiter has richer data than ExploitRank for this because it
knows what's relevant to YOUR org, not just what's hot globally.

---

## Feature 8: AI-Assisted Explainability
**Source:** ExploitRank (internal/ai/ai.go) + daily-patch (Claude scoring)
**Effort:** Low
**Impact:** Low (nice-to-have)

What: Optional LLM layer that turns structured score data into natural-language
prose for notifications. Opt-in, key-gated, fails gracefully (AI outage never
breaks the tool).

```
# Without AI (already implemented):
"CRITICAL (confidence: HIGH)
 Likelihood 5.0: active exploitation + KEV
 Impact 5.0: CVSS 9.8 + app is critical infrastructure
 ..."

# With AI upgrade (optional):
"CVE-2024-38472 in Apache HTTP Server requires immediate attention.
 It's actively exploited, confirmed by CISA KEV, and your internet-facing
 lb-01 and lb-02 instances are vulnerable. Severity is critical with
 high confidence. Patch immediately."
```

Implementation: One file (~80 lines), OpenAI-compatible /chat/completions
endpoint. Call from notification router when formatting Slack/Teams messages.
Cache responses in SQLite (avoid re-generation). Same structured data as source
of truth — AI is presentation only.

Why: Structured explanations are great for analysts. Natural-language prose is
better for Slack/Teams notifications where non-security people (IT ops, managers)
also read them.

---

## Feature 9: Multi-Action Routing Rules
**Source:** IntelOwl (playbook pattern) + TheHive (alert feeders)
**Effort:** Low (schema change only)
**Impact:** Low (v2 prep)

Current arbiter routing: severity + confidence → notification channel.
Proposed: severity + confidence → list of actions.

```yaml
routing:
  rules:
    - severity: critical
      confidence: [high]
      actions:
        - notify: [slack, email]
        - create_case: thehive       # v2
        - tag_misp: "reviewed"       # v2 (feedback loop)
        - webhook: "https://..."     # custom integrations
```

Why: The notification router is the right place to hang additional actions.
Changing the schema now (list of actions instead of single "channels") is a
backward-compatible schema change that enables future integrations without
rewiring the router. Not v1 but plan for it.

---

## Feature 10: Per-Source Confidence Attribution
**Source:** OpenCTI + IntelOwl
**Effort:** Trivial
**Impact:** Low

Current arbiter: confidence dimension mixes source confidence with sighting
counts into a single score. The data is tracked but the per-source breakdown
isn't visible in explanations.

Proposed: Show it.

```
Confidence: 3.0/4.0 (HIGH)
  • CISA KEV (source: authoritative)           +3
  • MISP — CIRCL (community trust: high)        +2
  • MISP — NCSC-NL (community trust: medium)    +1
  • 2 independent sightings                     +1
```

Why: Already tracking this data. Just surface it in the explanation. Builds
analyst trust — they can see exactly which sources contributed to the confidence
score and judge for themselves.

---

## Priority Ranking

| Rank | Feature | Source | Effort | Impact | Category |
|------|---------|--------|--------|--------|----------|
| 1 | SSVC action labels | ExploitRank + CERT/CC | Low | **High** | Output UX |
| 2 | Threat tagging (ATT&CK + actors) | ExploitRank | Low | Medium | Enrichment |
| 3 | Graceful source degradation | ExploitRank | Low | **High** | Resilience |
| 4 | Watchlists / boosting | ExploitRank | Low | Medium | Config |
| 5 | On-demand CVE lookup | ExploitRank | Low | Medium | Workflow |
| 6 | Offline HTML dashboard | ExploitRank | Medium | Medium | UX |
| 7 | Daily brief / diff | ExploitRank | Medium | Medium | Workflow |
| 8 | AI-assisted explainability | ExploitRank + daily-patch | Low | Low | Polish |
| 9 | Multi-action routing rules | IntelOwl + TheHive | Low | Low | v2 prep |
| 10 | Per-source confidence in explanation | OpenCTI + IntelOwl | Trivial | Low | Transparency |

---

## Competitive positioning after these changes

| Dimension | ExploitRank | threat-intel-arbiter (with features) |
|-----------|-------------|--------------------------------------|
| Sources | NVD, KEV, GHSA, OSV, EPSS, PoC, RSS | **MISP** + KEV (v2: NVD, GHSA) |
| Scoring | Weighted sum (CVSS+EPSS+KEV+PoC) | **4-dim weighted** (Likelihood×Impact×Exposure) + Confidence |
| Org context | Watchlists only | **Full tech stack matching** + sector + exposure |
| Explainability | One-line rationale | **Full score breakdown** per dimension |
| Action labels | SSVC (Act Now / Schedule / Track / Monitor) | **SSVC** (adopt) |
| Threat metadata | ATT&CK + actors (offline) | **ATT&CK + actors** (adopt) + MISP tags/galaxies |
| Notifications | Slack/Discord (opt-in) | **Slack/Teams/Email** with confidence-aware routing |
| Alert lifecycle | None | **new→acked→false_pos→resolved** with feedback loop |
| Dashboard | Offline HTML | **Offline HTML** (adopt) |
| Resilience | Per-source isolation | **Per-source isolation** (adopt) |
| Deployment | Single Go binary | Single Go binary |
| AI | Optional, key-gated | **Optional, key-gated** (adopt) |

--- 

## Key insight

ExploitRank and threat-intel-arbiter solve different problems with the same
architecture:

- **ExploitRank:** "Which CVEs are hottest RIGHT NOW?" — global ranking
- **threat-intel-arbiter:** "Should MY org care about THIS threat?" — contextual judgment

Adopting ExploitRank's UX features (dashboard, brief, action labels, threat
tagging, graceful degradation) makes arbiter feel like a polished product
without changing what it fundamentally does. The architecture already supports
all of these — they slot into existing components without refactoring.
