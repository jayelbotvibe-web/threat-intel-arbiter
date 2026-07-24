# Changelog

All notable changes to Threat Intel Arbiter are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/); this project does not
yet tag versioned releases, so changes are grouped by date on `main`.

## [Unreleased] — 2026-07-24

A two-round code review (correctness + security) across the matching, scoring,
API/auth, notification, ingest, and storage layers. Full test suite green under
`-race`. Commits: `c18a9a9` (round 1), `e30467c` (round 2).

### Fixed — correctness

- **SSVC action is now persisted.** `store.SaveAlert` omitted the `action`
  column, so every alert read back as the default `Track` and the dashboard's
  Act/Attend/Track buckets were permanently empty — the core "should we care
  right now?" signal was dropped at the storage layer. (`e30467c`)
- **KEV matcher is fed from the live CISA catalog** via a thread-safe `Replace`,
  refreshed on every poll. It was a hardcoded 3-CVE stub disconnected from the
  poller, so most real known-exploited CVEs received no KEV scoring boost. (`c18a9a9`)
- **Unparseable CVE range boundaries no longer suppress a match.** `version.InRange`
  returned "not affected" when a range bound (e.g. `unspecified`, `3.x`) couldn't
  be parsed — a false negative. It now downgrades to `product_only_match` instead
  of dropping the alert. (`c18a9a9`)
- **MISP normalizer parses CPE attributes into `AffectedProducts`**, enabling
  version-aware CVE matching. Previously `AffectedProducts` was never populated,
  capping MISP CVEs at `weak_title_match`. (CVE-only events without CPE still
  match by title — a source-data limitation.) (`e30467c`)
- **Notification router treats an empty `confidence` list as match-all.** Rules
  that omitted `confidence` (including the shipped `medium` rule and the console
  default) silently matched nothing and dropped every alert of that severity.
  Severity matching is now case-insensitive; unregistered channels and
  zero-delivery are logged. (`e30467c`)

### Fixed — security

- **Login rate limit keyed per host, not per connection.** The limiter keyed on
  `r.RemoteAddr` (`ip:port`), so every new TCP connection got a fresh bucket and
  the per-IP throttle was inert by default. Now uses `net.SplitHostPort`. (`c18a9a9`)
- **Username-enumeration oracle closed.** The nonexistent-user login branch now
  enforces the per-account limiter (429) identically to the real-user branch,
  instead of always returning 401. (`c18a9a9`)
- **Email header injection closed.** SMTP headers are run through `headerSafe`
  (strips CR/LF), preventing a source-controlled event title from injecting
  headers such as `Bcc`. (`e30467c`)
- **X-Forwarded-For trusts the rightmost entry** when proxied (leftmost is
  client-spoofable). (`c18a9a9`)
- **HTTP server timeouts + 64 KB login body cap** (Slowloris / memory DoS). (`c18a9a9`)
- **Response-size caps** (`io.LimitReader`) on MISP/KEV reads (memory DoS). (`e30467c`)
- **IPv6 loopback/ULA/link-local/mapped addresses now block** in the CrowdStrike
  IOC denylist, which was IPv4-only — no private IPv6 is pushed to the EDR. (`e30467c`)
- **Webhook secret URLs are redacted from error logs** (Slack/Teams incoming
  webhook URLs are credentials). (`e30467c`)
- **Rate-limiter key ceiling** with inline eviction (memory-DoS bound). (`c18a9a9`)
- **Constant-time legacy SHA-256 hash verification.** (`c18a9a9`)

### Changed

- `SuppressAlertsForEvent` returns its error and the poller logs suppression
  failures, instead of silently leaving retracted-intel alerts active. (`e30467c`)
- Removed dead, unused API-key `auth` middleware. (`c18a9a9`)
- Corrected misleading `sources.yaml` / `routing.yaml` comments (config is JSON). (`c18a9a9`)

### Known / deferred

- **Per-rule notification recipients** — `notify.Rule` has no `EmailTo`/`SlackChannel`;
  email always goes to `SMTP_FROM`. Delivery works (all matched alerts reach the
  configured channel), but per-recipient splitting from `routing.json` is not
  honored. Requires a `Notifier.Send` interface change.
- **Exclusive version bounds** — ranges are inclusive-only, a false-positive at
  the exact patched version (`versionEndExcluding`).
- Lower priority: strict CSV load aborts on one bad row; `http://` MISP sends the
  API key in cleartext; `PullInterval` is dead config; dedup TOCTOU;
  Slack/Teams markdown injection.
