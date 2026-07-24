# CLAUDE.md — threat-intel-arbiter

A threat-prioritization engine. It ingests threat intel from a MISP instance and the CISA
KEV catalog, matches it against one organisation's tech stack / sector / exposure, and
emits scored, explained, routed alerts. The single question it answers: *"should this
organisation care about this threat right now?"*

Deliberately **not** a TIP, scanner, SIEM, or CMDB. Prioritization is CVE-driven — IOCs are
extracted only for EDR push, never for matching or scoring.

## Commands

There is **no Makefile**. Raw `go`:

```bash
go build -o arbiter ./cmd/arbiter/     # build
go test ./... -v                        # test
./arbiter --config ./config/            # run
```

Flags (`cmd/arbiter/main.go`): `--config` (default `./config`), `--db`
(default `./data/arbiter.db`), `--port` (default `:8080`), `--key` (falls back to
`$ARBITER_ADMIN_KEY`).

**There is no linter.** No golangci-lint config, no `go vet` step in CI, no pre-commit.
Don't invent one or claim `make lint` works.

CI (`.github/workflows/test.yml`) runs `go test ./... -v` then the build, on push/PR to
`main`.

## Stack

Go **1.25.0** (`go.mod`). Two direct dependencies: `golang.org/x/crypto v0.53.0` and
`modernc.org/sqlite v1.53.0` — pure-Go SQLite, **no cgo**. No web framework: `net/http`
plus a single page embedded via `//go:embed dashboard.html`.

## Architecture

Entry point and only `package main`: `cmd/arbiter/main.go`. It wires
config → store → pollers → match → risk → notify → API, connected by a buffered channel
`eventQueue := make(chan model.ThreatEvent, 5000)`.

- `internal/model/threat_event.go` — the canonical source-agnostic event. **Adding a new
  intel source means writing one normalizer to this type**, nothing else.
- `internal/source/` — `misp.go`, `kev.go`, `poller.go` (cursor persistence)
- `internal/filter/filter.go` — drops TLP:RED, disputed and warning-list CVEs pre-match
- `internal/match/` — `cve_matcher.go`, `sector_matcher.go`, `kev_matcher.go` behind
  `engine.go`; `internal/match/version/` is the version-comparison subsystem
- `internal/risk/` — `engine.go` (4-dimension score), `ssvc.go` (SSVC v2.1), `alert.go`
- `internal/notify/` — `router.go`, `slack.go` (also Teams), `email.go`, `crowdstrike.go`
- `internal/store/` — SQLite: `db.go`, `alerts.go`, `users.go`, `techstack.go`, `settings.go`
- `internal/api/` — `server.go`, `auth.go` (Argon2id + sessions), `ratelimit.go`

No code generation beyond the single `go:embed`.

**Score and explanation share one struct** — the explanation is generated from the same
data that computed the score, deliberately (commit `e3d4e35`). Don't split them.

## Conventions

- Errors wrapped as `fmt.Errorf("<lowercase context>: %w", err)`
- Logging is stdlib `log` only, configured once in `main.go` with
  `log.SetFlags(log.LstdFlags | log.Lshortfile)`. `log.Fatalf` for startup, `log.Printf`
  otherwise. No structured logger.
- Tests are `_test.go` beside the code, same package, named `TestSubject_Scenario`
  (e.g. `TestMISPPoller_CursorPersistsAcrossRestart`)
- JSON fixtures live in `testdata/`
- Commits: Conventional Commits with scope and issue tag —
  `fix(match): wire version comparator into CVE matching (#FIX2)`

## Gotchas

- **Config is JSON, not YAML**, in `config/`: `org.json`, `sources.json`, `matchers.json`,
  `risk.json`, `routing.json`. (Note: `notify.Rule` and the config structs still carry
  dead `yaml:` struct tags — harmless, fields are populated manually in `main.go`.)
- **`config/techstack.csv` is gitignored** and must be created:
  `cp config/techstack.csv.example config/techstack.csv`
- **The tracked config carries placeholder org identity**, not neutral defaults —
  "NanoFab Semiconductor Inc.", `soc@nanofab.example.com`, `https://misp.example.com`.
  Must be edited before real use.
- **There is no `.env.example`.** Env vars are documented only in README prose and code:
  `MISP_API_KEY`, `ARBITER_ADMIN_KEY`, `SMTP_{HOST,PORT,FROM,PASSWORD}`,
  `SLACK_WEBHOOK_URL`, `TEAMS_WEBHOOK_URL`, `CROWDSTRIKE_*`, `TRUSTED_PROXY`.
- CrowdStrike falls into **mock mode** when `CROWDSTRIKE_CLIENT_ID` is empty.
- Warning CVEs are hardcoded in `main.go` (`LoadWarningCVEs("CVE-2024-99999", ...)`) — a
  stub, not config-driven. (The KEV *matcher* was a similar hardcoded stub but is now
  fed live from the KEV poller's catalog via `KEVMatcher.Replace` — see the 2026-07 review.)
- First start seeds an `admin` account with a random one-time password printed to stdout.
- Needs a reachable MISP instance; KEV-only mode is roadmap, not implemented.
- `tools/start.sh` is destructive-adjacent: `pkill`s the arbiter, removes VMware `.lck`
  files, and SSHes into the MISP VM to rewrite `/etc/resolv.conf`.

## State

Feature-complete for its v1 scope, not a prototype. Zero TODO/FIXME markers. Recent work
is a security-hardening arc: constant-time key comparison, rate-limit eviction, session
invalidation on user delete/demote/password change, TLS verification restored by default.
`VERIFICATION-v3.md` documents that round.

A 2026-07 code review added: KEVMatcher fed from the live catalog (not a hardcoded list);
`version.InRange` no longer suppresses a match when a CVE range *boundary* is unparseable
(false-negative fix — downgrades to `product_only_match` instead of dropping); rate-limit
key keyed per-host not per-connection (`net.SplitHostPort`); login enumeration-oracle
closed; rightmost-XFF when proxied; HTTP server timeouts + login body cap; constant-time
legacy hash verify; rate-limit key ceiling. **Still open:** version ranges are inclusive-only
(no `versionEndExcluding` support) — a false-positive at the exact patched version.
