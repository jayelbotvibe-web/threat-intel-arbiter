# Exposure Ceiling for Internal-Only Assets

## Current behavior

The risk scoring formula is `(L × I × E) / (5 × 5 × 3)`:
- Likelihood: 0–5
- Impact: 0–5
- Exposure: 1–3 (floored at 1 when any matcher fires)

For an **internal-only** asset (not internet-facing, not SaaS, no credential exposure, no untrusted network exposure): exposure = 1.

```
Max score: (5 × 5 × 1) / 75 = 25/75 ≈ 0.33
```

This means an internal asset can reach **high** severity (≥0.25) but can never reach **critical** (≥0.50). A domain controller or internal CA with an actively-exploited, KEV-listed, CVSS-9.8 RCE would score as "high" — not "critical."

## Is this correct?

**For most assets, yes.** An internal-only threat has no direct internet exposure — the attacker must already be inside the network. The threat is real but the blast radius is smaller than an internet-facing RCE.

**For critical internal infrastructure — maybe not.** A domain controller, internal Certificate Authority, or secrets management server might warrant critical severity even without internet exposure because compromise of these assets provides lateral movement to everything else.

## Recommendation

Make the **exposure floor configurable per-asset** via the `criticality` field in the tech stack:

| Criticality | Exposure floor |
|---|---|
| `low` | 1 (current default) |
| `medium` | 1 |
| `high` | 2 |
| `critical` | 3 (allows reaching critical severity) |

If asset `criticality = critical` AND exposure would be 1, raise the floor to 3. This means a domain controller (critical criticality, internal-only) with an active RCE would score:
```
(5 × 5 × 3) / 75 = 75/75 = 1.0 → critical
```

## Decision needed

This is a **product decision**, not a bug. The current behavior is defensible for most deployments. The configurable per-asset approach requires changes to `internal/risk/engine.go` (exposure calculation), `internal/config/risk.yaml` (mapping), and the tech stack model. Implementation should be opt-in and backward-compatible.
