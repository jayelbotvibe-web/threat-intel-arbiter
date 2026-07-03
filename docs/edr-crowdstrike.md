# EDR Integration — CrowdStrike Falcon

Threat Intel Arbiter closes the loop from detection to prevention by forwarding extracted IOCs (IPs, domains, hashes) to your EDR platform. **CrowdStrike Falcon** is the first supported integration, with the architecture ready for SentinelOne, Microsoft Defender, and others.

## How It Works

```
MISP Event → Normalizer → Extract IOCs → Severity filter → CrowdStrike API
                   │
        ip-src/dst → ipv4
        domain/hostname → domain
        sha256/md5 → hash
```

1. **Pull event** from MISP with IOC attributes (ip-dst, domain, sha256, md5)
2. **Extract IOCs** — map MISP attribute types to CrowdStrike IOC types
3. **Filter by severity** — only send IOCs from events meeting minimum severity (default: medium)
4. **Deduplicate** — track sent IOCs in-memory, never re-send the same value
5. **Batch** — collect IOCs, flush every 30 seconds or at 100-batch size
6. **Send** — POST to CrowdStrike Falcon API with OAuth2 authentication

## Supported IOC Types

| MISP Attribute Type | CrowdStrike IOC Type |
|---|---|
| `ip-src`, `ip-dst`, `ip` | `ipv4` |
| `ipv6` | `ipv6` |
| `domain`, `hostname` | `domain` |
| `sha256` | `hash_sha256` |
| `md5` | `hash_md5` |

## CrowdStrike API Format

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

## Configuration

| Env Variable | Default | Description |
|---|---|---|
| `CROWDSTRIKE_CLIENT_ID` | *(empty — mock mode)* | Falcon API client ID |
| `CROWDSTRIKE_CLIENT_SECRET` | *(empty)* | Falcon API client secret |
| `CROWDSTRIKE_BASE_URL` | `https://api.crowdstrike.com` | Falcon API base URL |
| `CROWDSTRIKE_ACTION` | `detect` | `detect` or `prevent` |
| `CROWDSTRIKE_SEVERITY` | `medium` | Minimum severity: `critical`, `high`, `medium`, `low` |
| `CROWDSTRIKE_EXPIRATION` | `30` | Days until IOC expires in Falcon |

## Mock Mode

When `CROWDSTRIKE_CLIENT_ID` is not set (default), the integration runs in **mock mode** — it logs what would be sent without making any network calls:

```
crowdstrike [MOCK]: would send 6 IOCs from event misp:8842:a1f0 (6 total sent)
```

The dashboard health bar shows `EDR mock` with a yellow dot. When credentials are set, it switches to `EDR online` with a green dot and sends real API calls.

## Authentication

CrowdStrike Falcon uses **OAuth2**:
1. POST `/oauth2/token` with `client_id` + `client_secret`
2. Receive `access_token` (valid ~30 minutes)
3. Use `Authorization: Bearer <token>` for IOC API calls
4. Token auto-refreshes when expired (60-second buffer)

## Deduplication

IOCs are tracked in-memory by `type:value` key (e.g., `ipv4:45.153.241.187`). Once sent, the same IOC is never re-sent — avoiding duplicate entries in Falcon and reducing API calls.

## Batching

IOCs are collected across multiple events and sent in batches:
- **Flush interval:** 30 seconds
- **Batch size:** up to 100 IOCs per POST (Falcon limit: 500)
- **Failure recovery:** failed batches are re-queued for the next flush

## Health Dashboard

The EDR status is visible in the header health bar:
- 🟡 **EDR mock** — mock mode active (no credentials)
- 🟢 **EDR online** — connected with real credentials

Settings → ⚙ → API & Webhooks → EDR — CrowdStrike Falcon section for configuring Client ID, Secret, and Base URL.
