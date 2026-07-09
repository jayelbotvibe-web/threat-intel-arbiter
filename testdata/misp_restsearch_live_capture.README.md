# MISP Live Capture Fixture

- **MISP version:** 2.4.220
- **Captured:** 2026-07-09 16:31 UTC
- **Source:** `https://172.16.146.129/events/restSearch` (lab MISP, NAT vmnet8)
- **Captured by:** Purple Loop Build Agent (Round 3.2)

## Capture command

```bash
curl -sk -X POST "https://<MISP_IP>/events/restSearch" \
  -H "Authorization: $MISP_API_KEY" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{"returnFormat":"json","eventid":79,"limit":1,"includeAttachments":0,"includeFeedCorrelations":0,"includeEventCorrelations":0,"includeDecayScore":0,"includeSightingdb":0}' \
  -o testdata/misp_restsearch_live_capture.json
```

## Scrubs applied

API key replaced with REDACTED:
```bash
sed -i "s/$MISP_API_KEY/REDACTED/g" testdata/misp_restsearch_live_capture.json
```

No lab IPs present in the event JSON body (MISP returns relative URLs). No structural changes — key names and JSON structure are untouched.

## CVE coverage

Contains CVE-2024-38472 (Apache HTTP Server) which was added to event 79 via MISP API for tech stack matching:
```bash
curl -sk -X POST "https://<MISP_IP>/attributes/add/79" \
  -H "Authorization: $MISP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"type":"vulnerability","category":"External analysis","value":"CVE-2024-38472","comment":"Apache HTTP Server vulnerability","to_ids":false,"distribution":"5"}'
```

## Integrity

```
sha256sum: d799b7cb4fc60618b11553c4ab80cc1f9b8e07e84dbf43e4d573fcaa3c535ad8
size: 335844 bytes
```
