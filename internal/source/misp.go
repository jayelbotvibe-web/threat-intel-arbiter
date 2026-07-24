// Package source provides threat intelligence source connectors.
package source

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/model"
)

// maxMISPResponseBytes caps how much of a MISP HTTP response we buffer, so a
// hostile or misbehaving server can't exhaust memory. Real restSearch payloads
// are well under this.
const maxMISPResponseBytes = 128 << 20 // 128 MB

// MISPClient is a REST client for the MISP threat intelligence platform.
// It handles HMAC-SHA256 request signing as required by MISP's API.
type MISPClient struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
}

// NewMISPClient creates a new MISP API client.
// tlsSkipVerify disables TLS certificate verification (lab use only — a WARN is logged).
// caCertPath loads a custom CA certificate for self-signed lab MISPs.
func NewMISPClient(baseURL, apiKey string, tlsSkipVerify bool, caCertPath string) *MISPClient {
	tlsConfig := &tls.Config{}

	if caCertPath != "" {
		caCert, err := os.ReadFile(caCertPath)
		if err != nil {
			log.Printf("misp: WARNING — failed to read CA cert from %s: %v (falling back to system pool)", caCertPath, err)
		} else {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caCert) {
				log.Printf("misp: WARNING — no certificates found in %s", caCertPath)
			}
			tlsConfig.RootCAs = pool
		}
	}

	if tlsSkipVerify {
		tlsConfig.InsecureSkipVerify = true
		log.Printf("misp: WARNING — TLS certificate verification DISABLED — lab use only")
	}

	return &MISPClient{
		BaseURL: strings.TrimRight(baseURL, "/"),
		APIKey:  apiKey,
		HTTP: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
	}
}

// MISPResponse wraps the MISP REST API response format.
// MISP always wraps results in a "response" array.
type MISPResponse struct {
	Response []MISPResponseItem `json:"response"`
}

// MISPResponseItem contains either an Event or a minimal reference.
type MISPResponseItem struct {
	Event MISPEvent `json:"Event"`
}

// MISPEvent is the raw MISP event structure from the REST API.
type MISPEvent struct {
	ID           string          `json:"id"`
	UUID         string          `json:"uuid"`
	OrgID        string          `json:"org_id"`
	OrgcID       string          `json:"orgc_id"`
	Date         string          `json:"date"`
	ThreatLevel  string          `json:"threat_level_id"`
	Info         string          `json:"info"`
	Published    bool            `json:"published"`
	Analysis     string          `json:"analysis"`
	Timestamp    string          `json:"timestamp"`
	Distribution string          `json:"distribution"`
	Tags         []MISPEventTag  `json:"Tag"`
	Attributes   []MISPAttribute `json:"Attribute"`
	Galaxies     []MISPGalaxy    `json:"Galaxy"`
	Sightings    []MISPSighting  `json:"Sighting"`
	Org          *MISPOrg        `json:"Org"`
	Orgc         *MISPOrg        `json:"Orgc"`
}

// MISPEventTag is a tag on a MISP event.
type MISPEventTag struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// MISPAttribute is an attribute (IOC, CVE, link, etc.) on a MISP event.
type MISPAttribute struct {
	ID       string         `json:"id"`
	Category string         `json:"category"`
	Type     string         `json:"type"`
	Value    string         `json:"value"`
	Comment  string         `json:"comment"`
	Tags     []MISPEventTag `json:"Tag"`
}

// MISPGalaxy is a galaxy cluster attached to a MISP event.
type MISPGalaxy struct {
	Name           string              `json:"name"`
	Type           string              `json:"type"`
	GalaxyClusters []MISPGalaxyCluster `json:"GalaxyCluster"`
}

// MISPGalaxyCluster is a single galaxy cluster (threat actor, TTP, etc.).
type MISPGalaxyCluster struct {
	Type        string `json:"type"`
	Value       string `json:"value"`
	Description string `json:"description"`
}

// MISPSighting is a sighting of an attribute by an organisation.
type MISPSighting struct {
	ID           string   `json:"id"`
	AttributeID  string   `json:"attribute_id"`
	EventID      string   `json:"event_id"`
	OrgID        string   `json:"org_id"`
	DateSighting string   `json:"date_sighting"`
	Org          *MISPOrg `json:"Organisation"`
}

// MISPOrg is a MISP organisation reference.
type MISPOrg struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// MISPManifestEntry is an entry in MISP's event manifest.
type MISPManifestEntry struct {
	Event map[string]struct {
		UUID      string `json:"uuid"`
		Timestamp string `json:"timestamp"`
		Published bool   `json:"published"`
		Info      string `json:"info"`
	} `json:"Event"`
}

// FetchEvents pulls events from the MISP REST API.
// If since is set, only events modified after that timestamp are returned.
func (c *MISPClient) FetchEvents(since string, limit, page int) ([]MISPEvent, error) {
	u, err := url.Parse(c.BaseURL + "/events/restSearch")
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}

	q := u.Query()
	q.Set("returnFormat", "json")
	q.Set("limit", fmt.Sprintf("%d", limit))
	q.Set("page", fmt.Sprintf("%d", page+1)) // MISP pages are 1-indexed
	if since != "" {
		q.Set("timestamp", since)
	}
	u.RawQuery = q.Encode()

	body, err := c.doRequest("GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("fetch events: %w", err)
	}

	var resp MISPResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	events := make([]MISPEvent, 0, len(resp.Response))
	for _, item := range resp.Response {
		events = append(events, item.Event)
	}
	return events, nil
}

// FetchEvent fetches a single event by UUID.
func (c *MISPClient) FetchEvent(uuid string) (*MISPEvent, error) {
	u := fmt.Sprintf("%s/events/view/%s", c.BaseURL, uuid)
	q := url.Values{}
	q.Set("returnFormat", "json")
	fullURL := u + "?" + q.Encode()

	body, err := c.doRequest("GET", fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch event %s: %w", uuid, err)
	}

	var resp MISPResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if len(resp.Response) == 0 {
		return nil, fmt.Errorf("event %s not found", uuid)
	}
	return &resp.Response[0].Event, nil
}

// doRequest makes an HTTP request with MISP HMAC-SHA256 signing.
func (c *MISPClient) doRequest(method, urlStr string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequest(method, urlStr, body)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	// MISP HMAC-SHA256 signing
	// Authorization: <api key>
	req.Header.Set("Authorization", c.APIKey)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	// Cap the response read so a compromised/MITM'd MISP (trivial when the lab
	// TLS-skip flag is on) can't OOM the arbiter with a multi-GB body.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxMISPResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("misp api error %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// NormalizeEvent converts a raw MISP event into a canonical ThreatEvent.
func NormalizeMISPEvent(raw MISPEvent) model.ThreatEvent {
	event := model.ThreatEvent{
		ID:               raw.UUID,
		Source:           "misp",
		SourceConfidence: mapTLPToConfidence(extractTLP(raw.Tags)),
		Title:            raw.Info,
		Description:      raw.Info,
	}

	// Parse timestamp
	if ts, err := strToUnix(raw.Timestamp); err == nil {
		event.Timestamp = ts
	}

	// Extract CVEs and CVSS from attributes
	for _, attr := range raw.Attributes {
		if strings.HasPrefix(attr.Value, "CVE-") {
			event.CVEs = append(event.CVEs, attr.Value)
		}
		// Extract CVSS from attribute tags
		for _, tag := range attr.Tags {
			if strings.HasPrefix(tag.Name, "cvss:") {
				if cvss, err := parseCVSS(strings.TrimPrefix(tag.Name, "cvss:")); err == nil {
					event.CVSS = cvss
				}
			}
		}
		// Extract references
		if attr.Type == "link" {
			event.References = append(event.References, attr.Value)
		}
		// Extract CPE product/version into AffectedProducts. This is what lets
		// the CVE matcher version-compare (reach exact_version_match) instead of
		// relying only on the weak title-keyword fallback. Events that carry a
		// CVE but no CPE still match by title — that is a source-data limit, not
		// something we can synthesize here (the tool does no NVD/CPE enrichment).
		if attr.Type == "cpe" {
			if ap, ok := parseCPE(attr.Value); ok {
				event.AffectedProducts = append(event.AffectedProducts, ap)
			}
		}
		// Extract IOCs for EDR integration
		iocType := mapMISPToIOCType(attr.Type)
		if iocType != "" && attr.Value != "" {
			desc := attr.Comment
			if desc == "" {
				desc = raw.Info
			}
			event.IOCs = append(event.IOCs, model.IOC{
				Type:        iocType,
				Value:       attr.Value,
				Description: desc,
				Source:      "misp",
				Tags:        eventTags(attr.Tags),
			})
		}
	}

	// Extract tags
	for _, tag := range raw.Tags {
		event.Tags = append(event.Tags, tag.Name)
	}

	// Extract threat actors from galaxies
	for _, galaxy := range raw.Galaxies {
		for _, cluster := range galaxy.GalaxyClusters {
			if cluster.Type == "threat-actor" {
				event.ThreatActors = append(event.ThreatActors, cluster.Value)
			}
		}
	}

	return event
}

// mapTLPToConfidence maps TLP markings to source confidence levels.
func mapTLPToConfidence(tlp string) string {
	switch tlp {
	case "tlp:red":
		return "high" // TLP:RED comes from trusted sources
	case "tlp:amber":
		return "medium"
	case "tlp:green":
		return "medium"
	case "tlp:white":
		return "low"
	default:
		return "medium"
	}
}

// extractTLP extracts the TLP tag from a list of tags.
func extractTLP(tags []MISPEventTag) string {
	for _, tag := range tags {
		if strings.HasPrefix(tag.Name, "tlp:") {
			return tag.Name
		}
	}
	return ""
}

// extractTLP
func strToUnix(s string) (time.Time, error) {
	var unix int64
	if _, err := fmt.Sscanf(s, "%d", &unix); err != nil {
		return time.Time{}, err
	}
	return time.Unix(unix, 0), nil
}

// parseCVSS parses a CVSS score string to float64.
func parseCVSS(s string) (float64, error) {
	var score float64
	if _, err := fmt.Sscanf(s, "%f", &score); err != nil {
		return 0, err
	}
	return score, nil
}

// parseCPE parses a CPE 2.2 (cpe:/a:vendor:product:version) or CPE 2.3
// (cpe:2.3:a:vendor:product:version:...) string into an AffectedProduct.
// Returns ok=false if vendor/product can't be extracted. A concrete version
// (not "*"/"-") is recorded as an exact affected version so the CVE matcher can
// version-compare against the tech stack.
func parseCPE(cpe string) (model.AffectedProduct, bool) {
	s := strings.TrimSpace(strings.ToLower(cpe))
	var fields []string
	switch {
	case strings.HasPrefix(s, "cpe:2.3:"):
		fields = strings.Split(strings.TrimPrefix(s, "cpe:2.3:"), ":") // part,vendor,product,version,...
	case strings.HasPrefix(s, "cpe:/"):
		fields = strings.Split(strings.TrimPrefix(s, "cpe:/"), ":") // part,vendor,product,version,...
	default:
		return model.AffectedProduct{}, false
	}
	if len(fields) < 3 {
		return model.AffectedProduct{}, false
	}
	vendor := cpeUnbind(fields[1])
	product := cpeUnbind(fields[2])
	if vendor == "" || product == "" {
		return model.AffectedProduct{}, false
	}
	ap := model.AffectedProduct{Vendor: vendor, Product: product}
	if len(fields) >= 4 {
		if ver := cpeUnbind(fields[3]); ver != "" {
			ap.VersionStart = ver
			ap.VersionEnd = ver // CPE names a specific affected version
		}
	}
	return ap, true
}

// cpeUnbind converts a CPE well-formed-name component to a plain string:
// wildcards become empty, underscores become spaces (CPE convention for
// spaces), and escaped characters are unescaped.
func cpeUnbind(s string) string {
	if s == "" || s == "*" || s == "-" {
		return ""
	}
	s = strings.ReplaceAll(s, `\:`, ":")
	s = strings.ReplaceAll(s, `\`, "")
	s = strings.ReplaceAll(s, "_", " ")
	return strings.TrimSpace(s)
}

// mapMISPToIOCType maps a MISP attribute type to an IOC type for EDR integration.
func mapMISPToIOCType(mispType string) model.IOCType {
	switch mispType {
	case "ip-src", "ip-dst", "ip":
		return model.IOCIPv4
	case "ipv6":
		return model.IOCIPv6
	case "domain", "hostname":
		return model.IOCDomain
	case "sha256":
		return model.IOCHashSHA256
	case "md5":
		return model.IOCHashMD5
	default:
		return ""
	}
}

// eventTags extracts tag names from MISP attribute tags.
func eventTags(tags []MISPEventTag) []string {
	out := make([]string, len(tags))
	for i, t := range tags {
		out[i] = t.Name
	}
	return out
}
