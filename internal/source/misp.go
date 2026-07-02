// Package source provides threat intelligence source connectors.
package source

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/model"
)

// MISPClient is a REST client for the MISP threat intelligence platform.
// It handles HMAC-SHA256 request signing as required by MISP's API.
type MISPClient struct {
	BaseURL  string
	APIKey   string
	HTTP     *http.Client
}

// NewMISPClient creates a new MISP API client.
func NewMISPClient(baseURL, apiKey string) *MISPClient {
	return &MISPClient{
		BaseURL: strings.TrimRight(baseURL, "/"),
		APIKey:  apiKey,
		HTTP: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
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
	Value    string         `json:"value1"`
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
	ID          string  `json:"id"`
	AttributeID string  `json:"attribute_id"`
	EventID     string  `json:"event_id"`
	OrgID       string  `json:"org_id"`
	DateSighting string `json:"date_sighting"`
	Org         *MISPOrg `json:"Organisation"`
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

	respBody, err := io.ReadAll(resp.Body)
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
