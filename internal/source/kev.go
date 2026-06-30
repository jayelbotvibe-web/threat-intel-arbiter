package source

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/jayelbotvibe-web/threatlib/internal/model"
)

// KEVEntry is a single entry in the CISA KEV catalog.
type KEVEntry struct {
	CVEID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	ShortDescription  string `json:"shortDescription"`
	RequiredAction    string `json:"requiredAction"`
	DueDate           string `json:"dueDate"`
	KnownRansomware   string `json:"knownRansomwareCampaignUse"`
	Notes             string `json:"notes"`
}

// KEVResponse is the CISA KEV catalog JSON structure.
type KEVResponse struct {
	Title           string     `json:"title"`
	CatalogVersion  string     `json:"catalogVersion"`
	DateReleased    string     `json:"dateReleased"`
	Count           int        `json:"count"`
	Vulnerabilities []KEVEntry `json:"vulnerabilities"`
}

// KEVClient fetches the CISA Known Exploited Vulnerabilities catalog.
type KEVClient struct {
	URL  string
	HTTP *http.Client
}

// DefaultKEVURL is the public CISA KEV JSON endpoint.
const DefaultKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// NewKEVClient creates a KEV catalog client.
func NewKEVClient(url string) *KEVClient {
	if url == "" {
		url = DefaultKEVURL
	}
	return &KEVClient{
		URL:  url,
		HTTP: &http.Client{Timeout: 30 * time.Second},
	}
}

// Fetch pulls the KEV catalog and returns all entries.
func (c *KEVClient) Fetch() ([]KEVEntry, error) {
	resp, err := c.HTTP.Get(c.URL)
	if err != nil {
		return nil, fmt.Errorf("fetch KEV: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("KEV API returned %d: %s", resp.StatusCode, string(body))
	}

	var catalog KEVResponse
	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("decode KEV: %w", err)
	}

	return catalog.Vulnerabilities, nil
}

// NormalizeKEV converts a KEV entry into a canonical ThreatEvent.
func NormalizeKEV(entry KEVEntry) model.ThreatEvent {
	return model.ThreatEvent{
		ID:               entry.CVEID,
		Source:           "cisa-kev",
		SourceConfidence: "high", // CISA is authoritative
		Title:            entry.CVEID + " — " + entry.VulnerabilityName,
		CVEs:             []string{entry.CVEID},
		Tags:             []string{"exploit:in-the-wild", "source:cisa-kev"},
		Description:      entry.ShortDescription,
		AffectedProducts: []model.AffectedProduct{
			{Vendor: entry.VendorProject, Product: entry.Product},
		},
		References: []string{"https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
	}
}

// KEVPoller periodically fetches the KEV catalog and sends entries to the event queue.
type KEVPoller struct {
	Client   *KEVClient
	Events   chan<- model.ThreatEvent
	Interval time.Duration
}

// Run starts the KEV polling loop. Blocks until ctx is cancelled.
func (p *KEVPoller) Run(ctx context.Context) error {
	ticker := time.NewTicker(p.Interval)
	defer ticker.Stop()

	// Fetch immediately on start
	p.fetchAndSend()

	for {
		select {
		case <-ctx.Done():
			log.Println("kev poller: shutting down")
			return ctx.Err()
		case <-ticker.C:
			p.fetchAndSend()
		}
	}
}

func (p *KEVPoller) fetchAndSend() {
	entries, err := p.Client.Fetch()
	if err != nil {
		log.Printf("kev poller: fetch error: %v", err)
		return
	}

	log.Printf("kev poller: fetched %d entries", len(entries))

	for _, entry := range entries {
		event := NormalizeKEV(entry)
		select {
		case p.Events <- event:
		default:
			log.Printf("kev poller: queue full, dropping %s", entry.CVEID)
		}
	}
}
