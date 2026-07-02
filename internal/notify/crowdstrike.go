// Package notify provides notification dispatchers (Slack, Teams, Email, Crowdstrike).
package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/model"
)

// CrowdstrikeNotifier sends IOCs to Crowdstrike Falcon for EDR integration.
// Supports mock mode for testing without real credentials.
type CrowdstrikeNotifier struct {
	BaseURL    string
	ClientID   string
	Secret     string
	Action     string // "detect" or "prevent"
	Severity   string // minimum severity to send
	Expiration int    // days until IOC expires
	Mock       bool   // if true, log instead of sending
	client     *http.Client
}

// NewCrowdstrikeNotifier creates a Crowdstrike notifier from environment variables.
// If CLIENT_ID is empty, runs in mock mode (logs IOCs instead of sending).
func NewCrowdstrikeNotifier() *CrowdstrikeNotifier {
	cid := os.Getenv("CROWDSTRIKE_CLIENT_ID")
	cs := &CrowdstrikeNotifier{
		BaseURL:    envOrDefault("CROWDSTRIKE_BASE_URL", "https://api.crowdstrike.com"),
		ClientID:   cid,
		Secret:     os.Getenv("CROWDSTRIKE_CLIENT_SECRET"),
		Action:     envOrDefault("CROWDSTRIKE_ACTION", "detect"),
		Severity:   envOrDefault("CROWDSTRIKE_SEVERITY", "medium"),
		Expiration: 30,
		Mock:       cid == "",
		client:     &http.Client{Timeout: 30 * time.Second},
	}
	if exp := os.Getenv("CROWDSTRIKE_EXPIRATION"); exp != "" {
		fmt.Sscanf(exp, "%d", &cs.Expiration)
	}
	return cs
}

// Notify sends IOCs from a threat event to Crowdstrike Falcon.
// Returns the number of IOCs sent (or logged in mock mode).
func (c *CrowdstrikeNotifier) Notify(event model.ThreatEvent, severity, confidence string) (int, error) {
	if len(event.IOCs) == 0 {
		return 0, nil
	}

	// Filter by severity floor
	if !meetsSeverity(severity, c.Severity) {
		return 0, nil
	}

	// Build Crowdstrike-format indicators
	var indicators []csIndicator
	for _, ioc := range event.IOCs {
		indicators = append(indicators, csIndicator{
			Source:      ioc.Source,
			Action:      c.Action,
			Expiration:  time.Now().Add(time.Duration(c.Expiration) * 24 * time.Hour).UTC().Format("2006-01-02T15:04:05Z"),
			Type:        string(ioc.Type),
			Value:       ioc.Value,
			Description: fmt.Sprintf("%s: %s", event.Title, ioc.Description),
			Severity:    mapToCSSeverity(severity),
			Platforms:   []string{"windows", "mac", "linux"},
			Tags:        append(event.Tags, event.CVEs...),
		})
	}

	if c.Mock {
		log.Printf("crowdstrike [MOCK]: would send %d IOCs from event %s", len(indicators), event.ID)
		return len(indicators), nil
	}

	return c.send(indicators)
}

// send posts the IOC batch to Crowdstrike Falcon API.
func (c *CrowdstrikeNotifier) send(indicators []csIndicator) (int, error) {
	body := csRequest{
		Comment:     fmt.Sprintf("Threat Intel Arbiter — %d IOCs", len(indicators)),
		Indicators:  indicators,
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return 0, fmt.Errorf("marshal: %w", err)
	}

	url := c.BaseURL + "/indicators/entities/iocs/v1"
	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	if err != nil {
		return 0, fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.ClientID)

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("send: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return 0, fmt.Errorf("crowdstrike API error %d: %s", resp.StatusCode, string(respBody))
	}

	log.Printf("crowdstrike: sent %d IOCs (status %d)", len(indicators), resp.StatusCode)
	return len(indicators), nil
}

// csRequest is the Crowdstrike Falcon IOC batch request format.
type csRequest struct {
	Comment    string        `json:"comment"`
	Indicators []csIndicator `json:"indicators"`
}

// csIndicator is a single IOC in Crowdstrike Falcon format.
type csIndicator struct {
	Source      string   `json:"source"`
	Action      string   `json:"action"`
	Expiration  string   `json:"expiration"`
	Type        string   `json:"type"`
	Value       string   `json:"value"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Platforms   []string `json:"platforms"`
	Tags        []string `json:"tags"`
}

// meetsSeverity returns true if the event severity meets the configured floor.
func meetsSeverity(eventSev, floor string) bool {
	ranks := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
	return ranks[eventSev] >= ranks[floor]
}

// mapToCSSeverity maps our severity labels to Crowdstrike's format.
func mapToCSSeverity(sev string) string {
	switch sev {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	default:
		return "low"
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
