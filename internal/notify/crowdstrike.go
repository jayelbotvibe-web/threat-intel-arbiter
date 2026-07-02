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
	"sync"
	"time"

	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/model"
)

// CrowdstrikeNotifier sends IOCs to Crowdstrike Falcon for EDR integration.
// Authenticates via OAuth2 (client_id + client_secret) and auto-refreshes tokens.
// In mock mode (CLIENT_ID not set), logs instead of sending.
type CrowdstrikeNotifier struct {
	BaseURL    string
	ClientID   string
	Secret     string
	Action     string // "detect" or "prevent"
	Severity   string // minimum severity to send
	Expiration int    // days until IOC expires
	Mock       bool

	mu       sync.Mutex
	token    string
	expires  time.Time
	sent     map[string]bool // dedup: "type:value" → true
	client   *http.Client
	pending  []csIndicator // batched IOCs
	flushCh  chan struct{} // signal to flush batch
}

// NewCrowdstrikeNotifier creates a Crowdstrike notifier from environment variables.
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
		sent:       make(map[string]bool),
		pending:    make([]csIndicator, 0, 100),
		flushCh:    make(chan struct{}, 1),
		client:     &http.Client{Timeout: 30 * time.Second},
	}
	if exp := os.Getenv("CROWDSTRIKE_EXPIRATION"); exp != "" {
		fmt.Sscanf(exp, "%d", &cs.Expiration)
	}
	// Background flusher: send batched IOCs every 30 seconds
	if !cs.Mock {
		go cs.flusher()
	}
	return cs
}

// flusher periodically sends batched IOCs.
func (c *CrowdstrikeNotifier) flusher() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.flush()
		case <-c.flushCh:
			c.flush()
		}
	}
}

// Notify sends IOCs from a threat event to Crowdstrike Falcon.
// IOCs are batched and sent periodically to avoid rate limits.
func (c *CrowdstrikeNotifier) Notify(event model.ThreatEvent, severity, confidence string) (int, error) {
	if len(event.IOCs) == 0 {
		return 0, nil
	}
	if !meetsSeverity(severity, c.Severity) {
		return 0, nil
	}

	var sent int
	expiration := time.Now().Add(time.Duration(c.Expiration) * 24 * time.Hour).UTC().Format("2006-01-02T15:04:05Z")
	csSev := mapToCSSeverity(severity)

	for _, ioc := range event.IOCs {
		key := string(ioc.Type) + ":" + ioc.Value
		if c.sent[key] {
			continue // already sent in a previous cycle
		}

		// Build description from the IOC's own comment, not the event title
		desc := ioc.Description
		if desc == "" || desc == event.Title {
			desc = fmt.Sprintf("%s IOC from MISP event", ioc.Type)
		}

		indicator := csIndicator{
			Source:      ioc.Source,
			Action:      c.Action,
			Expiration:  expiration,
			Type:        string(ioc.Type),
			Value:       ioc.Value,
			Description: desc,
			Severity:    csSev,
			Platforms:   []string{"windows", "mac", "linux"},
			Tags:        append(event.Tags, event.CVEs...),
		}

		if c.Mock {
			c.sent[key] = true
			sent++
			continue
		}

		c.mu.Lock()
		c.pending = append(c.pending, indicator)
		c.sent[key] = true
		c.mu.Unlock()
		sent++

		// Flush if batch is full
		if len(c.pending) >= 100 {
			select {
			case c.flushCh <- struct{}{}:
			default:
			}
		}
	}

	if c.Mock && sent > 0 {
		log.Printf("crowdstrike [MOCK]: would send %d IOCs from event %s (%d total sent)", sent, event.ID, len(c.sent))
	}

	return sent, nil
}

// flush sends all pending IOCs to Crowdstrike.
func (c *CrowdstrikeNotifier) flush() {
	c.mu.Lock()
	if len(c.pending) == 0 {
		c.mu.Unlock()
		return
	}
	batch := make([]csIndicator, len(c.pending))
	copy(batch, c.pending)
	c.pending = c.pending[:0]
	c.mu.Unlock()

	if _, err := c.send(batch); err != nil {
		log.Printf("crowdstrike: flush error: %v (re-queuing)", err)
		// Re-queue on failure
		c.mu.Lock()
		c.pending = append(batch, c.pending...)
		c.mu.Unlock()
	}
}

// getToken returns a valid OAuth2 access token, refreshing if needed.
func (c *CrowdstrikeNotifier) getToken() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token != "" && time.Now().Before(c.expires) {
		return c.token, nil
	}

	url := c.BaseURL + "/oauth2/token"
	body := fmt.Sprintf("client_id=%s&client_secret=%s", c.ClientID, c.Secret)
	req, err := http.NewRequest("POST", url, bytes.NewReader([]byte(body)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("oauth2: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("oauth2 error %d: %s", resp.StatusCode, string(respBody))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return "", fmt.Errorf("oauth2 parse: %w", err)
	}

	c.token = tokenResp.AccessToken
	c.expires = time.Now().Add(time.Duration(tokenResp.ExpiresIn-60) * time.Second) // buffer
	return c.token, nil
}

// send posts a batch of IOCs to Crowdstrike Falcon API.
func (c *CrowdstrikeNotifier) send(indicators []csIndicator) (int, error) {
	if len(indicators) == 0 {
		return 0, nil
	}

	body := csRequest{
		Comment:    fmt.Sprintf("Threat Intel Arbiter — %d IOCs", len(indicators)),
		Indicators: indicators,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return 0, fmt.Errorf("marshal: %w", err)
	}

	token, err := c.getToken()
	if err != nil {
		return 0, fmt.Errorf("auth: %w", err)
	}

	url := c.BaseURL + "/indicators/entities/iocs/v1"
	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	if err != nil {
		return 0, fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("send: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return 0, fmt.Errorf("crowdstrike API error %d: %s", resp.StatusCode, string(respBody))
	}

	log.Printf("crowdstrike: sent %d IOCs (status %d, total sent %d)", len(indicators), resp.StatusCode, len(c.sent))
	return len(indicators), nil
}

// ─── Types ───

type csRequest struct {
	Comment    string        `json:"comment"`
	Indicators []csIndicator `json:"indicators"`
}

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

// ─── Helpers ───

func meetsSeverity(eventSev, floor string) bool {
	ranks := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
	return ranks[eventSev] >= ranks[floor]
}

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
