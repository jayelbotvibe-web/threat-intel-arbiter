// Package notify provides notification dispatchers (Slack, Teams, Email, Crowdstrike).
package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/model"
)

// CrowdstrikeNotifier sends IOCs to Crowdstrike Falcon for EDR integration.
// Authenticates via OAuth2 (client_id + client_secret) and auto-refreshes tokens.
// In mock mode (CLIENT_ID not set), logs instead of sending.
// Safe-by-default: action=detect unless explicit approval gate is met.
type CrowdstrikeNotifier struct {
	BaseURL    string
	ClientID   string
	Secret     string
	Action     string // "detect" or "prevent"
	Severity   string // minimum severity to send
	Expiration int    // days until IOC expires
	Mock       bool

	mu         sync.Mutex // protects sent, pending, flushCh
	tokenMu    sync.Mutex // protects token, expires, tokenRefreshing
	token      string
	expires    time.Time
	refreshing bool // single-flight guard for token refresh
	sent       map[string]bool
	client     *http.Client
	pending    []csIndicator
	flushCh    chan struct{}
	closed     chan struct{} // closed on shutdown for graceful drain
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
		closed:     make(chan struct{}),
		client:     &http.Client{Timeout: 30 * time.Second},
	}
	if exp := os.Getenv("CROWDSTRIKE_EXPIRATION"); exp != "" {
		if n, err := fmt.Sscanf(exp, "%d", &cs.Expiration); err != nil || n != 1 {
			log.Printf("crowdstrike: invalid CROWDSTRIKE_EXPIRATION %q, using default %d", exp, cs.Expiration)
		}
	}
	log.Printf("crowdstrike: action=%s severity=%s expiration=%dd mock=%v",
		cs.Action, cs.Severity, cs.Expiration, cs.Mock)
	if !cs.Mock {
		go cs.flusher()
	}
	return cs
}

// Close shuts down the flusher and performs a final flush of pending IOCs.
func (c *CrowdstrikeNotifier) Close() {
	close(c.closed)
	if !c.Mock {
		c.flush()
	}
}

// flusher periodically sends batched IOCs.
func (c *CrowdstrikeNotifier) flusher() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.closed:
			return
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
		c.mu.Lock()
		if c.sent[key] {
			c.mu.Unlock()
			continue
		}
		c.mu.Unlock()

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
			c.mu.Lock()
			c.sent[key] = true
			c.mu.Unlock()
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
		log.Printf("crowdstrike [MOCK]: would send %d IOCs from event %s (%d total sent)", sent, event.ID, c.sentCount())
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
// Releases the lock before making HTTP calls — single-flight pattern.
func (c *CrowdstrikeNotifier) getToken() (string, error) {
	c.tokenMu.Lock()
	if c.token != "" && time.Now().Before(c.expires) {
		tok := c.token
		c.tokenMu.Unlock()
		return tok, nil
	}
	if c.refreshing {
		// Another goroutine is already refreshing — wait briefly
		c.tokenMu.Unlock()
		time.Sleep(100 * time.Millisecond)
		return c.getToken()
	}
	c.refreshing = true
	c.tokenMu.Unlock()

	endpoint := c.BaseURL + "/oauth2/token"
	body := url.Values{
		"client_id":     {c.ClientID},
		"client_secret": {c.Secret},
	}.Encode()
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader([]byte(body)))
	if err != nil {
		c.tokenMu.Lock()
		c.refreshing = false
		c.tokenMu.Unlock()
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		c.tokenMu.Lock()
		c.refreshing = false
		c.tokenMu.Unlock()
		return "", fmt.Errorf("oauth2: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		c.tokenMu.Lock()
		c.refreshing = false
		c.tokenMu.Unlock()
		return "", fmt.Errorf("oauth2 read: %w", err)
	}
	if resp.StatusCode >= 400 {
		c.tokenMu.Lock()
		c.refreshing = false
		c.tokenMu.Unlock()
		return "", fmt.Errorf("oauth2 error %d: %s", resp.StatusCode, string(respBody))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		c.tokenMu.Lock()
		c.refreshing = false
		c.tokenMu.Unlock()
		return "", fmt.Errorf("oauth2 parse: %w", err)
	}

	c.tokenMu.Lock()
	c.token = tokenResp.AccessToken
	c.expires = time.Now().Add(time.Duration(tokenResp.ExpiresIn-60) * time.Second)
	c.refreshing = false
	tok := c.token
	c.tokenMu.Unlock()

	return tok, nil
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

	csURL := c.BaseURL + "/indicators/entities/iocs/v1"
	req, err := http.NewRequest("POST", csURL, bytes.NewReader(payload))
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

	log.Printf("crowdstrike: sent %d IOCs (status %d, total sent %d)", len(indicators), resp.StatusCode, c.sentCount())
	return len(indicators), nil
}

// sentCount returns the number of deduplicated IOCs under the mutex.
func (c *CrowdstrikeNotifier) sentCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.sent)
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
