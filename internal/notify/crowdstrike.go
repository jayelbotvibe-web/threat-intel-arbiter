// Package notify provides notification dispatchers (Slack, Teams, Email, Crowdstrike).
package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
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

	mu           sync.Mutex // protects sent, pending, flushCh
	tokenMu      sync.Mutex // protects token, expires, tokenRefreshing
	token        string
	expires      time.Time
	refreshing   bool // single-flight guard for token refresh
	sent         map[string]bool
	client       *http.Client
	pending      []csIndicator
	flushCh      chan struct{}
	closed       chan struct{}   // closed on shutdown for graceful drain
	preventTypes map[string]bool // types eligible for prevent (empty = all detect)
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
	// P0-1: Prevent requires explicit IOC type allowlist
	if cs.Action == "prevent" {
		cs.preventTypes = make(map[string]bool)
		if types := os.Getenv("CROWDSTRIKE_PREVENT_IOC_TYPES"); types != "" {
			for _, t := range strings.Split(types, ",") {
				cs.preventTypes[strings.TrimSpace(t)] = true
			}
		}
		if len(cs.preventTypes) == 0 {
			log.Printf("crowdstrike: WARNING — action=prevent but CROWDSTRIKE_PREVENT_IOC_TYPES not set; all IOCs downgraded to detect")
		}
	}
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

		// P0-2: Validate and clean the IOC value
		clean := validateIOC(string(ioc.Type), ioc.Value)
		if clean == "" {
			log.Printf("crowdstrike: dropped invalid IOC %s=%q from %s", ioc.Type, ioc.Value, event.ID)
			continue
		}
		// P0-3: Block private IP ranges
		if (ioc.Type == model.IOCIPv4 || ioc.Type == model.IOCIPv6) && isPrivateIP(clean) {
			log.Printf("crowdstrike: blocked private IP %s from %s", clean, event.ID)
			continue
		}
		// P0-4: Check TLP export boundary
		if blockedTLP(append(ioc.Tags, event.Tags...)) {
			log.Printf("crowdstrike: blocked TLP-restricted IOC %s=%s from %s", ioc.Type, ioc.Value, event.ID)
			continue
		}

		// Dedup key uses cleaned value
		dedupKey := string(ioc.Type) + ":" + clean

		// Build description from the IOC's own comment, not the event title
		desc := ioc.Description
		if desc == "" || desc == event.Title {
			desc = fmt.Sprintf("%s IOC from MISP event", ioc.Type)
		}

		action := c.Action
		// P0-1: Only allow prevent for explicitly approved IOC types
		if action == "prevent" && len(c.preventTypes) > 0 && !c.preventTypes[string(ioc.Type)] {
			action = "detect"
		}

		indicator := csIndicator{
			Source:      ioc.Source,
			Action:      action,
			Expiration:  expiration,
			Type:        string(ioc.Type),
			Value:       clean,
			Description: cleanDesc(desc),
			Severity:    csSev,
			Platforms:   []string{"windows", "mac", "linux"},
			Tags:        copyTags(event),
		}

		if c.Mock {
			c.mu.Lock()
			c.sent[dedupKey] = true
			c.mu.Unlock()
			sent++
			continue
		}

		c.mu.Lock()
		c.pending = append(c.pending, indicator)
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
		c.mu.Lock()
		c.pending = append(batch, c.pending...)
		if len(c.pending) > 1000 {
			log.Printf("crowdstrike: pending overflow (%d), dropping %d oldest", len(c.pending), len(c.pending)-1000)
			c.pending = c.pending[len(c.pending)-1000:]
		}
		c.mu.Unlock()
	} else {
		// Mark delivered IOCs as sent (dedup after confirmed 2xx)
		c.mu.Lock()
		for _, ind := range batch {
			c.sent[ind.Type+":"+ind.Value] = true
		}
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

// cleanDesc sanitizes the IOC description — caps length, strips control chars.
func cleanDesc(d string) string {
	if len(d) > 256 {
		d = d[:256]
	}
	return strings.Map(func(r rune) rune {
		if r < 32 && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, d)
}

// copyTags creates a fresh slice from event tags + CVEs to prevent aliasing.
func copyTags(event model.ThreatEvent) []string {
	tags := make([]string, 0, len(event.Tags)+len(event.CVEs))
	tags = append(tags, event.Tags...)
	tags = append(tags, event.CVEs...)
	return tags
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ─── IOC validation, denylist, and TLP guards ───

var (
	// RFC1918, loopback, link-local, CGNAT, multicast — never send to EDR.
	privateNets = []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", // RFC1918
		"127.0.0.0/8",    // loopback
		"169.254.0.0/16", // link-local
		"100.64.0.0/10",  // CGNAT
		"224.0.0.0/4",    // multicast
		"0.0.0.0/8",      // current network
		"240.0.0.0/4",    // reserved
	}
	// Common defang patterns to refang.
	defangRE = regexp.MustCompile(`\[\.\]|\(dot\)|hxxps?://|hxxp://|\\[.\\]`)
	// Valid domain name (hostname label)
	domainRE = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.?$`)
)

// validateIOC checks the IOC value and returns the cleaned value or empty string if invalid.
func validateIOC(iocType string, value string) string {
	v := strings.TrimSpace(strings.ToLower(defangRE.ReplaceAllString(value, ".")))
	v = strings.ReplaceAll(v, "hxxp://", "")
	v = strings.ReplaceAll(v, "hxxps://", "")

	switch iocType {
	case "ipv4", "ipv6":
		if ip := net.ParseIP(v); ip != nil {
			return ip.String()
		}
		return ""
	case "domain":
		if domainRE.MatchString(v) && !strings.HasSuffix(v, ".local") {
			return v
		}
		return ""
	case "hash_sha256":
		if len(v) == 64 && isHex(v) {
			return v
		}
		return ""
	case "hash_md5":
		if len(v) == 32 && isHex(v) {
			return v
		}
		return ""
	default:
		return ""
	}
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// isPrivateIP returns true if the IP is in a private/reserved range.
func isPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return true // can't parse = reject
	}
	for _, cidr := range privateNets {
		_, net, _ := net.ParseCIDR(cidr)
		if net != nil && net.Contains(parsed) {
			return true
		}
	}
	return false
}

// blockedTLP returns true if the IOC's TLP marking is above the export threshold.
// Default: allow green/clear only; block amber/red unless opted in.
func blockedTLP(tags []string) bool {
	maxTLP := os.Getenv("CROWDSTRIKE_MAX_TLP")
	if maxTLP == "" {
		maxTLP = "green"
	}
	tlpRanks := map[string]int{"red": 4, "amber": 3, "green": 2, "white": 1, "clear": 1}
	threshold := tlpRanks[strings.ToLower(maxTLP)]
	for _, tag := range tags {
		if strings.HasPrefix(strings.ToLower(tag), "tlp:") {
			parts := strings.SplitN(tag, ":", 2)
			if len(parts) == 2 {
				if level, ok := tlpRanks[strings.ToLower(parts[1])]; ok {
					return level > threshold
				}
			}
		}
	}
	return false // no TLP = default allow (open source feeds)
}
