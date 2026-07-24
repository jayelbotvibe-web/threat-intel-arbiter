package notify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/model"
)

// redactPostErr strips the request URL from a transport error before it is
// returned/logged. A Slack/Teams incoming-webhook URL *is* the credential, and
// *url.Error embeds it in its Error() string, so wrapping it with %w would leak
// the secret into logs on any network failure.
func redactPostErr(what string, err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s failed: %s: %v", what, ue.Op, ue.Err)
	}
	return fmt.Errorf("%s failed: %v", what, err)
}

// SlackNotifier sends alerts to a Slack incoming webhook.
type SlackNotifier struct {
	WebhookURL string
	HTTP       *http.Client
}

// NewSlackNotifier creates a Slack notifier from env or config.
func NewSlackNotifier(webhookURL string) *SlackNotifier {
	if webhookURL == "" {
		webhookURL = os.Getenv("SLACK_WEBHOOK_URL")
	}
	return &SlackNotifier{
		WebhookURL: webhookURL,
		HTTP:       &http.Client{Timeout: 10 * time.Second},
	}
}

func (n *SlackNotifier) Name() string { return "slack" }

func (n *SlackNotifier) Send(alert model.Alert) error {
	if n.WebhookURL == "" {
		return fmt.Errorf("slack: no webhook URL configured")
	}

	color := map[string]string{
		"critical": "#DC2626", "high": "#EA580C", "medium": "#CA8A04", "low": "#6B7280",
	}[alert.Severity]
	if color == "" {
		color = "#6B7280"
	}

	// Slack message payload
	payload := map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"color": color,
				"title": fmt.Sprintf("[%s] %s · %s confidence",
					strings.ToUpper(alert.Severity), alert.Explanation[:min(len(alert.Explanation), 120)],
					alert.Confidence),
				"text": alert.Explanation,
				"fields": []map[string]interface{}{
					{"title": "Severity", "value": strings.ToUpper(alert.Severity), "short": true},
					{"title": "Confidence", "value": alert.Confidence, "short": true},
				},
				"footer": fmt.Sprintf("Alert ID: %s · Event: %s", alert.ID, alert.EventID),
				"ts":     time.Now().Unix(),
			},
		},
	}

	body, _ := json.Marshal(payload)
	resp, err := n.HTTP.Post(n.WebhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return redactPostErr("slack post", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack returned %d", resp.StatusCode)
	}
	return nil
}

// TeamsNotifier sends alerts to a Microsoft Teams incoming webhook.
type TeamsNotifier struct {
	WebhookURL string
	HTTP       *http.Client
}

// NewTeamsNotifier creates a Teams notifier from env or config.
func NewTeamsNotifier(webhookURL string) *TeamsNotifier {
	if webhookURL == "" {
		webhookURL = os.Getenv("TEAMS_WEBHOOK_URL")
	}
	return &TeamsNotifier{
		WebhookURL: webhookURL,
		HTTP:       &http.Client{Timeout: 10 * time.Second},
	}
}

func (n *TeamsNotifier) Name() string { return "teams" }

func (n *TeamsNotifier) Send(alert model.Alert) error {
	if n.WebhookURL == "" {
		return fmt.Errorf("teams: no webhook URL configured")
	}

	// Adaptive Card format
	payload := map[string]interface{}{
		"@type":    "MessageCard",
		"@context": "https://schema.org/extensions",
		"summary":  fmt.Sprintf("Threat Intel Arbiter: %s alert", alert.Severity),
		"title":    fmt.Sprintf("[%s] %s", strings.ToUpper(alert.Severity), alert.Explanation[:min(len(alert.Explanation), 100)]),
		"text":     alert.Explanation,
		"sections": []map[string]interface{}{
			{
				"facts": []map[string]string{
					{"name": "Severity", "value": strings.ToUpper(alert.Severity)},
					{"name": "Confidence", "value": alert.Confidence},
					{"name": "Alert ID", "value": alert.ID},
				},
			},
		},
	}

	body, _ := json.Marshal(payload)
	resp, err := n.HTTP.Post(n.WebhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return redactPostErr("teams post", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("teams returned %d", resp.StatusCode)
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
