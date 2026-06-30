// Package notify provides the alert notification router and channel senders.
package notify

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/jayelbotvibe-web/threatlib/internal/model"
)

// Rule is a routing rule from routing.yaml.
type Rule struct {
	Severity   string   `yaml:"severity"`
	Confidence []string `yaml:"confidence"`
	Channels   []string `yaml:"channels"`
	Format     string   `yaml:"format"` // "realtime", "daily_digest", "weekly_digest"
}

// Router matches alerts to notification channels based on routing rules.
type Router struct {
	Rules      []Rule
	Notifiers  map[string]Notifier
}

// Notifier sends an alert to a specific channel.
type Notifier interface {
	Name() string
	Send(alert model.Alert) error
}

// NewRouter creates a router with the given rules and notifiers.
func NewRouter(rules []Rule) *Router {
	return &Router{
		Rules:     rules,
		Notifiers: make(map[string]Notifier),
	}
}

// Register adds a notifier for a channel name.
func (r *Router) Register(name string, n Notifier) {
	r.Notifiers[name] = n
}

// Route determines which channels an alert should go to and sends it.
func (r *Router) Route(alert model.Alert) []string {
	var routed []string

ruleLoop:
	for _, rule := range r.Rules {
		// Match severity
		if rule.Severity != alert.Severity {
			continue
		}
		// Match confidence
		if !containsAny(rule.Confidence, strings.ToLower(alert.Confidence)) {
			continue
		}
		// Send to each channel
		for _, channel := range rule.Channels {
			if n, ok := r.Notifiers[channel]; ok {
				if err := n.Send(alert); err != nil {
					log.Printf("notify: %s failed for alert %s: %v", channel, alert.ID, err)
					continue
				}
				routed = append(routed, channel)
			}
		}
		break ruleLoop // first matching rule wins
	}

	return routed
}

// containsAny returns true if s is in the list (case-insensitive).
func containsAny(list []string, s string) bool {
	for _, item := range list {
		if strings.ToLower(item) == s {
			return true
		}
	}
	return false
}

// ─────────────────────────────────────────────────────────────
// Console Notifier — prints formatted alerts to stdout for testing
// ─────────────────────────────────────────────────────────────

// ConsoleNotifier prints alerts to stdout with ANSI colors.
type ConsoleNotifier struct {
	name  string
	out   *os.File
}

// NewConsoleNotifier creates a notifier that prints to stdout.
func NewConsoleNotifier(name string) *ConsoleNotifier {
	return &ConsoleNotifier{name: name, out: os.Stdout}
}

// Name returns the notifier name.
func (n *ConsoleNotifier) Name() string { return n.name }

// Send prints a formatted alert to the console.
func (n *ConsoleNotifier) Send(alert model.Alert) error {
	// Severity color
	var color, reset string
	switch alert.Severity {
	case "critical":
		color = "\033[1;31m" // bold red
	case "high":
		color = "\033[1;33m" // bold yellow
	case "medium":
		color = "\033[1;36m" // bold cyan
	default:
		color = "\033[1;37m" // bold white
	}
	reset = "\033[0m"

	// Divider
	fmt.Fprintf(n.out, "\n%s══════════════════════════════════════════════════════════%s\n", color, reset)
	fmt.Fprintf(n.out, "%s  ▸▸▸ %s ALERT · %s · %s▸▸▸%s\n",
		color, strings.ToUpper(alert.Severity), alert.Confidence, n.name, reset)
	fmt.Fprintf(n.out, "%s══════════════════════════════════════════════════════════%s\n\n", color, reset)

	// Explanation (already formatted by risk engine)
	fmt.Fprintln(n.out, alert.Explanation)

	// Matched apps
	if len(alert.MatchedApps) > 0 {
		fmt.Fprintf(n.out, "\nMatched applications: %s\n", strings.Join(alert.MatchedApps, ", "))
	}

	// Footer
	fmt.Fprintf(n.out, "\n%s──────────────────────────────────────────────────────────────%s\n", color, reset)
	fmt.Fprintf(n.out, "Alert ID: %s · Event: %s · Time: %s\n", alert.ID, alert.EventID, alert.CreatedAt)
	fmt.Fprintf(n.out, "%s──────────────────────────────────────────────────────────────%s\n\n", color, reset)

	return nil
}

// ─────────────────────────────────────────────────────────────
// Text File Notifier — writes alerts to a file
// ─────────────────────────────────────────────────────────────

// FileNotifier writes alerts to a text file on disk.
type FileNotifier struct {
	name string
	path string
}

// NewFileNotifier creates a notifier that appends alerts to a file.
func NewFileNotifier(name, path string) *FileNotifier {
	return &FileNotifier{name: name, path: path}
}

// Name returns the notifier name.
func (n *FileNotifier) Name() string { return n.name }

// Send appends the alert to the file.
func (n *FileNotifier) Send(alert model.Alert) error {
	f, err := os.OpenFile(n.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open %s: %w", n.path, err)
	}
	defer f.Close()

	fmt.Fprintf(f, "\n══════════════════════════════════════════════════\n")
	fmt.Fprintf(f, "  %s ALERT · %s\n", strings.ToUpper(alert.Severity), alert.Confidence)
	fmt.Fprintf(f, "══════════════════════════════════════════════════\n\n")
	fmt.Fprintf(f, "%s\n", alert.Explanation)
	fmt.Fprintf(f, "Alert ID: %s · Event: %s · Time: %s\n\n", alert.ID, alert.EventID, alert.CreatedAt)
	return nil
}
