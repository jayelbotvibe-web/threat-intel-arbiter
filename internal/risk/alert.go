package risk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/model"
)

// DedupKey generates a deduplication hash from event + score result.
func DedupKey(event model.ThreatEvent, result ScoreResult) string {
	h := sha256.New()
	data := fmt.Sprintf("%s|%s|%s|%.1f|%s",
		event.ID, event.Source, result.Severity, result.RiskScore, event.Title,
	)
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// NewAlert creates an alert from a scored event.
func NewAlert(event model.ThreatEvent, result ScoreResult, matches []model.Match) model.Alert {
	apps := make([]string, 0)
	for _, m := range matches {
		if m.AppName != "" {
			apps = append(apps, m.AppName)
		}
	}
	return model.Alert{
		ID:          DedupKey(event, result),
		EventID:     event.ID,
		Severity:    result.Severity,
		Confidence:  result.ConfidenceLabel,
		Action:      SSVCAction(result.Severity, result.ConfidenceLabel),
		Explanation: result.Explanation,
		Status:      "new",
		MatchedApps: apps,
		CreatedAt:   time.Now().Format(time.RFC3339),
	}
}

// SSVCAction maps severity + confidence to an SSVC action directive.
func SSVCAction(severity, confidence string) string {
	switch {
	case severity == "critical" && confidence == "HIGH":
		return "Act Now"
	case severity == "critical":
		return "Schedule"
	case severity == "high" && (confidence == "HIGH" || confidence == "MEDIUM"):
		return "Schedule"
	case severity == "high":
		return "Track"
	case severity == "medium":
		return "Track"
	default:
		return "Monitor"
	}
}

// MarshalAlert serializes an alert to JSON.
func MarshalAlert(a model.Alert) ([]byte, error) {
	return json.Marshal(a)
}
