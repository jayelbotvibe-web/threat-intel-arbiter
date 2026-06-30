package risk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jayelbotvibe-web/threatlib/internal/model"
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
		Explanation: result.Explanation,
		Status:      "new",
		MatchedApps: apps,
		CreatedAt:   time.Now().Format(time.RFC3339),
	}
}

// MarshalAlert serializes an alert to JSON.
func MarshalAlert(a model.Alert) ([]byte, error) {
	return json.Marshal(a)
}
