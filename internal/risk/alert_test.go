package risk

import (
	"testing"
	"time"

	"github.com/jayelbotvibe-web/threatlib/internal/model"
)

func TestDedupKey(t *testing.T) {
	event1 := model.ThreatEvent{
		ID: "ev-001", Source: "misp", Title: "Apache CVE",
	}
	result1 := ScoreResult{Severity: "critical", RiskScore: 0.67}

	event2 := model.ThreatEvent{
		ID: "ev-001", Source: "misp", Title: "Apache CVE",
	}
	result2 := ScoreResult{Severity: "critical", RiskScore: 0.67}

	// Same event + same result = same hash
	k1 := DedupKey(event1, result1)
	k2 := DedupKey(event2, result2)
	if k1 != k2 {
		t.Errorf("same input should produce same hash: %s != %s", k1, k2)
	}

	// Different event = different hash
	event3 := model.ThreatEvent{
		ID: "ev-002", Source: "misp", Title: "Windows CVE",
	}
	k3 := DedupKey(event3, result1)
	if k1 == k3 {
		t.Error("different events should produce different hashes")
	}

	t.Logf("dedup hash: %s", k1)
}

func TestNewAlert(t *testing.T) {
	event := model.ThreatEvent{
		ID: "test-alert-001", Source: "misp", Title: "Test CVE-2024-99999 — Critical RCE",
	}
	result := ScoreResult{
		Severity: "critical", ConfidenceLabel: "HIGH",
		RiskScore: 0.75, Explanation: "test explanation",
	}
	matches := []model.Match{
		{AppName: "Apache HTTP Server", Matcher: "CVEMatcher"},
		{AppName: "Windows Server", Matcher: "CVEMatcher"},
	}

	alert := NewAlert(event, result, matches)

	if alert.EventID != "test-alert-001" {
		t.Errorf("EventID = %s", alert.EventID)
	}
	if alert.Severity != "critical" {
		t.Errorf("Severity = %s", alert.Severity)
	}
	if alert.Confidence != "HIGH" {
		t.Errorf("Confidence = %s", alert.Confidence)
	}
	if alert.Status != "new" {
		t.Errorf("Status = %s", alert.Status)
	}
	if len(alert.MatchedApps) != 2 {
		t.Errorf("MatchedApps = %d, want 2", len(alert.MatchedApps))
	}

	t.Logf("alert: id=%s severity=%s confidence=%s apps=%v",
		alert.ID, alert.Severity, alert.Confidence, alert.MatchedApps)
}

func TestAlert_DedupSuppression(t *testing.T) {
	// Same event scored twice should produce same alert ID (hash)
	event := model.ThreatEvent{
		ID: "dedup-test", Source: "misp", Title: "Duplicate CVE Test",
	}
	result := ScoreResult{Severity: "high", RiskScore: 0.35}

	alert1 := NewAlert(event, result, nil)
	alert2 := NewAlert(event, result, nil)

	if alert1.ID != alert2.ID {
		t.Errorf("same event+score should generate same dedup key: %s != %s", alert1.ID, alert2.ID)
	}

	// Different severity should produce different hash
	result2 := ScoreResult{Severity: "critical", RiskScore: 0.65}
	alert3 := NewAlert(event, result2, nil)

	if alert1.ID == alert3.ID {
		t.Error("different severity should produce different dedup key")
	}

	t.Logf("dedup: %s == %s (same), != %s (different severity)", alert1.ID, alert2.ID, alert3.ID)
}

func TestMarshalAlert(t *testing.T) {
	alert := model.Alert{
		ID: "test-marshal", EventID: "ev-001", Severity: "critical",
		Confidence: "HIGH", Status: "new", MatchedApps: []string{"Apache"},
		CreatedAt: time.Now().Format(time.RFC3339),
	}

	data, err := MarshalAlert(alert)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if len(data) == 0 {
		t.Error("empty JSON output")
	}

	t.Logf("alert JSON: %s", string(data))
}
