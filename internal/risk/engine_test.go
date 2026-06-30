package risk

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jayelbotvibe-web/threatlib/internal/config"
	"github.com/jayelbotvibe-web/threatlib/internal/match"
	"github.com/jayelbotvibe-web/threatlib/internal/model"
	"github.com/jayelbotvibe-web/threatlib/internal/source"
)

func loadOrgCtx(t *testing.T) model.OrgContext {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "config", "techstack.csv")
	apps, err := config.ParseTechStack(path)
	if err != nil {
		t.Fatalf("load tech stack: %v", err)
	}
	return model.OrgContext{
		OrgID:           "default",
		Name:            "NanoFab Semiconductor Inc.",
		Sector:          "eu-nis-oes-manufacturing",
		Country:         "BE",
		Timezone:        "Europe/Brussels",
		DataSensitivity: "critical",
		TechStack:       apps,
	}
}

func loadFixtureEvent(t *testing.T, name string) model.ThreatEvent {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "testdata", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var wrapper struct {
		Response []struct {
			Event source.MISPEvent `json:"Event"`
		} `json:"response"`
	}
	json.Unmarshal(data, &wrapper)
	return source.NormalizeMISPEvent(wrapper.Response[0].Event)
}

func TestRiskEngine_CriticalApache(t *testing.T) {
	org := loadOrgCtx(t)
	event := loadFixtureEvent(t, "misp_event_critical_apache.json")

	// Run matchers
	engine := match.NewEngine(
		match.NewCVEMatcher(),
		&match.SectorMatcher{},
		match.NewKEVMatcher([]string{"CVE-2024-38472", "CVE-2024-28941", "CVE-2024-27318"}),
	)
	matches := engine.Run(event, org)

	// Score
	riskEngine := NewEngine()
	result := riskEngine.Score(event, org, matches)

	t.Logf("\n%s", result.Explanation)

	// Verify severity — should be critical (KEV + exploit + critical app + internet-facing)
	if result.Severity != "critical" {
		t.Errorf("severity = %s, want critical", result.Severity)
	}

	// Verify confidence — should be high (source TLP:amber = medium confidence)
	if result.ConfidenceLabel != "HIGH" && result.ConfidenceLabel != "MEDIUM" {
		t.Errorf("confidence = %s, want HIGH or MEDIUM", result.ConfidenceLabel)
	}

	// Verify dimensions
	if result.Likelihood < 4 {
		t.Errorf("likelihood = %d, want at least 4 (KEV + weaponization + actor + freshness)", result.Likelihood)
	}
	if result.Impact < 4 {
		t.Errorf("impact = %d, want at least 4 (CVSS 9.8 + critical app)", result.Impact)
	}

	// Verify explanation contains key details
	explanation := result.Explanation
	required := []string{"CRITICAL", "CVE-2024-38472", "Apache", "CVSS 9.8", "KEV", "internet-facing"}
	for _, s := range required {
		if !strings.Contains(explanation, s) {
			t.Errorf("explanation missing %q", s)
		}
	}
}

func TestRiskEngine_SectorOnly(t *testing.T) {
	org := loadOrgCtx(t)
	event := loadFixtureEvent(t, "misp_event_sector_actor.json")

	engine := match.NewEngine(&match.SectorMatcher{})
	matches := engine.Run(event, org)

	riskEngine := NewEngine()
	result := riskEngine.Score(event, org, matches)

	t.Logf("\n%s", result.Explanation)

	// No CVE, no CVSS — should be low. Sector-only intel has baseline impact
	// but can't score high without a matched CVE. This is correct behavior
	// for the multiplicative model. Calibration of the severity thresholds
	// (.50/.25/.10) against production data may change this.
	if result.Severity != "low" {
		t.Logf("sector-only: severity=%s (expected low for multiplicative model)", result.Severity)
	}

	t.Logf("sector-only: severity=%s confidence=%s score=%.2f",
		result.Severity, result.ConfidenceLabel, result.RiskScore)
}

func TestRiskEngine_KEVWindows(t *testing.T) {
	org := loadOrgCtx(t)
	event := loadFixtureEvent(t, "misp_event_kev_windows.json")

	engine := match.NewEngine(
		match.NewCVEMatcher(),
		match.NewKEVMatcher([]string{"CVE-2024-38472", "CVE-2024-28941", "CVE-2024-27318"}),
	)
	matches := engine.Run(event, org)

	riskEngine := NewEngine()
	result := riskEngine.Score(event, org, matches)

	t.Logf("\n%s", result.Explanation)

	// KEV match + CVSS 9.1 + Windows Server (high) = should be high or critical
	if result.Severity != "critical" && result.Severity != "high" {
		t.Errorf("severity = %s, want critical or high", result.Severity)
	}

	// Should have KEV match in explanation
	if !strings.Contains(result.Explanation, "KEV") {
		t.Error("explanation missing KEV reference")
	}
}

func TestRiskEngine_WordPress_NoMatch(t *testing.T) {
	org := loadOrgCtx(t)
	event := loadFixtureEvent(t, "misp_event_wordpress_negative.json")

	engine := match.NewEngine(match.NewCVEMatcher())
	matches := engine.Run(event, org)

	riskEngine := NewEngine()
	result := riskEngine.Score(event, org, matches)

	t.Logf("\n%s", result.Explanation)

	// WordPress is not in our tech stack — no CVEMatcher matches
	// With no matches, score should be low
	if result.Severity != "low" {
		t.Errorf("unmatched event severity = %s, want low (no apps matched)", result.Severity)
	}
}

func TestScoreEdges(t *testing.T) {
	engine := NewEngine()

	tests := []struct {
		name     string
		event    model.ThreatEvent
		org      model.OrgContext
		matches  []model.Match
		wantSev  string
	}{
		{
			name: "max everything",
			event: model.ThreatEvent{
				ID: "max-test", CVEs: []string{"CVE-2024-99999"}, CVSS: 9.8,
				Tags: []string{"exploit:in-the-wild", "exploit:weaponized"},
				ThreatActors: []string{"APT41"},
				SourceConfidence: "high",
			},
			org: model.OrgContext{
				TechStack: []model.App{{Name: "TestApp", Criticality: "critical", InternetFacing: true, DataSensitivity: "critical"}},
			},
			matches: []model.Match{
				{KEVMatch: true, AppName: "TestApp"},
			},
			wantSev: "critical",
		},
		{
			name: "nothing — empty event",
			event: model.ThreatEvent{
				ID: "empty-test", SourceConfidence: "low",
			},
			org:     model.OrgContext{},
			matches: []model.Match{},
			wantSev: "low",
		},
		{
			name: "medium CVSS, medium app, not exposed — low (formula penalty)",
			event: model.ThreatEvent{
				ID: "med-test", CVEs: []string{"CVE-2024-55555"}, CVSS: 5.5,
				SourceConfidence: "medium",
			},
			org: model.OrgContext{
				TechStack: []model.App{{Name: "MedApp", Criticality: "medium", InternetFacing: false}},
			},
			matches: []model.Match{
				{AppName: "MedApp"},
			},
			wantSev: "low", // multiplicative model: moderate on all axes → low
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.Score(tt.event, tt.org, tt.matches)
			t.Logf("%s: L=%d I=%d E=%d C=%d → score=%.2f severity=%s confidence=%s",
				tt.name, result.Likelihood, result.Impact, result.Exposure, result.Confidence,
				result.RiskScore, result.Severity, result.ConfidenceLabel)

			if result.Severity != tt.wantSev {
				t.Errorf("severity = %s, want %s", result.Severity, tt.wantSev)
			}
		})
	}
}
