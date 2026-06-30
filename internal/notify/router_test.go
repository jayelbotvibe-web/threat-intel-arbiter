package notify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jayelbotvibe-web/threatlib/internal/config"
	"github.com/jayelbotvibe-web/threatlib/internal/match"
	"github.com/jayelbotvibe-web/threatlib/internal/model"
	"github.com/jayelbotvibe-web/threatlib/internal/risk"
	"github.com/jayelbotvibe-web/threatlib/internal/source"
)

func loadOrgCtx(t *testing.T) model.OrgContext {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "config", "techstack.csv")
	apps, _ := config.ParseTechStack(path)
	return model.OrgContext{
		OrgID: "default", Name: "NanoFab Semiconductor Inc.",
		Sector: "eu-nis-oes-manufacturing", Country: "BE",
		DataSensitivity: "critical", TechStack: apps,
	}
}

func loadFixtureEvent(t *testing.T, name string) model.ThreatEvent {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "testdata", name)
	data, _ := os.ReadFile(path)
	var wrapper struct {
		Response []struct {
			Event source.MISPEvent `json:"Event"`
		} `json:"response"`
	}
	json.Unmarshal(data, &wrapper)
	return source.NormalizeMISPEvent(wrapper.Response[0].Event)
}

func TestFullPipeline_ConsoleOutput(t *testing.T) {
	org := loadOrgCtx(t)

	// Set up the full pipeline
	engine := match.NewEngine(
		match.NewCVEMatcher(),
		&match.SectorMatcher{},
		match.NewKEVMatcher([]string{"CVE-2024-38472", "CVE-2024-28941", "CVE-2024-27318"}),
	)
	riskEngine := risk.NewEngine()

	// Set up router with console notifier
	router := NewRouter([]Rule{
		{Severity: "critical", Confidence: []string{"high", "medium"}, Channels: []string{"console", "alerts-file"}, Format: "realtime"},
		{Severity: "critical", Confidence: []string{"low"}, Channels: []string{"console"}, Format: "realtime"},
		{Severity: "high", Confidence: []string{"high", "medium"}, Channels: []string{"console"}, Format: "realtime"},
		{Severity: "high", Confidence: []string{"low"}, Channels: []string{"console"}, Format: "daily_digest"},
		{Severity: "medium", Channels: []string{"console"}, Format: "weekly_digest"},
	})
	router.Register("console", NewConsoleNotifier("console"))
	router.Register("alerts-file", NewFileNotifier("alerts-file", filepath.Join(t.TempDir(), "alerts.txt")))

	// Feed all fixtures through the pipeline
	fixtures := []struct {
		name string
		desc string
	}{
		{"misp_event_critical_apache.json", "Apache CVE + KEV + exploit + sector"},
		{"misp_event_kev_windows.json", "Windows Server KEV CVE"},
		{"misp_event_sap_critical.json", "SAP NetWeaver CVE + sector tag"},
		{"misp_event_sector_actor.json", "APT41 campaign — sector only, no CVE"},
		{"misp_event_wordpress_negative.json", "WordPress — should not match our stack"},
		{"misp_event_modified_apache.json", "Apache CVE — MODIFIED with weaponized tag"},
	}

	t.Log("\n")
	t.Log("═══════════════════════════════════════════════════════════════")
	t.Log("  THREATLIB END-TO-END PIPELINE TEST")
	t.Log("  NanoFab Semiconductor Inc. — 31 apps tracked")
	t.Log("═══════════════════════════════════════════════════════════════")
	t.Log("\n")

	for _, f := range fixtures {
		event := loadFixtureEvent(t, f.name)
		t.Logf("── Processing: %s ──\n", f.desc)

		// Match
		matches := engine.Run(event, org)

		// Score
		result := riskEngine.Score(event, org, matches)

		// Create alert (dedup skipped for test)
		alert := risk.NewAlert(event, result, matches)

		// Route
		routed := router.Route(alert)

		t.Logf("  Result: %s · %s · routed to %v · %d matches\n",
			alert.Severity, alert.Confidence, routed, len(matches))
	}

	t.Log("\n═══ Pipeline complete ═══")
}
