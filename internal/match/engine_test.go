package match

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jayelbotvibe-web/threatlib/internal/config"
	"github.com/jayelbotvibe-web/threatlib/internal/model"
	"github.com/jayelbotvibe-web/threatlib/internal/source"
)

// orgCtx is the test organisation context (semiconductor fab).
var orgCtx = model.OrgContext{
	OrgID:           "default",
	Name:            "NanoFab Semiconductor Inc.",
	Sector:          "eu-nis-oes-manufacturing",
	Country:         "BE",
	Timezone:        "Europe/Brussels",
	DataSensitivity: "critical",
}

// loadTestTechStack loads the semiconductor tech stack for testing.
func loadTestTechStack(t *testing.T) []model.App {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "config", "techstack.csv")
	apps, err := config.ParseTechStack(path)
	if err != nil {
		t.Fatalf("load tech stack: %v", err)
	}
	orgCtx.TechStack = apps
	return apps
}

// loadFixture loads a MISP fixture and returns the first event.
func loadFixture(t *testing.T, name string) source.MISPEvent {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "testdata", name)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}

	var wrapper struct {
		Response []struct {
			Event source.MISPEvent `json:"Event"`
		} `json:"response"`
	}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		t.Fatalf("unmarshal %s: %v", name, err)
	}
	if len(wrapper.Response) == 0 {
		t.Fatalf("no events in fixture %s", name)
	}
	return wrapper.Response[0].Event
}

func TestCVEMatcher(t *testing.T) {
	apps := loadTestTechStack(t)
	m := NewCVEMatcher()

	tests := []struct {
		name     string
		fixture  string
		wantMin  int // minimum expected matches
		wantApps []string
	}{
		{
			name:    "Apache CVE matches Apache HTTP Server",
			fixture: "misp_event_critical_apache.json",
			wantMin: 1,
			wantApps: []string{"Apache HTTP Server"},
		},
		{
			name:    "Windows CVE matches Windows Server",
			fixture: "misp_event_kev_windows.json",
			wantMin: 1,
			wantApps: []string{"Windows Server"},
		},
		{
			name:    "SAP CVE matches SAP S/4HANA",
			fixture: "misp_event_sap_critical.json",
			wantMin: 1,
			wantApps: []string{"SAP S/4HANA"},
		},
		{
			name:    "WordPress CVE — no match in semiconductor stack",
			fixture: "misp_event_wordpress_negative.json",
			wantMin: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := loadFixture(t, tt.fixture)
			event := source.NormalizeMISPEvent(raw)

			matches := m.Match(event, orgCtx)
			t.Logf("%s: %d CVEs in event, %d matches", tt.fixture, len(event.CVEs), len(matches))

			if len(matches) < tt.wantMin {
				t.Errorf("expected at least %d matches, got %d", tt.wantMin, len(matches))
			}

			for _, wantApp := range tt.wantApps {
				found := false
				for _, match := range matches {
					if match.AppName == wantApp {
						found = true
						t.Logf("  ✓ matched app: %s (confidence: %s)", match.AppName, match.MatchConfidence)
					}
				}
				if !found {
					t.Errorf("expected match for app %q, not found", wantApp)
				}
			}

			// Verify match confidence is set
			for _, match := range matches {
				if match.MatchConfidence == "" {
					t.Errorf("match for %s has empty confidence", match.AppName)
				}
			}
		})
	}

	_ = apps
}

func TestSectorMatcher(t *testing.T) {
	loadTestTechStack(t)
	m := &SectorMatcher{}

	tests := []struct {
		name        string
		fixture     string
		wantSector  bool
	}{
		{
			name:       "Apache event tagged manufacturing — sector match",
			fixture:    "misp_event_critical_apache.json",
			wantSector: true, // tagged eu-nis-oes:eu-nis-oes-manufacturing
		},
		{
			name:       "APT41 campaign targeting manufacturing — sector match",
			fixture:    "misp_event_sector_actor.json",
			wantSector: true, // tagged eu-nis-oes:eu-nis-oes-manufacturing + targeted-threat-index:targets-manufacturing
		},
		{
			name:       "KEV Windows event — no sector tag",
			fixture:    "misp_event_kev_windows.json",
			wantSector: false, // only TLP and exploit tags
		},
		{
			name:       "SAP event tagged manufacturing — sector match",
			fixture:    "misp_event_sap_critical.json",
			wantSector: true, // tagged eu-nis-oes:eu-nis-oes-manufacturing
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := loadFixture(t, tt.fixture)
			event := source.NormalizeMISPEvent(raw)
			matches := m.Match(event, orgCtx)

			hasSectorMatch := false
			for _, match := range matches {
				if match.SectorMatch {
					hasSectorMatch = true
					t.Logf("  ✓ sector match: %s", match.Details)
				}
			}

			if hasSectorMatch != tt.wantSector {
				t.Errorf("sector match = %v, want %v (tags: %v, org sector: %s)",
					hasSectorMatch, tt.wantSector, event.Tags, orgCtx.Sector)
			}
		})
	}
}

func TestKEVMatcher(t *testing.T) {
	m := NewKEVMatcher([]string{
		"CVE-2024-38472", // Apache — in our KEV fixture
		"CVE-2024-28941", // Windows — in our KEV fixture
		"CVE-2024-27318", // PostgreSQL — in our KEV fixture
	})

	if m.Count() != 3 {
		t.Errorf("KEV count = %d, want 3", m.Count())
	}

	tests := []struct {
		name     string
		fixture  string
		wantKEV  bool
		wantCVE  string
	}{
		{
			name:    "Apache CVE is in KEV",
			fixture: "misp_event_critical_apache.json",
			wantKEV: true,
			wantCVE: "CVE-2024-38472",
		},
		{
			name:    "Windows CVE is in KEV",
			fixture: "misp_event_kev_windows.json",
			wantKEV: true,
			wantCVE: "CVE-2024-28941",
		},
		{
			name:    "SAP CVE is NOT in KEV",
			fixture: "misp_event_sap_critical.json",
			wantKEV: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := loadFixture(t, tt.fixture)
			event := source.NormalizeMISPEvent(raw)
			matches := m.Match(event, orgCtx)

			hasKEV := false
			for _, match := range matches {
				if match.KEVMatch {
					hasKEV = true
					t.Logf("  ✓ KEV match: %s", match.Details)
				}
			}

			if hasKEV != tt.wantKEV {
				t.Errorf("KEV match = %v, want %v", hasKEV, tt.wantKEV)
			}

			if tt.wantKEV && !m.Has(tt.wantCVE) {
				t.Errorf("Has(%s) = false, want true", tt.wantCVE)
			}
		})
	}
}

func TestEngine_RunAllMatchers(t *testing.T) {
	apps := loadTestTechStack(t)
	_ = apps

	engine := NewEngine(
		NewCVEMatcher(),
		&SectorMatcher{},
		NewKEVMatcher([]string{"CVE-2024-38472", "CVE-2024-28941", "CVE-2024-27318"}),
	)

	tests := []struct {
		name    string
		fixture string
		wantMin int // minimum total matches across all matchers
		desc    string
	}{
		{
			name:    "Apache event — CVEMatcher + SectorMatcher + KEVMatcher all fire",
			fixture: "misp_event_critical_apache.json",
			wantMin: 3,
			desc:    "All 3 matchers should match",
		},
		{
			name:    "Sector-only event — only SectorMatcher fires",
			fixture: "misp_event_sector_actor.json",
			wantMin: 1,
			desc:    "No CVE, sector + actor only",
		},
		{
			name:    "WordPress event — no matchers fire",
			fixture: "misp_event_wordpress_negative.json",
			wantMin: 0,
			desc:    "No CVEs in stack, no sector tags",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := loadFixture(t, tt.fixture)
			event := source.NormalizeMISPEvent(raw)
			matches := engine.Run(event, orgCtx)

			t.Logf("%s: %d total matches — %s", tt.fixture, len(matches), tt.desc)
			for _, m := range matches {
				t.Logf("  [%s] %s", m.Matcher, m.Details)
			}

			if len(matches) < tt.wantMin {
				t.Errorf("expected at least %d matches, got %d", tt.wantMin, len(matches))
			}
		})
	}

	names := engine.MatcherNames()
	t.Logf("registered matchers: %s", strings.Join(names, ", "))
	if len(names) != 3 {
		t.Errorf("expected 3 matchers, got %d: %v", len(names), names)
	}
}

func TestVendorAliasNormalization(t *testing.T) {
	m := NewCVEMatcher()

	tests := []struct {
		input    string
		expected string
	}{
		{"Apache Software Foundation", "apache"},
		{"The Apache Software Foundation", "apache"},
		{"Microsoft Corporation", "microsoft"},
		{"Microsoft Corp", "microsoft"},
		{"Red Hat", "red hat"},
		{"RedHat", "red hat"},
		{"SAP AG", "sap"},
		{"SAP SE", "sap"},
		{"Siemens AG", "siemens"},
		{"Canonical", "canonical"},
		{"UnknownVendor", "unknownvendor"}, // passes through unchanged (lowercased)
		{"  SAP SE  ", "sap"},              // trimmed
	}

	for _, tt := range tests {
		got := m.normalizeVendor(tt.input)
		if got != tt.expected {
			t.Errorf("normalizeVendor(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
