package config

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jayelbotvibe-web/threatlib/internal/model"
)

func TestParseTechStack(t *testing.T) {
	csv := `name,version,vendor,category,criticality,owner_team,internet_facing,hosts,data_sensitivity
"Apache HTTP Server","2.4.57","Apache","Web Server","critical","web-ops","true","lb-01,lb-02","low"
"PostgreSQL","15.3","PostgreSQL","Database","high","data-eng","false","db-primary","high"
"SAP NetWeaver","7.5 SPS22","SAP","ERP","critical","sap-team","false","sap-app-01","high"
"Confluence","8.5","Atlassian","Wiki","low","corp-it","false","wiki-01","low"
`

	apps, err := ParseTechStackReader(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("ParseTechStackReader: %v", err)
	}

	if len(apps) != 4 {
		t.Fatalf("expected 4 apps, got %d", len(apps))
	}

	// Check first app
	apache := apps[0]
	if apache.Name != "Apache HTTP Server" {
		t.Errorf("app[0].Name = %q, want Apache HTTP Server", apache.Name)
	}
	if apache.Version != "2.4.57" {
		t.Errorf("app[0].Version = %q", apache.Version)
	}
	if apache.Criticality != "critical" {
		t.Errorf("app[0].Criticality = %q, want critical", apache.Criticality)
	}
	if !apache.InternetFacing {
		t.Error("app[0].InternetFacing should be true")
	}

	// Check SAP version (non-semver)
	sap := apps[2]
	if sap.Version != "7.5 SPS22" {
		t.Errorf("SAP version = %q, want 7.5 SPS22", sap.Version)
	}
	if sap.Criticality != "critical" {
		t.Errorf("SAP criticality = %q, want critical", sap.Criticality)
	}

	// Check data sensitivity
	pg := apps[1]
	if pg.DataSensitivity != "high" {
		t.Errorf("PostgreSQL data_sensitivity = %q, want high", pg.DataSensitivity)
	}

	t.Logf("parsed %d apps", len(apps))
	for _, a := range apps {
		t.Logf("  %s (%s) — %s — internet=%v data=%s",
			a.Name, a.Vendor, a.Criticality, a.InternetFacing, a.DataSensitivity)
	}
}

func TestComputeDelta(t *testing.T) {
	existing := []model.App{
		{Name: "Apache HTTP Server", Vendor: "Apache", Criticality: "high", InternetFacing: true},
		{Name: "PostgreSQL", Vendor: "PostgreSQL", Criticality: "high", InternetFacing: false},
		{Name: "nginx", Vendor: "Nginx", Criticality: "medium", InternetFacing: true},
	}

	newApps := []model.App{
		{Name: "Apache HTTP Server", Vendor: "Apache", Criticality: "critical", InternetFacing: true}, // modified
		{Name: "PostgreSQL", Vendor: "PostgreSQL", Criticality: "high", InternetFacing: false},          // unchanged
		// nginx removed
		{Name: "SAP NetWeaver", Vendor: "SAP", Criticality: "critical", InternetFacing: false}, // added
	}

	added, removed, modified := ComputeDelta(newApps, existing)

	if len(added) != 1 || added[0].Name != "SAP NetWeaver" {
		t.Errorf("added = %d items, expected SAP NetWeaver", len(added))
	}
	if len(removed) != 1 || removed[0].Name != "nginx" {
		t.Errorf("removed = %d items, expected nginx", len(removed))
	}
	if len(modified) != 1 || modified[0].Name != "Apache HTTP Server" {
		t.Errorf("modified = %d items, expected Apache (criticality changed)", len(modified))
	}

	t.Logf("delta: +%d added, -%d removed, ~%d modified", len(added), len(removed), len(modified))
}

func TestComputeDelta_NoChanges(t *testing.T) {
	apps := []model.App{
		{Name: "Apache", Vendor: "Apache", Criticality: "critical"},
	}

	added, removed, modified := ComputeDelta(apps, apps)
	if len(added) != 0 || len(removed) != 0 || len(modified) != 0 {
		t.Error("expected no delta when stacks are identical")
	}
}

func TestParseRealTechStack(t *testing.T) {
	// Parse the actual semiconductor tech stack CSV
	// Use runtime.Caller to find the correct path regardless of test binary location
	_, thisFile, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "config", "techstack.csv")

	apps, err := ParseTechStack(path)
	if err != nil {
		t.Fatalf("ParseTechStack: %v", err)
	}

	if len(apps) == 0 {
		t.Fatal("expected apps, got none")
	}

	t.Logf("loaded %d apps from semiconductor tech stack", len(apps))

	// Verify some key semiconductor-specific apps
	found := map[string]bool{}
	for _, app := range apps {
		found[app.Name] = true
	}

	criticalApps := []string{
		"Red Hat Enterprise Linux",
		"SAP S/4HANA",
		"Cadence Virtuoso",
		"Applied Materials E3",
		"Palo Alto Networks PAN-OS",
		"Splunk Enterprise",
		"HashiCorp Vault",
	}
	for _, name := range criticalApps {
		if !found[name] {
			t.Errorf("missing critical app: %s", name)
		}
	}

	// Verify criticality counts
	crit, high, med, low := 0, 0, 0, 0
	for _, app := range apps {
		switch app.Criticality {
		case "critical":
			crit++
		case "high":
			high++
		case "medium":
			med++
		case "low":
			low++
		}
	}
	t.Logf("criticality: %d critical, %d high, %d medium, %d low", crit, high, med, low)
	if crit < 10 {
		t.Errorf("expected at least 10 critical apps in semiconductor stack, got %d", crit)
	}
}
