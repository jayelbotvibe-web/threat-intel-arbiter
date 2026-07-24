package source

import "testing"

// TestParseCPE guards the MISP AffectedProducts fix: CPE 2.2/2.3 strings must
// yield vendor/product/version so the CVE matcher can version-compare.
func TestParseCPE(t *testing.T) {
	tests := []struct {
		name                     string
		cpe                      string
		ok                       bool
		vendor, product, version string
	}{
		{"cpe 2.3 with version", "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", true, "apache", "http server", "2.4.49"},
		{"cpe 2.2 with version", "cpe:/a:microsoft:windows_server:2019", true, "microsoft", "windows server", "2019"},
		{"cpe 2.3 wildcard version", "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", true, "apache", "log4j", ""},
		{"not a cpe", "just-a-string", false, "", "", ""},
		{"too few fields", "cpe:2.3:a", false, "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ap, ok := parseCPE(tt.cpe)
			if ok != tt.ok {
				t.Fatalf("parseCPE(%q) ok = %v, want %v", tt.cpe, ok, tt.ok)
			}
			if !ok {
				return
			}
			if ap.Vendor != tt.vendor || ap.Product != tt.product {
				t.Errorf("got vendor=%q product=%q, want vendor=%q product=%q", ap.Vendor, ap.Product, tt.vendor, tt.product)
			}
			if ap.VersionStart != tt.version || ap.VersionEnd != tt.version {
				t.Errorf("got version=%q/%q, want %q", ap.VersionStart, ap.VersionEnd, tt.version)
			}
		})
	}
}

// TestNormalizeMISPEvent_CPEAffectedProducts guards that a MISP event carrying a
// CPE attribute populates AffectedProducts (previously always empty).
func TestNormalizeMISPEvent_CPEAffectedProducts(t *testing.T) {
	raw := MISPEvent{
		UUID: "evt-1",
		Info: "Apache HTTP Server RCE",
		Attributes: []MISPAttribute{
			{Type: "vulnerability", Value: "CVE-2024-1234"},
			{Type: "cpe", Value: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
		},
	}
	ev := NormalizeMISPEvent(raw)
	if len(ev.AffectedProducts) != 1 {
		t.Fatalf("AffectedProducts = %d, want 1 (from CPE attribute)", len(ev.AffectedProducts))
	}
	ap := ev.AffectedProducts[0]
	if ap.Vendor != "apache" || ap.Product != "http server" || ap.VersionStart != "2.4.49" {
		t.Errorf("AffectedProduct = %+v, want apache/http server/2.4.49", ap)
	}
}
