package match

import (
	"testing"

	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/model"
)

// TestKEVMatcher_ReplaceFromLiveCatalog guards the fix that wires the matcher
// to the live KEV poller: a matcher created empty must start matching nothing,
// then match once Replace populates it from the catalog.
func TestKEVMatcher_ReplaceFromLiveCatalog(t *testing.T) {
	m := NewKEVMatcher(nil)
	if m.Count() != 0 {
		t.Fatalf("new empty matcher Count = %d, want 0", m.Count())
	}

	event := model.ThreatEvent{CVEs: []string{"CVE-2024-3400"}}
	if got := m.Match(event, model.OrgContext{}); len(got) != 0 {
		t.Fatalf("empty matcher matched %d, want 0", len(got))
	}

	// Poller pushes the live catalog.
	m.Replace([]string{"CVE-2024-3400", "CVE-2024-1709"})
	if m.Count() != 2 {
		t.Fatalf("after Replace Count = %d, want 2", m.Count())
	}
	got := m.Match(event, model.OrgContext{})
	if len(got) != 1 || !got[0].KEVMatch {
		t.Fatalf("after Replace, Match = %+v, want 1 KEV match", got)
	}

	// A later catalog that no longer contains the CVE must stop matching it.
	m.Replace([]string{"CVE-2023-0001"})
	if got := m.Match(event, model.OrgContext{}); len(got) != 0 {
		t.Fatalf("after catalog rotation, matched %d, want 0", len(got))
	}
}

// TestKEVMatcher_CaseInsensitive verifies CVE IDs are normalized so catalog
// and event casing/whitespace differences don't cause missed exploited CVEs.
func TestKEVMatcher_CaseInsensitive(t *testing.T) {
	m := NewKEVMatcher([]string{" cve-2024-3400 "})
	event := model.ThreatEvent{CVEs: []string{"CVE-2024-3400"}}
	if got := m.Match(event, model.OrgContext{}); len(got) != 1 {
		t.Fatalf("case-insensitive match failed: got %d, want 1", len(got))
	}
	if !m.Has("cve-2024-3400") {
		t.Errorf("Has(lowercase) = false, want true")
	}
}
