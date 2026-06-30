package match

import (
	"github.com/jayelbotvibe-web/threatlib/internal/model"
)

// KEVMatcher checks whether any CVE in the event appears in the
// CISA Known Exploited Vulnerabilities catalog.
// A KEV match is a strong signal of active exploitation.
type KEVMatcher struct {
	// kev holds CVE IDs from the KEV catalog.
	kev map[string]bool
}

// NewKEVMatcher creates a KEVMatcher with the given KEV CVE IDs.
// The CVE IDs should be uppercase (CVE-YYYY-NNNNN).
func NewKEVMatcher(kevCVEs []string) *KEVMatcher {
	m := &KEVMatcher{kev: make(map[string]bool)}
	for _, cve := range kevCVEs {
		m.kev[cve] = true
	}
	return m
}

// Name returns the matcher name.
func (m *KEVMatcher) Name() string { return "KEVMatcher" }

// Match checks if any event CVE is in the KEV catalog.
func (m *KEVMatcher) Match(event model.ThreatEvent, org model.OrgContext) []model.Match {
	var matches []model.Match

	for _, cve := range event.CVEs {
		if m.kev[cve] {
			matches = append(matches, model.Match{
				Matcher:  "KEVMatcher",
				CVE:      cve,
				KEVMatch: true,
				Details:  "CVE " + cve + " is on the CISA Known Exploited Vulnerabilities list — actively exploited",
			})
		}
	}

	return matches
}

// Has returns true if the given CVE is in the KEV catalog.
func (m *KEVMatcher) Has(cve string) bool {
	return m.kev[cve]
}

// Count returns the number of CVEs in the KEV catalog.
func (m *KEVMatcher) Count() int {
	return len(m.kev)
}
