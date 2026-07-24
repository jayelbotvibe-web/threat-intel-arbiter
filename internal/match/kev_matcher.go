package match

import (
	"strings"
	"sync"

	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/model"
)

// KEVMatcher checks whether any CVE in the event appears in the
// CISA Known Exploited Vulnerabilities catalog.
// A KEV match is a strong signal of active exploitation.
//
// The catalog is not static: the KEV poller calls Replace on every successful
// fetch, so the matcher stays in sync with the live CISA feed rather than a
// hardcoded list. Replace and Match are safe to call concurrently.
type KEVMatcher struct {
	mu  sync.RWMutex
	kev map[string]bool // CVE IDs, normalized to upper-case
}

// NewKEVMatcher creates a KEVMatcher seeded with the given KEV CVE IDs.
// Pass nil to start empty and let the KEV poller populate it via Replace.
func NewKEVMatcher(kevCVEs []string) *KEVMatcher {
	m := &KEVMatcher{kev: make(map[string]bool)}
	m.Replace(kevCVEs)
	return m
}

// Replace atomically swaps the catalog contents with a normalized copy of
// kevCVEs. Called by the KEV poller after each fetch of the live catalog.
func (m *KEVMatcher) Replace(kevCVEs []string) {
	set := make(map[string]bool, len(kevCVEs))
	for _, cve := range kevCVEs {
		if id := normalizeCVE(cve); id != "" {
			set[id] = true
		}
	}
	m.mu.Lock()
	m.kev = set
	m.mu.Unlock()
}

func normalizeCVE(cve string) string {
	return strings.ToUpper(strings.TrimSpace(cve))
}

// Name returns the matcher name.
func (m *KEVMatcher) Name() string { return "KEVMatcher" }

// Match checks if any event CVE is in the KEV catalog.
func (m *KEVMatcher) Match(event model.ThreatEvent, org model.OrgContext) []model.Match {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var matches []model.Match
	for _, cve := range event.CVEs {
		if m.kev[normalizeCVE(cve)] {
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
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.kev[normalizeCVE(cve)]
}

// Count returns the number of CVEs in the KEV catalog.
func (m *KEVMatcher) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.kev)
}
