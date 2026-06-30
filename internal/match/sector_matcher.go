package match

import (
	"strings"

	"github.com/jayelbotvibe-web/threatlib/internal/model"
)

// SectorMatcher checks event tags against sector taxonomies and
// cross-references with the organisation's sector profile.
// It works on events with and without CVEs — actor reports, campaign
// intelligence, and sector-targeted tags all match here.
type SectorMatcher struct{}

// Name returns the matcher name.
func (m *SectorMatcher) Name() string { return "SectorMatcher" }

// Match checks event tags and threat actors against org sector.
func (m *SectorMatcher) Match(event model.ThreatEvent, org model.OrgContext) []model.Match {
	var matches []model.Match

	// Normalize org sector for comparison
	orgSector := strings.ToLower(org.Sector)

	for _, tag := range event.Tags {
		tagLower := strings.ToLower(tag)

		// Check sector taxonomies
		sectorMatched := false
		for _, prefix := range sectorTaxonomies {
			if strings.HasPrefix(tagLower, prefix) && strings.Contains(tagLower, orgSector) {
				sectorMatched = true
				break
			}
		}

		if sectorMatched {
			matches = append(matches, model.Match{
				Matcher:     "SectorMatcher",
				SectorMatch: true,
				Details:     "Event tagged " + tag + " matches org sector " + org.Sector,
			})
			break // One sector match is sufficient
		}
	}

	// Check threat actors — if event mentions an actor and sector matches, boost
	if len(event.ThreatActors) > 0 && len(matches) > 0 {
		// Actor + sector match is stronger evidence
		matches[0].Details += " — threat actor: " + strings.Join(event.ThreatActors, ", ")
	}

	return matches
}

// sectorTaxonomies lists the MISP taxonomy namespaces used for sector matching.
var sectorTaxonomies = []string{
	"eu-nis-oes",
	"eu-nis-sector-and-subsectors",
	"dhs-ciip-sectors",
	"nis2",
	"targeted-threat-index:targets-",
}
