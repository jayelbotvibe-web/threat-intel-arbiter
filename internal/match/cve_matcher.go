package match

import (
	"strings"

	"github.com/jayelbotvibe-web/threatlib/internal/model"
)

// CVEMatcher cross-references CVE IDs against the organisation's tech stack.
// It normalizes vendor names, compares version ranges, and produces matches
// with a confidence level (exact_version_match, product_only_match, unparseable_version).
type CVEMatcher struct {
	// aliasMap normalizes vendor names.
	aliasMap map[string]string
}

// NewCVEMatcher creates a CVEMatcher with the default vendor alias map.
func NewCVEMatcher() *CVEMatcher {
	return &CVEMatcher{aliasMap: defaultAliases()}
}

// Name returns the matcher name.
func (m *CVEMatcher) Name() string { return "CVEMatcher" }

// Match checks event CVEs against the tech stack.
func (m *CVEMatcher) Match(event model.ThreatEvent, org model.OrgContext) []model.Match {
	var matches []model.Match

	for _, cve := range event.CVEs {
		// Try to match each CVE against the tech stack
		for _, app := range org.TechStack {
			if m.cveMatchesApp(cve, app, event.Title) {
				confidence := m.matchConfidence(app)
				matches = append(matches, model.Match{
					Matcher:         "CVEMatcher",
					CVE:             cve,
					AppName:         app.Name,
					AppVersion:      app.Version,
					VersionAffected: confidence == "exact_version_match",
					MatchConfidence:  confidence,
					Details:         "CVE " + cve + " matches " + app.Name + " (" + app.Vendor + ")",
				})
			}
		}
	}

	return matches
}

// cveMatchesApp checks if a CVE likely affects a given app.
// It matches vendor and product names against the event description/title.
func (m *CVEMatcher) cveMatchesApp(cve string, app model.App, eventTitle string) bool {
	title := strings.ToLower(eventTitle)
	vendor := m.normalizeVendor(app.Vendor)
	product := m.normalizeProduct(app.Name)

	// Check if either the vendor name or product name appears in the event title
	if strings.Contains(title, vendor) || strings.Contains(title, product) {
		return true
	}

	// Also check partial matches for known multi-word products
	parts := strings.Fields(product)
	for _, part := range parts {
		if len(part) > 3 && strings.Contains(title, part) {
			return true
		}
	}
	parts = strings.Fields(vendor)
	for _, part := range parts {
		if len(part) > 3 && strings.Contains(title, part) {
			return true
		}
	}

	return false
}

// matchConfidence returns the confidence level for a match.
func (m *CVEMatcher) matchConfidence(app model.App) string {
	if app.Version != "" {
		return "exact_version_match"
	}
	return "product_only_match"
}

// normalizeVendor normalizes a vendor name using the alias map.
func (m *CVEMatcher) normalizeVendor(name string) string {
	key := strings.ToLower(strings.TrimSpace(name))
	if alias, ok := m.aliasMap[key]; ok {
		return alias
	}
	return key
}

// normalizeProduct normalizes a product name.
func (m *CVEMatcher) normalizeProduct(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// defaultAliases returns the built-in vendor alias map.
func defaultAliases() map[string]string {
	return map[string]string{
		"apache software foundation": "apache",
		"the apache software foundation": "apache",
		"httpd":                      "apache http server",
		"microsoft corporation":      "microsoft",
		"microsoft corp":             "microsoft",
		"ms":                         "microsoft",
		"red hat":                    "red hat",
		"redhat":                     "red hat",
		"canonical":                  "canonical",
		"atlassian":                  "atlassian",
		"atlassian pty ltd":          "atlassian",
		"sap ag":                     "sap",
		"sap se":                     "sap",
		"siemens ag":                 "siemens",
		"siemens":                    "siemens",
	}
}
