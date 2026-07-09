package match

import (
	"strings"

	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/match/version"
	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/model"
)

// CVEMatcher cross-references CVE IDs against the organisation's tech stack.
// It normalizes vendor names, compares version ranges, and produces matches
// with a confidence level (exact_version_match, product_only_match, weak_title_match).
type CVEMatcher struct {
	aliasMap        map[string]string
	productAliasMap map[string]string
}

// NewCVEMatcher creates a CVEMatcher with the default vendor alias map.
func NewCVEMatcher() *CVEMatcher {
	return &CVEMatcher{aliasMap: defaultAliases(), productAliasMap: defaultProductAliases()}
}

// Name returns the matcher name.
func (m *CVEMatcher) Name() string { return "CVEMatcher" }

// Match checks event CVEs against the tech stack.
func (m *CVEMatcher) Match(event model.ThreatEvent, org model.OrgContext) []model.Match {
	var matches []model.Match

	for _, cve := range event.CVEs {
		for _, app := range org.TechStack {
			if match := m.cveMatchesApp(cve, app, event); match != nil {
				matches = append(matches, *match)
			}
		}
	}

	return matches
}

// cveMatchesApp checks if a CVE likely affects a given app.
func (m *CVEMatcher) cveMatchesApp(cve string, app model.App, event model.ThreatEvent) *model.Match {
	vendor := m.normalizeVendor(app.Vendor)
	product := m.normalizeProduct(app.Name)

	// 1. Try structured matching via AffectedProducts first
	confidence, cveRange := m.matchViaAffectedProducts(event, vendor, product)

	// 2. If no structured match, fall back to title-keyword matching (weak)
	if confidence == "" {
		if m.matchViaTitle(event.Title, vendor, product) {
			confidence = "weak_title_match"
		}
	}
	if confidence == "" {
		return nil
	}

	// 3. If we have version range data, use real version comparison
	if cveRange != nil && app.Version != "" {
		inRange, label := version.InRange(app.Version, cveRange.VersionStart, cveRange.VersionEnd)
		if !inRange {
			// Version is outside the affected range — suppress
			return &model.Match{
				Matcher:        "CVEMatcher",
				CVE:            cve,
				AppName:        app.Name,
				AppVersion:     app.Version,
				MatchConfidence: "version_not_affected",
				Suppressed:     true,
				SuppressReason: "version_not_affected: " + app.Name + " " + app.Version + " outside affected range [" + cveRange.VersionStart + "," + cveRange.VersionEnd + "]",
				Details:        "CVE " + cve + " does not affect " + app.Name + " " + app.Version,
			}
		}
		confidence = label // "exact_version_match" or "product_only_match" from InRange
	}

	// 4. Determine if version is actually affected
	versionAffected := confidence == "exact_version_match"

	return &model.Match{
		Matcher:         "CVEMatcher",
		CVE:             cve,
		AppName:         app.Name,
		AppVersion:      app.Version,
		VersionAffected:  versionAffected,
		MatchConfidence:  confidence,
		Details:          "CVE " + cve + " matches " + app.Name + " (" + app.Vendor + ")",
	}
}

// matchViaAffectedProducts checks if the event's AffectedProducts list
// contains a product matching the given vendor/product. Returns confidence
// level and the matching AffectedProduct (for version range lookup).
func (m *CVEMatcher) matchViaAffectedProducts(event model.ThreatEvent, vendor, product string) (string, *model.AffectedProduct) {
	for i := range event.AffectedProducts {
		ap := &event.AffectedProducts[i]
		apVendor := m.normalizeVendor(ap.Vendor)
		apProduct := m.normalizeProduct(ap.Product)
		if vendorMatch(apVendor, vendor) && productMatch(apProduct, product) {
			return "product_only_match", ap
		}
	}
	return "", nil
}

// matchViaTitle checks if vendor or product appear in the event title.
// This is the weak last-resort fallback.
func (m *CVEMatcher) matchViaTitle(title, vendor, product string) bool {
	t := strings.ToLower(title)
	if vendor != "" && strings.Contains(t, vendor) {
		return true
	}
	if product != "" && strings.Contains(t, product) {
		return true
	}
	return false
}

// vendorMatch returns true if two normalized vendor names match.
func vendorMatch(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return a == b || strings.Contains(a, b) || strings.Contains(b, a)
}

// productMatch returns true if two normalized product names match.
func productMatch(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return a == b || strings.Contains(a, b) || strings.Contains(b, a)
}

// normalizeVendor normalizes a vendor name using the alias map.
func (m *CVEMatcher) normalizeVendor(name string) string {
	key := strings.ToLower(strings.TrimSpace(name))
	if alias, ok := m.aliasMap[key]; ok {
		return alias
	}
	return key
}

// normalizeProduct normalizes a product name, using the product alias map.
func (m *CVEMatcher) normalizeProduct(name string) string {
	key := strings.ToLower(strings.TrimSpace(name))
	if alias, ok := m.productAliasMap[key]; ok {
		return alias
	}
	return key
}

// defaultAliases returns the built-in vendor alias map.
func defaultAliases() map[string]string {
	return map[string]string{
		"apache software foundation":  "apache",
		"the apache software foundation": "apache",
		"httpd":                         "apache http server",
		"microsoft corporation":         "microsoft",
		"microsoft corp":                "microsoft",
		"ms":                            "microsoft",
		"red hat":                       "red hat",
		"redhat":                        "red hat",
		"canonical":                     "canonical",
		"atlassian":                     "atlassian",
		"atlassian pty ltd":             "atlassian",
		"sap ag":                        "sap",
		"sap se":                        "sap",
		"siemens ag":                    "siemens",
		"siemens":                       "siemens",
	}
}

// defaultProductAliases returns the built-in product alias map.
// Maps common CVE/MISP product names to tech stack application names.
func defaultProductAliases() map[string]string {
	return map[string]string{
		"httpd":               "apache http server",
		"apache2":             "apache http server",
		"apache httpd":        "apache http server",
		"microsoft windows":   "windows server",
		"windows":             "windows server",
		"windows 10":          "windows server",
		"windows 11":          "windows server",
		"sap netweaver":       "sap s/4hana",
		"netweaver":           "sap s/4hana",
	}
}
