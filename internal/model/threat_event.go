// Package model defines the canonical data types used throughout Threat Intel Arbiter.
// Every component operates on these types. Source-specific details are
// isolated in normalizers under internal/source/.
package model

import "time"

// ThreatEvent is the canonical threat intelligence event, normalized from
// any source (MISP, CISA KEV, GitHub Advisory, etc.).
type ThreatEvent struct {
	ID               string            `json:"id"`
	Source           string            `json:"source"`
	SourceConfidence string            `json:"source_confidence"` // "high", "medium", "low"
	Title            string            `json:"title"`
	CVEs             []string          `json:"cves"`
	CVSS             float64           `json:"cvss"`
	Tags             []string          `json:"tags"`
	Description      string            `json:"description"`
	Timestamp        time.Time         `json:"timestamp"`
	AffectedProducts []AffectedProduct `json:"affected_products"`
	ThreatActors     []string          `json:"threat_actors"`
	References       []string          `json:"references"`
	IOCs             []IOC             `json:"iocs,omitempty"`
}

// AffectedProduct describes a product affected by a threat.
type AffectedProduct struct {
	Vendor        string `json:"vendor"`
	Product       string `json:"product"`
	VersionStart  string `json:"version_start"`
	VersionEnd    string `json:"version_end"`
	VersionScheme string `json:"version_scheme"` // "semver", "date", "sap", "windows_build", "linux_kernel", "unknown"
}

// App represents an application in the organisation's tech stack.
type App struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	Vendor          string `json:"vendor"`
	Category        string `json:"category"`
	Criticality     string `json:"criticality"` // "critical", "high", "medium", "low"
	OwnerTeam       string `json:"owner_team"`
	InternetFacing  bool   `json:"internet_facing"`
	Hosts           string `json:"hosts"`
	DataSensitivity string `json:"data_sensitivity"` // "critical", "high", "medium", "low"
}

// OrgContext holds the organisation's profile for matching and scoring.
type OrgContext struct {
	OrgID           string `json:"org_id"`
	Name            string `json:"name"`
	Sector          string `json:"sector"`
	Country         string `json:"country"`
	Timezone        string `json:"timezone"`
	DataSensitivity string `json:"data_sensitivity"`
	TechStack       []App  `json:"-"` // loaded separately, not serialized
}

// Match is produced by a Matcher when a threat event matches the org's context.
type Match struct {
	Matcher         string `json:"matcher"`
	CVE             string `json:"cve,omitempty"`
	AppName         string `json:"app_name,omitempty"`
	AppVersion      string `json:"app_version,omitempty"`
	VersionAffected bool   `json:"version_affected"`
	MatchConfidence string `json:"match_confidence"` // "exact_version_match", "product_only_match", "unparseable_version"
	SectorMatch     bool   `json:"sector_match"`
	KEVMatch        bool   `json:"kev_match"`
	Details         string `json:"details"`
}

// Matcher is the interface implemented by all threat matchers.
type Matcher interface {
	Name() string
	Match(event ThreatEvent, org OrgContext) []Match
}

// Alert represents a generated alert ready for routing.
type Alert struct {
	ID          string   `json:"id"`
	EventID     string   `json:"event_id"`
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence"`
	Action      string   `json:"action"`       // SSVC: "Act Now", "Schedule", "Track", "Monitor"
	Explanation string   `json:"explanation"`
	Status      string   `json:"status"`
	MatchedApps []string `json:"matched_apps"`
	RoutedTo    []string `json:"routed_to"`
	CreatedAt   string   `json:"created_at"`
}

// IOCType represents the supported indicator types for EDR integration.
type IOCType string

const (
	IOCIPv4       IOCType = "ipv4"
	IOCIPv6       IOCType = "ipv6"
	IOCDomain     IOCType = "domain"
	IOCHashSHA256 IOCType = "hash_sha256"
	IOCHashMD5    IOCType = "hash_md5"
)

// IOC represents an indicator of compromise extracted from a threat event.
type IOC struct {
	Type        IOCType `json:"type"`
	Value       string  `json:"value"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	Source      string  `json:"source"`
	Tags        []string `json:"tags,omitempty"`
}
