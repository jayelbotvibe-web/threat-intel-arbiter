// Package version provides version scheme detection and range comparison
// for the CVEMatcher. Handles semver, date-based, SAP, Windows build,
// and Linux kernel version schemes.
package version

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Scheme identifies the versioning scheme of a version string.
type Scheme string

const (
	SchemeSemver      Scheme = "semver"
	SchemeDate        Scheme = "date"
	SchemeSAP         Scheme = "sap"
	SchemeWindows     Scheme = "windows_build"
	SchemeLinuxKernel Scheme = "linux_kernel"
	SchemeUnknown     Scheme = "unknown"
)

// Detect determines the version scheme from a version string.
func Detect(v string) Scheme {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v") // handle "v1.2.3"

	// Date: YYYY-MM-DD
	if matched, _ := regexp.MatchString(`^\d{4}-\d{2}-\d{2}$`, v); matched {
		return SchemeDate
	}

	// SAP: contains "SPS" (Support Package Stack)
	if strings.Contains(strings.ToUpper(v), "SPS") {
		return SchemeSAP
	}

	// Windows build: 10.0.XXXXX (5-digit build number)
	if matched, _ := regexp.MatchString(`^10\.0\.\d{4,5}$`, v); matched {
		return SchemeWindows
	}

	// Linux kernel: X.Y.Z[-N-generic] or X.Y.Z-N-generic
	if matched, _ := regexp.MatchString(`^\d+\.\d+\.\d+`, v); matched {
		if strings.Contains(v, "-generic") || strings.Contains(v, "-aws") {
			return SchemeLinuxKernel
		}
		// Distinguish kernel from semver by the dash pattern
		if strings.Count(v, "-") >= 2 {
			return SchemeLinuxKernel
		}
	}

	// Semver: X.Y.Z or X.Y
	if matched, _ := regexp.MatchString(`^\d+\.\d+(\.\d+)?`, v); matched {
		if strings.Count(v, ".") >= 2 || strings.Count(v, ".") == 1 {
			return SchemeSemver
		}
	}

	return SchemeUnknown
}

// Parse converts a version string to a comparable integer tuple based on its scheme.
func Parse(v string) (scheme Scheme, tuple []int, err error) {
	scheme = Detect(v)
	v = strings.TrimSpace(v)

	switch scheme {
	case SchemeSemver:
		tuple, err = parseSemver(v)
	case SchemeDate:
		tuple, err = parseDate(v)
	case SchemeSAP:
		tuple, err = parseSAP(v)
	case SchemeWindows:
		tuple, err = parseWindows(v)
	case SchemeLinuxKernel:
		tuple, err = parseLinuxKernel(v)
	default:
		return SchemeUnknown, nil, fmt.Errorf("unknown version scheme: %q", v)
	}
	return
}

// InRange checks if a version falls within a start-end range.
// Both start and end are inclusive. If start is empty, no lower bound.
// InRange checks if a version falls within a start-end range.
func InRange(version, start, end string) (bool, string) {
	verScheme, verTuple, err := Parse(version)
	if err != nil {
		// Can't parse version — conservative: assume affected
		return true, "product_only_match"
	}
	_ = verScheme
	// Compare against start
	if start != "" {
		_, startTuple, err := Parse(start)
		if err != nil {
			return false, "unparseable_version"
		}
		if compareTuples(verTuple, startTuple) < 0 {
			return false, "exact_version_match" // version is below affected range — not affected
		}
	}

	// Compare against end
	if end != "" {
		_, endTuple, err := Parse(end)
		if err != nil {
			return false, "unparseable_version"
		}
		if compareTuples(verTuple, endTuple) > 0 {
			return false, "exact_version_match" // version is above affected range — not affected
		}
	}

	// Version falls within affected range AND we could parse it
	if verScheme != SchemeUnknown {
		return true, "exact_version_match"
	}
	return true, "product_only_match"
}

// compareTuples compares two integer tuples lexicographically.
// Returns -1 if a < b, 0 if equal, 1 if a > b.
func compareTuples(a, b []int) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}

// ─────────────────────────────────────────────────────────────
// Scheme-specific parsers
// ─────────────────────────────────────────────────────────────

func parseSemver(v string) ([]int, error) {
	// Strip any leading 'v'
	v = strings.TrimPrefix(v, "v")
	// Split on dots
	parts := strings.Split(v, ".")
	var tuple []int
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return nil, fmt.Errorf("semver parse %q: %w", p, err)
		}
		tuple = append(tuple, n)
	}
	return tuple, nil
}

func parseDate(v string) ([]int, error) {
	t, err := time.Parse("2006-01-02", v)
	if err != nil {
		return nil, fmt.Errorf("date parse %q: %w", v, err)
	}
	// Convert to days since epoch for comparison
	days := int(t.Unix() / 86400)
	return []int{days}, nil
}

func parseSAP(v string) ([]int, error) {
	// Format: "7.5 SPS22" or "SPS22"
	v = strings.ToUpper(v)

	// Extract SPS number
	spsRe := regexp.MustCompile(`SPS(\d+)`)
	spsMatch := spsRe.FindStringSubmatch(v)
	spsNum := 0
	if len(spsMatch) >= 2 {
		spsNum, _ = strconv.Atoi(spsMatch[1])
	}

	// Extract base version (e.g., "7.5")
	baseRe := regexp.MustCompile(`(\d+)\.(\d+)`)
	baseMatch := baseRe.FindStringSubmatch(v)
	major, minor := 0, 0
	if len(baseMatch) >= 3 {
		major, _ = strconv.Atoi(baseMatch[1])
		minor, _ = strconv.Atoi(baseMatch[2])
	}

	return []int{major, minor, spsNum}, nil
}

func parseWindows(v string) ([]int, error) {
	// Format: "10.0.20348"
	parts := strings.Split(v, ".")
	if len(parts) < 3 {
		return nil, fmt.Errorf("windows build parse %q: need 3 components", v)
	}
	major, _ := strconv.Atoi(parts[0])
	minor, _ := strconv.Atoi(parts[1])
	build, _ := strconv.Atoi(parts[2])
	return []int{major, minor, build}, nil
}

func parseLinuxKernel(v string) ([]int, error) {
	// Format: "5.10.0-26-generic" or "5.10.0"
	// Strip suffix after first dash
	base := strings.SplitN(v, "-", 2)[0]
	parts := strings.Split(base, ".")
	if len(parts) < 3 {
		return nil, fmt.Errorf("kernel parse %q: need 3 components", v)
	}
	major, _ := strconv.Atoi(parts[0])
	minor, _ := strconv.Atoi(parts[1])
	patch, _ := strconv.Atoi(parts[2])
	return []int{major, minor, patch}, nil
}
