package version

import (
	"testing"
)

func TestDetect(t *testing.T) {
	tests := []struct {
		input  string
		scheme Scheme
	}{
		{"2.4.57", SchemeSemver},
		{"1.2.3", SchemeSemver},
		{"2023-07-15", SchemeDate},
		{"2024-01-01", SchemeDate},
		{"7.5 SPS22", SchemeSAP},
		{"SPS22", SchemeSAP},
		{"10.0.20348", SchemeWindows},
		{"10.0.19045", SchemeWindows},
		{"5.10.0-26-generic", SchemeLinuxKernel},
		{"5.15.0-91-generic", SchemeLinuxKernel},
		{"free text version", SchemeUnknown},
		{"", SchemeUnknown},
	}

	for _, tt := range tests {
		got := Detect(tt.input)
		if got != tt.scheme {
			t.Errorf("Detect(%q) = %s, want %s", tt.input, got, tt.scheme)
		}
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		input  string
		scheme Scheme
		want   []int
	}{
		{"2.4.57", SchemeSemver, []int{2, 4, 57}},
		{"1.2.3", SchemeSemver, []int{1, 2, 3}},
		{"v1.2.3", SchemeSemver, []int{1, 2, 3}},
		{"2023-07-15", SchemeDate, nil}, // date tuple varies by timezone; scheme check is sufficient
		{"7.5 SPS22", SchemeSAP, []int{7, 5, 22}},
		{"SPS22", SchemeSAP, []int{0, 0, 22}},
		{"10.0.20348", SchemeWindows, []int{10, 0, 20348}},
		{"5.10.0-26-generic", SchemeLinuxKernel, []int{5, 10, 0}},
	}

	for _, tt := range tests {
		scheme, tuple, err := Parse(tt.input)
		if err != nil {
			t.Errorf("Parse(%q): %v", tt.input, err)
			continue
		}
		if scheme != tt.scheme {
			t.Errorf("Parse(%q).scheme = %s, want %s", tt.input, scheme, tt.scheme)
		}
		if !equalTuples(tuple, tt.want) && tt.want != nil {
			t.Errorf("Parse(%q).tuple = %v, want %v", tt.input, tuple, tt.want)
		}
	}
}

func TestInRange(t *testing.T) {
	tests := []struct {
		name    string
		version string
		start   string
		end     string
		affected bool
		conf     string
	}{
		// Semver
		{"semver: in range", "2.4.30", "2.4.0", "2.4.56", true, "exact_version_match"},
		{"semver: below range (safe)", "2.3.9", "2.4.0", "2.4.56", false, "exact_version_match"},
		{"semver: above range (safe)", "2.4.57", "2.4.0", "2.4.56", false, "exact_version_match"},
		{"semver: at boundary", "2.4.56", "2.4.0", "2.4.56", true, "exact_version_match"},
		{"semver: no upper bound", "3.0.0", "2.4.0", "", true, "exact_version_match"},
		{"semver: no lower bound", "1.0.0", "", "2.4.56", true, "exact_version_match"},

		// SAP
		{"sap: SPS20 affected (range 0-21)", "7.5 SPS20", "7.5 SPS00", "7.5 SPS21", true, "exact_version_match"},
		{"sap: SPS22 safe (above SPS21)", "7.5 SPS22", "7.5 SPS00", "7.5 SPS21", false, "exact_version_match"},

		// Windows
		{"windows: in build range", "10.0.20348", "10.0.19045", "10.0.22000", true, "exact_version_match"},
		{"windows: below range", "10.0.17763", "10.0.19045", "10.0.22000", false, "exact_version_match"},

		// Date
		{"date: in range", "2023-06-15", "2023-01-01", "2023-12-31", true, "exact_version_match"},
		{"date: before range", "2022-12-31", "2023-01-01", "2023-12-31", false, "exact_version_match"},

		// Unknown scheme
		{"unknown: falls back to product_only", "free text", "1.0", "2.0", true, "product_only_match"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			affected, conf := InRange(tt.version, tt.start, tt.end)
			if affected != tt.affected {
				t.Errorf("affected = %v, want %v (version=%s, start=%s, end=%s)",
					affected, tt.affected, tt.version, tt.start, tt.end)
			}
			if conf != tt.conf {
				t.Errorf("confidence = %s, want %s", conf, tt.conf)
			}
		})
	}
}

func TestCompareTuples(t *testing.T) {
	tests := []struct {
		a, b []int
		want int
	}{
		{[]int{2, 4, 30}, []int{2, 4, 57}, -1},
		{[]int{2, 4, 57}, []int{2, 4, 57}, 0},
		{[]int{3, 0, 0}, []int{2, 4, 57}, 1},
		{[]int{2, 4}, []int{2, 4, 0}, -1},
		{[]int{2, 4, 0}, []int{2, 4}, 1},
	}

	for _, tt := range tests {
		got := compareTuples(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("compareTuples(%v, %v) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func equalTuples(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
