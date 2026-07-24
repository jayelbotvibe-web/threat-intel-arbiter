package notify

import (
	"testing"

	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/model"
)

// TestHeaderSafe guards the email header-injection fix: CR/LF and control
// characters must be stripped so source-controlled text can't inject headers.
func TestHeaderSafe(t *testing.T) {
	cases := map[string]string{
		"normal subject":          "normal subject",
		"crlf\r\nBcc: evil@x.com": "crlfBcc: evil@x.com",
		"lf\ninjected":            "lfinjected",
		"tab\tand\x00null":        "tabandnull",
	}
	for in, want := range cases {
		if got := headerSafe(in); got != want {
			t.Errorf("headerSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

// captureNotifier records whether it was sent an alert.
type captureNotifier struct {
	name string
	sent int
}

func (c *captureNotifier) Name() string             { return c.name }
func (c *captureNotifier) Send(a model.Alert) error { c.sent++; return nil }

// TestRouter_EmptyConfidenceMatchesAll guards the silent-drop fix: a rule that
// omits confidence must match any confidence, not nothing.
func TestRouter_EmptyConfidenceMatchesAll(t *testing.T) {
	cap := &captureNotifier{name: "mem"}
	// Rule with NO confidence field — previously matched nothing.
	r := NewRouter([]Rule{{Severity: "medium", Channels: []string{"mem"}}})
	r.Register("mem", cap)

	routed := r.Route(model.Alert{ID: "a1", Severity: "medium", Confidence: "low"})
	if len(routed) != 1 || cap.sent != 1 {
		t.Fatalf("empty-confidence medium rule did not route: routed=%v sent=%d", routed, cap.sent)
	}

	// Case-insensitive severity match.
	routed = r.Route(model.Alert{ID: "a2", Severity: "MEDIUM", Confidence: "high"})
	if len(routed) != 1 {
		t.Errorf("case-insensitive severity match failed: routed=%v", routed)
	}
}

// TestIsPrivateIP_IPv6 guards the IOC-denylist fix: IPv6 loopback/ULA/link-local
// must be treated as private so they are never pushed to the EDR.
func TestIsPrivateIP_IPv6(t *testing.T) {
	private := []string{"::1", "fe80::1", "fc00::1", "fd12:3456::1", "::", "127.0.0.1", "10.0.0.1"}
	for _, ip := range private {
		if !isPrivateIP(ip) {
			t.Errorf("isPrivateIP(%q) = false, want true (reserved)", ip)
		}
	}
	public := []string{"2606:4700:4700::1111", "45.153.241.187", "8.8.8.8"}
	for _, ip := range public {
		if isPrivateIP(ip) {
			t.Errorf("isPrivateIP(%q) = true, want false (public)", ip)
		}
	}
}
