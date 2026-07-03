package notify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/model"
)

// ─── validateIOC tests ───

func TestValidateIOC(t *testing.T) {
	tests := []struct {
		name   string
		typ    string
		value  string
		want   string
	}{
		// Valid inputs
		{"valid ipv4", "ipv4", "45.153.241.187", "45.153.241.187"},
		{"valid ipv6", "ipv6", "::1", "::1"},
		{"valid domain", "domain", "evil.com", "evil.com"},
		{"valid sha256", "hash_sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"valid md5", "hash_md5", "d41d8cd98f00b204e9800998ecf8427e", "d41d8cd98f00b204e9800998ecf8427e"},

		// Refanging — bracket notation
		{"refang brackets domain", "domain", "evil[.]com", "evil.com"},
		{"refang parens domain", "domain", "evil(dot)com", "evil.com"},
		{"refang brackets ip", "ipv4", "1[.]2[.]3[.]4", "1.2.3.4"},

		// Refanging — scheme-defanged (must strip hxxp://, not replace)
		{"scheme-defanged domain", "domain", "hxxp://evil[.]com", "evil.com"},
		{"scheme-defanged https", "domain", "hxxps://evil(dot)com", "evil.com"},
		{"http prefix", "domain", "http://evil.com", "evil.com"},

		// Normalization
		{"uppercase hash", "hash_sha256", "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"whitespace trim", "ipv4", "  45.153.241.187  ", "45.153.241.187"},

		// Invalid
		{"bad ip", "ipv4", "not.an.ip", ""},
		{"bad domain", "domain", "!!!", ""},
		{"short sha256", "hash_sha256", "abc123", ""},
		{"wrong hex md5", "hash_md5", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", ""},
		{".local blocked", "domain", "evil.local", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateIOC(tt.typ, tt.value)
			if got != tt.want {
				t.Errorf("validateIOC(%q,%q) = %q, want %q", tt.typ, tt.value, got, tt.want)
			}
		})
	}
}

// ─── Denylist / never-block tests ───

func TestDenylist(t *testing.T) {
	os.Setenv("CROWDSTRIKE_CLIENT_ID", "test")
	defer os.Unsetenv("CROWDSTRIKE_CLIENT_ID")

	cs := NewCrowdstrikeNotifier()
	cs.Mock = true // avoid network calls

	event := model.ThreatEvent{
		ID:     "test-123",
		Title:  "Test event",
		CVEs:   []string{"CVE-2024-0001"},
		Tags:   []string{"tlp:green"},
		IOCs: []model.IOC{
			{Type: model.IOCIPv4, Value: "8.8.8.8", Source: "misp"},                                  // public DNS — blocked
			{Type: model.IOCIPv4, Value: "192.168.1.1", Source: "misp"},                              // private — blocked
			{Type: model.IOCIPv4, Value: "45.153.241.187", Source: "misp"},                           // valid — allowed
			{Type: model.IOCDomain, Value: "google.com", Source: "misp"},                            // CDN — blocked
			{Type: model.IOCDomain, Value: "evil.xyz", Source: "misp"},                              // valid — allowed
			{Type: model.IOCDomain, Value: "!!!invalid!!!", Source: "misp"},                         // invalid — dropped
		},
	}

	sent, err := cs.Notify(event, "high", "high")
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}

	// Only 2 should pass: 45.153.241.187 and evil.xyz (others blocked by denylist/validation)
	if sent != 2 {
		t.Errorf("want 1 IOC sent, got %d", sent)
	}
}

// ─── TLP gate ───

func TestTLPGate(t *testing.T) {
	os.Setenv("CROWDSTRIKE_CLIENT_ID", "test")
	defer os.Unsetenv("CROWDSTRIKE_CLIENT_ID")

	cs := NewCrowdstrikeNotifier()
	cs.Mock = true

	event := model.ThreatEvent{
		ID:     "test-tlp",
		Title:  "TLP test",
		Tags:   []string{"tlp:amber"},
		IOCs: []model.IOC{
			{Type: model.IOCDomain, Value: "evil.com", Source: "misp", Tags: []string{}},
		},
	}

	sent, _ := cs.Notify(event, "high", "high")
	if sent != 0 {
		t.Errorf("TLP:amber should be blocked by default, got %d sent", sent)
	}
}

// ─── Dedup test ───

func TestDedup(t *testing.T) {
	os.Setenv("CROWDSTRIKE_CLIENT_ID", "test")
	defer os.Unsetenv("CROWDSTRIKE_CLIENT_ID")

	cs := NewCrowdstrikeNotifier()
	cs.Mock = true

	event := model.ThreatEvent{
		ID:     "test-dedup",
		Title:  "Dedup test",
		Tags:   []string{"tlp:green"},
		IOCs: []model.IOC{
			{Type: model.IOCDomain, Value: "evil[.]com", Source: "misp"}, // defanged
			{Type: model.IOCDomain, Value: "evil.com", Source: "misp"},   // clean — same
		},
	}

	sent, _ := cs.Notify(event, "high", "high")
	if sent != 1 {
		t.Errorf("dedup: want 1 (defanged+clean = same), got %d", sent)
	}
}

// ─── Race test ───

func TestNotifyRace(t *testing.T) {
	os.Setenv("CROWDSTRIKE_CLIENT_ID", "test")
	defer os.Unsetenv("CROWDSTRIKE_CLIENT_ID")

	// Start a mock token + IOC server
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/indicators/entities/iocs/v1", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]interface{}{"errors": []interface{}{}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	os.Setenv("CROWDSTRIKE_BASE_URL", srv.URL)
	cs := NewCrowdstrikeNotifier()
	cs.Mock = false

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			event := model.ThreatEvent{
				ID:     "test-race-" + string(rune('a'+n%26)),
				Title:  "Race test",
				Tags:   []string{"tlp:green"},
				IOCs: []model.IOC{
					{Type: model.IOCDomain, Value: "evil-" + string(rune('a'+n%26)) + ".com", Source: "misp"},
				},
			}
			cs.Notify(event, "high", "high")
		}(i)
	}

	// Let flusher pick up the batches
	time.Sleep(100 * time.Millisecond)
	cs.flush()
	wg.Wait()

	cs.Close()
}

// ─── Prevent gate ───

func TestPreventGate(t *testing.T) {
	os.Setenv("CROWDSTRIKE_CLIENT_ID", "test")
	os.Setenv("CROWDSTRIKE_ACTION", "prevent")
	os.Setenv("CROWDSTRIKE_PREVENT_IOC_TYPES", "domain")
	defer os.Unsetenv("CROWDSTRIKE_CLIENT_ID")
	defer os.Unsetenv("CROWDSTRIKE_ACTION")
	defer os.Unsetenv("CROWDSTRIKE_PREVENT_IOC_TYPES")

	cs := NewCrowdstrikeNotifier()
	cs.Mock = true

	event := model.ThreatEvent{
		ID:     "test-prevent",
		Title:  "Prevent gate test",
		Tags:   []string{"tlp:green"},
		IOCs: []model.IOC{
			{Type: model.IOCDomain, Value: "evil.com", Source: "misp"},    // allowed for prevent
			{Type: model.IOCIPv4, Value: "45.153.241.187", Source: "misp"}, // not in preventTypes
		},
	}

	sent, _ := cs.Notify(event, "critical", "high")
	if sent != 2 {
		t.Errorf("prevent gate: want 2 (domain=prevent, ip=detect-downgrade), got %d", sent)
	}
}
