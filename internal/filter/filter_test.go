package filter

import (
	"testing"

	"github.com/jayelbotvibe-web/threatlib/internal/model"
)

func TestFilter_Allow(t *testing.T) {
	f := New()

	// Load some warning CVEs and notice events
	f.LoadWarningCVEs("CVE-2024-99999") // known false positive
	f.LoadNoticeEvents("event-uuid-suppressed")

	tests := []struct {
		name  string
		event model.ThreatEvent
		want  bool
	}{
		{
			name: "normal event passes",
			event: model.ThreatEvent{
				ID:   "ev-001",
				CVEs: []string{"CVE-2024-38472"},
				Tags: []string{"tlp:amber"},
			},
			want: true,
		},
		{
			name: "warninglist CVE dropped",
			event: model.ThreatEvent{
				ID:   "ev-002",
				CVEs: []string{"CVE-2024-99999"},
				Tags: []string{"tlp:white"},
			},
			want: false,
		},
		{
			name: "noticelist event dropped",
			event: model.ThreatEvent{
				ID:   "event-uuid-suppressed",
				CVEs: []string{"CVE-2024-38472"},
				Tags: []string{"tlp:amber"},
			},
			want: false,
		},
		{
			name: "TLP:RED dropped",
			event: model.ThreatEvent{
				ID:   "ev-003",
				CVEs: []string{"CVE-2024-28941"},
				Tags: []string{"tlp:red", "exploit:in-the-wild"},
			},
			want: false,
		},
		{
			name: "event with no CVE passes",
			event: model.ThreatEvent{
				ID:   "ev-004",
				CVEs: []string{},
				Tags: []string{"tlp:amber", "eu-nis-oes:eu-nis-oes-manufacturing"},
			},
			want: true,
		},
		{
			name: "mix of good and bad CVEs — dropped",
			event: model.ThreatEvent{
				ID:   "ev-005",
				CVEs: []string{"CVE-2024-38472", "CVE-2024-99999"},
				Tags: []string{"tlp:amber"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := f.Allow(tt.event)
			if got != tt.want {
				t.Errorf("Allow() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilter_FilterEvents(t *testing.T) {
	f := New()
	f.LoadWarningCVEs("CVE-2024-BAD")

	events := []model.ThreatEvent{
		{ID: "e1", CVEs: []string{"CVE-2024-38472"}, Tags: []string{"tlp:amber"}},
		{ID: "e2", CVEs: []string{"CVE-2024-BAD"}, Tags: []string{"tlp:white"}},
		{ID: "e3", CVEs: []string{"CVE-2024-28941"}, Tags: []string{"tlp:amber"}},
	}

	passed := f.FilterEvents(events)
	if len(passed) != 2 {
		t.Errorf("FilterEvents = %d events, want 2", len(passed))
	}
	if passed[0].ID != "e1" || passed[1].ID != "e3" {
		t.Errorf("unexpected event order: %v, %v", passed[0].ID, passed[1].ID)
	}

	w, n := f.Count()
	t.Logf("filter loaded: %d warning CVEs, %d notice events", w, n)
}

func TestFilter_Empty(t *testing.T) {
	f := New()

	event := model.ThreatEvent{
		ID:   "ev-empty-test",
		CVEs: []string{"CVE-2024-38472"},
		Tags: []string{"tlp:red"},
	}

	// Even with no warninglists loaded, TLP:RED should still be dropped
	if f.Allow(event) {
		t.Error("TLP:RED should be dropped even with empty warninglists")
	}
}
