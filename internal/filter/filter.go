// Package filter provides threat intelligence pre-processing filters.
// It loads MISP warninglists and noticelists and drops events matching
// known false positives, admin-suppressed entries, or non-actionable markings.
package filter

import (
	"strings"

	"github.com/jayelbotvibe-web/threatlib/internal/model"
)

// Filter holds cached warninglist and noticelist data used to drop
// events before they enter the matching engine.
type Filter struct {
	// warningCVEs holds CVE IDs from MISP warninglists (known false positives).
	warningCVEs map[string]bool
	// noticeEvents holds event UUIDs from MISP noticelists (admin-suppressed).
	noticeEvents map[string]bool
}

// New creates an empty filter. Use LoadWarningLists and LoadNoticeLists
// to populate it from MISP API responses.
func New() *Filter {
	return &Filter{
		warningCVEs:  make(map[string]bool),
		noticeEvents: make(map[string]bool),
	}
}

// LoadWarningCVEs populates the filter with CVE IDs from MISP warninglists.
// Each entry is a CVE ID that has been identified as a false positive.
func (f *Filter) LoadWarningCVEs(cves ...string) {
	for _, cve := range cves {
		f.warningCVEs[strings.ToUpper(cve)] = true
	}
}

// LoadNoticeEvents populates the filter with event UUIDs from MISP noticelists.
// These are events that administrators have explicitly suppressed.
func (f *Filter) LoadNoticeEvents(ids ...string) {
	for _, id := range ids {
		f.noticeEvents[id] = true
	}
}

// Allow checks whether an event should be allowed through the filter.
// Returns true if the event passes all filters.
func (f *Filter) Allow(event model.ThreatEvent) bool {
	// Check noticelists (admin-suppressed events)
	if f.noticeEvents[event.ID] {
		return false
	}

	// Check warninglists (known false-positive CVEs)
	for _, cve := range event.CVEs {
		if f.warningCVEs[strings.ToUpper(cve)] {
			return false
		}
	}

	// Drop TLP:RED events — not distributable
	for _, tag := range event.Tags {
		if tag == "tlp:red" {
			return false
		}
	}

	return true
}

// FilterEvents applies the filter to a slice of events and returns
// only those that pass.
func (f *Filter) FilterEvents(events []model.ThreatEvent) []model.ThreatEvent {
	var passed []model.ThreatEvent
	for _, event := range events {
		if f.Allow(event) {
			passed = append(passed, event)
		}
	}
	return passed
}

// Count returns the number of loaded warninglist and noticelist entries.
func (f *Filter) Count() (warnings, notices int) {
	return len(f.warningCVEs), len(f.noticeEvents)
}
