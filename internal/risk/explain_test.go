package risk

import (
	"strings"
	"testing"
	"time"

	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/model"
)

func testOrg() model.OrgContext {
	return model.OrgContext{
		TechStack: []model.App{
			{Name: "Apache", Criticality: "critical", InternetFacing: true, DataSensitivity: "high"},
			{Name: "Postgres", Criticality: "high", InternetFacing: false, DataSensitivity: "low"},
		},
	}
}

// The single source of truth guarantee: for every dimension, the factor deltas
// reconcile with the score — either they sum to it, or they exceed the cap and
// the score equals the cap.
func assertReconciles(t *testing.T, name string, score, max int, factors []Contribution) {
	t.Helper()
	raw := rawSum(factors)
	switch {
	case raw > max:
		if score != max {
			t.Errorf("%s: factors sum to %d (>cap %d) but score=%d, want %d", name, raw, max, score, max)
		}
	case raw < 0:
		if score != 0 {
			t.Errorf("%s: negative factor sum %d but score=%d, want 0", name, raw, score)
		}
	default:
		if score != raw {
			t.Errorf("%s: factors sum to %d but score=%d — breakdown does not reconcile", name, raw, score)
		}
	}
}

func TestExplanationReconciles(t *testing.T) {
	e := NewEngine()
	org := testOrg()
	now := time.Now()

	cases := []struct {
		name    string
		event   model.ThreatEvent
		matches []model.Match
	}{
		{
			name: "kev+actor+fresh+critical",
			event: model.ThreatEvent{
				Title: "t", CVSS: 9.8, Source: "misp", SourceConfidence: "medium",
				Tags: []string{"exploit:in-the-wild"}, ThreatActors: []string{"APT99"}, Timestamp: now,
			},
			matches: []model.Match{{AppName: "Apache", KEVMatch: true}},
		},
		{
			name: "old event, no exploitation, sector-only",
			event: model.ThreatEvent{
				Title: "t", CVSS: 5.0, Source: "misp", SourceConfidence: "low",
				Timestamp: now.Add(-90 * 24 * time.Hour),
			},
			matches: []model.Match{{AppName: "Postgres"}},
		},
		{
			name:    "no match at all",
			event:   model.ThreatEvent{Title: "t", CVSS: 8.1, SourceConfidence: "high", Timestamp: now},
			matches: nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := e.Score(c.event, org, c.matches)
			assertReconciles(t, "Likelihood", r.Likelihood, e.cfg.MaxLikelihood, r.LikelihoodFactors)
			assertReconciles(t, "Impact", r.Impact, e.cfg.MaxImpact, r.ImpactFactors)
			assertReconciles(t, "Exposure", r.Exposure, e.cfg.MaxExposure, r.ExposureFactors)
			assertReconciles(t, "Confidence", r.Confidence, e.cfg.MaxConfidence, r.ConfidenceFactors)
		})
	}
}

// Regression: an old event must NOT show a "Recent publication" factor — the
// previous Explain() printed it unconditionally.
func TestExplain_NoPhantomRecency(t *testing.T) {
	e := NewEngine()
	event := model.ThreatEvent{
		Title: "old", CVSS: 7.5, SourceConfidence: "medium",
		Timestamp: time.Now().Add(-100 * 24 * time.Hour),
	}
	r := e.Score(event, testOrg(), []model.Match{{AppName: "Apache"}})
	if strings.Contains(r.Explanation, "Recent publication") {
		t.Errorf("explanation claims recent publication for a 100-day-old event:\n%s", r.Explanation)
	}
}

// Regression: KEV and exploit:in-the-wild describe the same signal and must not
// both add +3 — the old Explain() listed both.
func TestExplain_NoDoubleCountExploitation(t *testing.T) {
	e := NewEngine()
	event := model.ThreatEvent{
		Title: "dup", CVSS: 9.0, SourceConfidence: "high", Timestamp: time.Now(),
		Tags: []string{"exploit:in-the-wild"},
	}
	r := e.Score(event, testOrg(), []model.Match{{AppName: "Apache", KEVMatch: true}})
	threes := 0
	for _, f := range r.LikelihoodFactors {
		if f.Delta == 3 {
			threes++
		}
	}
	if threes != 1 {
		t.Errorf("expected exactly one +3 exploitation factor, got %d: %+v", threes, r.LikelihoodFactors)
	}
}
