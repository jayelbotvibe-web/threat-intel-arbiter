package risk

import "testing"

// severity rank of the four outcome tiers, least → most urgent.
var actionRank = map[string]int{ActionTrack: 0, ActionTrackStar: 1, ActionAttend: 2, ActionAct: 3}

var (
	allExpl     = []string{explNone, explPoC, explActive}
	allExposure = []string{expSmall, expControlled, expOpen}
	allMission  = []string{missionLow, missionMedium, missionHigh, missionVeryHigh}
	allAuto     = []bool{false, true}
)

// Every one of the 72 combinations must map to a valid, known action.
func TestSSVC_FullCoverage(t *testing.T) {
	count := 0
	for _, e := range allExpl {
		for _, x := range allExposure {
			for _, a := range allAuto {
				for _, m := range allMission {
					cert := deployerOutcome(e, x, a, m)
					action, ok := certToAction[cert]
					if !ok || actionRank[action] < 0 {
						t.Errorf("%s/%s/%v/%s → unknown outcome %q", e, x, a, m, cert)
					}
					count++
				}
			}
		}
	}
	if count != 72 {
		t.Fatalf("expected 72 combinations, evaluated %d", count)
	}
}

// The table must be monotonic: worsening any single decision point (while
// holding the others fixed) never lowers the outcome's urgency. This catches
// transcription errors in the 72-row table.
func TestSSVC_Monotonic(t *testing.T) {
	rank := func(e, x string, a bool, m string) int {
		return actionRank[certToAction[deployerOutcome(e, x, a, m)]]
	}
	idx := func(s []string, v string) int {
		for i, x := range s {
			if x == v {
				return i
			}
		}
		return -1
	}
	for _, e := range allExpl {
		for _, x := range allExposure {
			for _, a := range allAuto {
				for _, m := range allMission {
					base := rank(e, x, a, m)
					// Worsen exploitation.
					if i := idx(allExpl, e); i+1 < len(allExpl) {
						if rank(allExpl[i+1], x, a, m) < base {
							t.Errorf("exploitation↑ lowered urgency at %s/%s/%v/%s", e, x, a, m)
						}
					}
					// Worsen exposure.
					if i := idx(allExposure, x); i+1 < len(allExposure) {
						if rank(e, allExposure[i+1], a, m) < base {
							t.Errorf("exposure↑ lowered urgency at %s/%s/%v/%s", e, x, a, m)
						}
					}
					// Worsen mission.
					if i := idx(allMission, m); i+1 < len(allMission) {
						if rank(e, x, a, allMission[i+1]) < base {
							t.Errorf("mission↑ lowered urgency at %s/%s/%v/%s", e, x, a, m)
						}
					}
					// Enable automatable.
					if !a && rank(e, x, true, m) < base {
						t.Errorf("automatable↑ lowered urgency at %s/%s/%v/%s", e, x, a, m)
					}
				}
			}
		}
	}
}

// Anchor rows taken verbatim from the published CERT/CC Deployer tree, mapped
// to CISA labels. If the table is ever re-transcribed, these pin the corners.
func TestSSVC_ReferenceRows(t *testing.T) {
	cases := []struct {
		e, x   string
		a      bool
		m      string
		want   string
		source string // CERT letter
	}{
		{explNone, expSmall, false, missionLow, ActionTrack, "D"},
		{explNone, expOpen, true, missionVeryHigh, ActionAttend, "O"},
		{explPoC, expOpen, true, missionHigh, ActionAttend, "O"},
		{explPoC, expSmall, false, missionLow, ActionTrack, "D"},
		{explActive, expSmall, false, missionLow, ActionTrackStar, "S"},
		{explActive, expControlled, true, missionLow, ActionAttend, "O"},
		{explActive, expOpen, false, missionVeryHigh, ActionAct, "I"},
		{explActive, expOpen, true, missionHigh, ActionAct, "I"},
	}
	for _, c := range cases {
		got := certToAction[deployerOutcome(c.e, c.x, c.a, c.m)]
		if got != c.want {
			t.Errorf("%s/%s/%v/%s = %s, want %s (CERT %s)", c.e, c.x, c.a, c.m, got, c.want, c.source)
		}
	}
}
