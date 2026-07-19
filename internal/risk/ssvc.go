// Package risk — SSVC Deployer decision tree.
//
// Implements the complete Stakeholder-Specific Vulnerability Categorization
// (SSVC) Deployer decision table — all 72 combinations of the four decision
// points, not a subset:
//
//	Exploitation {none, poc, active}
//	  × Exposure {small, controlled, open}
//	  × Automatable {no, yes}
//	  × Human Impact / Mission & Well-being {low, medium, high, very_high}
//
// Each leaf outcome is taken verbatim from the published CERT/CC SSVC Deployer
// tree and reported using CISA's Deployer action labels. The two label sets are
// the same four ordinal priority tiers under different names:
//
//	defer → Track   scheduled → Track*   out-of-cycle → Attend   immediate → Act
//
// Decision points are derived from the available data:
//  1. Exploitation — KEV match or exploit:in-the-wild tag → active; else none.
//     (EPSS → poc pathway reserved for a later workstream.)
//  2. Exposure — internet-facing match → open; other match → controlled; none → small.
//  3. Automatable — CVSS ≥ 7 heuristic (upgrade path: parse the CVSS vector).
//  4. Mission & Well-being — from asset criticality + data sensitivity + exposure.
//
// Sources:
//   - https://certcc.github.io/SSVC/howto/deployer_tree/
//   - https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc
package risk

import (
	"fmt"

	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/model"
)

// Exploitation levels for the SSVC tree.
const (
	explNone   = "none"
	explPoC    = "poc"
	explActive = "active"
)

// Exposure levels.
const (
	expSmall      = "small"
	expControlled = "controlled"
	expOpen       = "open"
)

// SSVC action labels (canonical v2.1 Deployer outputs).
const (
	ActionAct       = "Act"
	ActionAttend    = "Attend"
	ActionTrack     = "Track"
	ActionTrackStar = "Track*"

	missionVeryHigh = "very_high"
	missionHigh     = "high"
	missionMedium   = "medium"
	missionLow      = "low"
)

// SSVCResult holds the output of the SSVC decision tree, including
// a trace of which branches fired and why.
type SSVCResult struct {
	Action string `json:"action"`
	Trace  string `json:"trace"`
}

// deployerOutcomes is the CERT/CC SSVC Deployer decision table (72 leaves),
// indexed by exploitation*24 + exposure*8 + automatable*4 + humanImpact.
// Iteration order: exploitation{none,poc,active} × exposure{small,controlled,
// open} × automatable{no,yes} × humanImpact{low,medium,high,very_high}.
// Letters are the CERT/CC outcomes: D=defer, S=scheduled, O=out-of-cycle,
// I=immediate. The table is monotonic — the outcome never decreases as any
// single decision point worsens (enforced by TestSSVC_Monotonic).
// Rows are ordered exposure-outer, automatable-inner; the four letters in each
// group are human impact low, medium, high, very_high.
var deployerOutcomes = []byte(
	// exploitation:none
	"DDSS" + "DSSS" + // small:      no, yes
		"DSSS" + "SSSS" + // controlled: no, yes
		"DSSS" + "SSSO" + // open:       no, yes
		// exploitation:poc
		"DSSS" + "SSSS" + // small
		"DSSS" + "SSSO" + // controlled
		"SSSO" + "SSOO" + // open
		// exploitation:active
		"SSOO" + "SOOO" + // small
		"SSOO" + "OOOO" + // controlled
		"SOOI" + "OOII") // open

var (
	explIndex     = map[string]int{explNone: 0, explPoC: 1, explActive: 2}
	exposureIndex = map[string]int{expSmall: 0, expControlled: 1, expOpen: 2}
	missionIndex  = map[string]int{missionLow: 0, missionMedium: 1, missionHigh: 2, missionVeryHigh: 3}

	// certToAction maps CERT/CC Deployer outcomes to CISA action labels.
	certToAction = map[byte]string{'D': ActionTrack, 'S': ActionTrackStar, 'O': ActionAttend, 'I': ActionAct}
	certName     = map[byte]string{'D': "defer", 'S': "scheduled", 'O': "out-of-cycle", 'I': "immediate"}
)

// SSVCTree evaluates the full SSVC Deployer decision table for an event.
func SSVCTree(event model.ThreatEvent, org model.OrgContext, matches []model.Match) SSVCResult {
	exploitation := determineExploitation(event, matches)
	exposure := determineExposure(org, matches)
	automatable := determineAutomatable(event)
	mission := determineMissionImpact(org, matches)

	cert := deployerOutcome(exploitation, exposure, automatable, mission)
	action := certToAction[cert]
	trace := fmt.Sprintf("exploitation:%s → exposure:%s → automatable:%s → mission:%s → %s (%s)",
		exploitation, exposure, yesNo(automatable), mission, action, certName[cert])

	return SSVCResult{Action: action, Trace: trace}
}

// deployerOutcome looks up the CERT/CC Deployer outcome letter for the given
// decision-point values. Unrecognized inputs fall back to the least-urgent
// tier so a scoring gap can never inflate priority.
func deployerOutcome(exploitation, exposure string, automatable bool, mission string) byte {
	e, ok1 := explIndex[exploitation]
	x, ok2 := exposureIndex[exposure]
	h, ok3 := missionIndex[mission]
	if !ok1 || !ok2 || !ok3 {
		return 'D'
	}
	a := 0
	if automatable {
		a = 1
	}
	return deployerOutcomes[e*24+x*8+a*4+h]
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// determineExploitation decides the exploitation state from event data.
func determineExploitation(event model.ThreatEvent, matches []model.Match) string {
	// KEV match = active exploitation (CISA catalog)
	for _, m := range matches {
		if m.KEVMatch {
			return explActive
		}
	}
	// exploit:in-the-wild tag = active
	for _, tag := range event.Tags {
		if tag == "exploit:in-the-wild" {
			return explActive
		}
	}
	// EPSS ≥ threshold → PoC — reserved for Workstream 3
	return explNone
}

// determineExposure maps tech-stack matching to SSVC exposure levels.
func determineExposure(org model.OrgContext, matches []model.Match) string {
	hasAnyMatch := len(matches) > 0
	hasInternetFacing := false

	for _, m := range matches {
		if m.AppName == "" {
			continue
		}
		for _, app := range org.TechStack {
			if app.Name == m.AppName {
				if app.InternetFacing {
					hasInternetFacing = true
				}
			}
		}
	}

	if hasInternetFacing {
		return expOpen
	}
	if hasAnyMatch {
		return expControlled
	}
	return expSmall
}

// determineAutomatable decides whether exploitation can be automated.
//
// Conservative heuristic — CVSS ≥ 7.0 assumes automatable.
// Upgrade path: parse CVSS vector string for attackVector:Network +
// attackComplexity:Low + privilegesRequired:None.
func determineAutomatable(event model.ThreatEvent) bool {
	return event.CVSS >= 7.0
}

// determineMissionImpact maps asset criticality and data sensitivity
// to SSVC mission & well-being impact levels (very_high, high, medium, low).
func determineMissionImpact(org model.OrgContext, matches []model.Match) string {
	hasCritical := false
	hasHigh := false
	hasSensitiveData := false
	isInternetFacing := false

	for _, m := range matches {
		if m.AppName == "" {
			continue
		}
		for _, app := range org.TechStack {
			if app.Name == m.AppName {
				switch app.Criticality {
				case "critical":
					hasCritical = true
					if app.InternetFacing {
						isInternetFacing = true
					}
				case "high":
					hasHigh = true
				}
				if app.DataSensitivity == "critical" || app.DataSensitivity == "high" {
					hasSensitiveData = true
				}
			}
		}
	}

	// Very high: critical infrastructure asset, internet-facing, with sensitive data
	if hasCritical && isInternetFacing && hasSensitiveData {
		return missionVeryHigh
	}
	if hasCritical && hasSensitiveData {
		return missionHigh
	}
	if hasCritical || hasHigh {
		return missionMedium
	}
	return missionLow
}
