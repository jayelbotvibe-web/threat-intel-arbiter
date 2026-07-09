// Package risk — SSVC v2.1 Deployer decision tree.
//
// Implements the CMU/CISA Stakeholder-Specific Vulnerability Categorization
// (SSVC) v2.1 decision tree for the Deployer role. This is a genuine decision
// tree, not a score-to-label mapping.
//
// Decision points:
//  1. Exploitation — KEV/exploit tags → active; else → none
//     (EPSS → PoC pathway reserved for Workstream 3)
//  2. Exposure — internet-facing → open; matched internal → controlled;
//     no match → small
//  3. Automatable — CVSS ≥ 7 → yes (conservative heuristic);
//     // ponytail: upgrade path is parsing CVSS vector strings
//  4. Mission & Well-being — from asset criticality + data sensitivity
//
// Outputs: Act, Attend, Track*, Track (the canonical SSVC v2 labels).
package risk

import (
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
)

// SSVCResult holds the output of the SSVC decision tree, including
// a trace of which branches fired and why.
type SSVCResult struct {
	Action string `json:"action"`
	Trace  string `json:"trace"`
}

// SSVCTree evaluates the SSVC v2.1 Deployer decision tree.
//
// The tree is evaluated top-down: exploitation → exposure → automatable
// → mission & well-being. Each decision point is determined from the
// available data (event, org, matches).
func SSVCTree(event model.ThreatEvent, org model.OrgContext, matches []model.Match) SSVCResult {
	exploitation := determineExploitation(event, matches)
	exposure := determineExposure(org, matches)
	automatable := determineAutomatable(event)
	mission := determineMissionImpact(org, matches)

	var action string
	var trace string

	switch exploitation {
	case explNone:
		action = ActionTrack
		trace = "exploitation:none → Track"

	case explPoC:
		switch exposure {
		case expSmall:
			action = ActionTrack
			trace = "exploitation:PoC → exposure:small → Track"
		case expControlled:
			action = ActionAttend
			trace = "exploitation:PoC → exposure:controlled → Attend"
		case expOpen:
			action = ActionAttend
			trace = "exploitation:PoC → exposure:open → Attend"
		}

	case explActive:
		switch exposure {
		case expSmall:
			action = ActionAttend
			trace = "exploitation:active → exposure:small → Attend"
		case expControlled:
			action = ActionAttend
			trace = "exploitation:active → exposure:controlled → Attend"
		case expOpen:
			// active + open: proceed to automatable and mission
			if automatable {
				switch mission {
				case "high":
					action = ActionAct
					trace = "exploitation:active → exposure:open → automatable:yes → mission:high → Act"
				default: // medium, low
					action = ActionAttend
					trace = "exploitation:active → exposure:open → automatable:yes → mission:medium/low → Attend"
				}
			} else {
				switch mission {
				case "low":
					action = ActionTrackStar
					trace = "exploitation:active → exposure:open → automatable:no → mission:low → Track*"
				default: // high, medium
					action = ActionAttend
					trace = "exploitation:active → exposure:open → automatable:no → mission:high/medium → Attend"
				}
			}
		}
	}

	return SSVCResult{Action: action, Trace: trace}
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
	// ponytail: EPSS ≥ threshold → PoC — reserved for Workstream 3
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
// ponytail: conservative heuristic — CVSS ≥ 7.0 assumes automatable.
// Upgrade path: parse CVSS vector string for attackVector:Network +
// attackComplexity:Low + privilegesRequired:None.
func determineAutomatable(event model.ThreatEvent) bool {
	return event.CVSS >= 7.0
}

// determineMissionImpact maps asset criticality and data sensitivity
// to SSVC mission & well-being impact levels.
func determineMissionImpact(org model.OrgContext, matches []model.Match) string {
	hasCritical := false
	hasHigh := false
	hasSensitiveData := false

	for _, m := range matches {
		if m.AppName == "" {
			continue
		}
		for _, app := range org.TechStack {
			if app.Name == m.AppName {
				switch app.Criticality {
				case "critical":
					hasCritical = true
				case "high":
					hasHigh = true
				}
				if app.DataSensitivity == "critical" || app.DataSensitivity == "high" {
					hasSensitiveData = true
				}
			}
		}
	}

	if hasCritical && hasSensitiveData {
		return "high"
	}
	if hasCritical || hasHigh {
		return "medium"
	}
	return "low"
}
