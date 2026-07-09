// Package risk provides the threat prioritization engine.
// It computes severity and confidence using four dimensions:
// Likelihood, Impact, Exposure, and Confidence.
//
// Formula: risk_score = (L × I × E) / (maxL × maxI × maxE)
// Output: severity label + confidence label + explanation
package risk

import (
	"fmt"
	"time"
	"strings"

	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/config"
	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/model"
)

// Engine computes risk scores for threat events.
type Engine struct {
	cfg RiskWeights
}

// RiskWeights holds the configurable risk scoring parameters.
type RiskWeights struct {
	MaxLikelihood      int
	MaxImpact          int
	MaxExposure        int
	MaxConfidence      int
	SeverityThresholds map[string]float64
}

// ScoreResult holds the output of the risk engine.
type ScoreResult struct {
	Likelihood      int     `json:"likelihood"`
	Impact          int     `json:"impact"`
	Exposure        int     `json:"exposure"`
	Confidence      int     `json:"confidence"`
	RiskScore       float64 `json:"risk_score"`
	Severity        string  `json:"severity"`
	ConfidenceLabel string  `json:"confidence_label"`
	Action          string  `json:"action"`
	SSVCTrace       string  `json:"ssvc_trace"`
	Explanation     string  `json:"explanation"`
}

// NewEngine creates a risk scoring engine with defaults.
func NewEngine() *Engine {
	return &Engine{cfg: defaultWeights()}
}

// NewEngineWithConfig creates a risk scoring engine from a RiskConfig.
func NewEngineWithConfig(riskCfg config.RiskConfig) *Engine {
	w := defaultWeights()
	if riskCfg.Dimensions.Likelihood.Max > 0 {
		w.MaxLikelihood = riskCfg.Dimensions.Likelihood.Max
	}
	if riskCfg.Dimensions.Impact.Max > 0 {
		w.MaxImpact = riskCfg.Dimensions.Impact.Max
	}
	if riskCfg.Dimensions.Exposure.Max > 0 {
		w.MaxExposure = riskCfg.Dimensions.Exposure.Max
	}
	if riskCfg.Dimensions.Confidence.Max > 0 {
		w.MaxConfidence = riskCfg.Dimensions.Confidence.Max
	}
	if riskCfg.Severity.Thresholds != nil {
		w.SeverityThresholds = riskCfg.Severity.Thresholds
	}
	return &Engine{cfg: w}
}

func defaultWeights() RiskWeights {
	return RiskWeights{
		MaxLikelihood: 5,
		MaxImpact:     5,
		MaxExposure:   3,
		MaxConfidence: 4,
		SeverityThresholds: map[string]float64{
			"critical": 0.50,
			"high":     0.25,
			"medium":   0.10,
		},
	}
}

// Score evaluates a threat event against the organisation context using match results.
func (e *Engine) Score(event model.ThreatEvent, org model.OrgContext, matches []model.Match) ScoreResult {
	var result ScoreResult

	result.Likelihood = e.computeLikelihood(event, matches)
	result.Impact = e.computeImpact(event, org, matches)
	result.Exposure = e.computeExposure(event, org, matches)
	result.Confidence = e.computeConfidence(event, matches)

	riskScore := float64(result.Likelihood*result.Impact*result.Exposure) /
		float64(e.cfg.MaxLikelihood*e.cfg.MaxImpact*e.cfg.MaxExposure)
	result.RiskScore = riskScore

	result.Severity = e.severityLabel(riskScore)
	result.ConfidenceLabel = e.confidenceLabel(result.Confidence)

	ssvc := SSVCTree(event, org, matches)
	result.Action = ssvc.Action
	result.SSVCTrace = ssvc.Trace

	result.Explanation = e.Explain(result, event, matches, org)

	return result
}

func (e *Engine) computeLikelihood(event model.ThreatEvent, matches []model.Match) int {
	score := 0

	for _, m := range matches {
		if m.KEVMatch {
			score += 3
			break
		}
	}
	for _, tag := range event.Tags {
		if tag == "exploit:in-the-wild" {
			if score < 3 {
				score += 3
			}
			break
		}
	}

	for _, tag := range event.Tags {
		if tag == "exploit:weaponized" {
			score += 2
			break
		}
	}

	if len(event.ThreatActors) > 0 {
		score += 1
	}

	if time.Since(event.Timestamp) < 7*24*time.Hour {
		score += 1
	}

	if score > e.cfg.MaxLikelihood {
		score = e.cfg.MaxLikelihood
	}
	if score < 0 {
		score = 0
	}
	return score
}

func (e *Engine) computeImpact(event model.ThreatEvent, org model.OrgContext, matches []model.Match) int {
	score := 0

	if event.CVSS >= 9.0 {
		score += 3
	} else if event.CVSS >= 7.0 {
		score += 2
	} else if event.CVSS >= 4.0 {
		score += 1
	}

	hasCritical := false
	hasHigh := false
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
			}
		}
	}
	if hasCritical {
		score += 2
	} else if hasHigh {
		score += 1
	}

	if score == 0 && len(matches) > 0 {
		score = 1
	}

	hasSensitive := false
	for _, m := range matches {
		if m.AppName == "" {
			continue
		}
		for _, app := range org.TechStack {
			if app.Name == m.AppName && (app.DataSensitivity == "critical" || app.DataSensitivity == "high") {
				hasSensitive = true
			}
		}
	}
	if hasSensitive {
		score += 1
	}

	if score > e.cfg.MaxImpact {
		score = e.cfg.MaxImpact
	}
	return score
}

func (e *Engine) computeExposure(event model.ThreatEvent, org model.OrgContext, matches []model.Match) int {
	score := 0

	hasAnyMatch := false
	for _, m := range matches {
		if m.AppName == "" {
			continue
		}
		for _, app := range org.TechStack {
			if app.Name == m.AppName {
				hasAnyMatch = true
				if app.InternetFacing {
					score += 2
					goto checkCred
				}
			}
		}
	}
checkCred:

	if score == 0 && (hasAnyMatch || len(matches) > 0) {
		score = 1
	}

	for _, tag := range event.Tags {
		if strings.Contains(tag, "phishing") || strings.Contains(tag, "credential") {
			score += 1
			break
		}
	}

	if score > e.cfg.MaxExposure {
		score = e.cfg.MaxExposure
	}
	return score
}

func (e *Engine) computeConfidence(event model.ThreatEvent, matches []model.Match) int {
	score := 0

	switch event.SourceConfidence {
	case "high":
		score += 3
	case "medium":
		score += 2
	case "low":
		score += 0
	default:
		score += 1
	}

	if score < e.cfg.MaxConfidence {
		score += 1
	}

	if score > e.cfg.MaxConfidence {
		score = e.cfg.MaxConfidence
	}
	return score
}

// severityLabel maps a risk score to a severity label using configured thresholds.
func (e *Engine) severityLabel(score float64) string {
	critical := e.cfg.SeverityThresholds["critical"]
	high := e.cfg.SeverityThresholds["high"]
	medium := e.cfg.SeverityThresholds["medium"]

	switch {
	case score >= critical:
		return "critical"
	case score >= high:
		return "high"
	case score >= medium:
		return "medium"
	default:
		return "low"
	}
}

// confidenceLabel maps a confidence score to a label.
func (e *Engine) confidenceLabel(score int) string {
	switch {
	case score >= 3:
		return "HIGH"
	case score >= 2:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// Explain generates a human-readable explanation from the score result.
func (e *Engine) Explain(result ScoreResult, event model.ThreatEvent, matches []model.Match, org model.OrgContext) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("%s (confidence: %s)\n\n", strings.ToUpper(result.Severity), result.ConfidenceLabel))
	b.WriteString(fmt.Sprintf("%s\n\n", event.Title))

	b.WriteString(fmt.Sprintf("Likelihood: %d/%d\n", result.Likelihood, e.cfg.MaxLikelihood))
	for _, m := range matches {
		if m.KEVMatch {
			b.WriteString("  • Active exploitation confirmed by CISA KEV (+3)\n")
		}
	}
	for _, tag := range event.Tags {
		if tag == "exploit:in-the-wild" {
			b.WriteString("  • Active exploitation tag (+3)\n")
		}
		if tag == "exploit:weaponized" {
			b.WriteString("  • Weaponization confirmed (+2)\n")
		}
	}
	if len(event.ThreatActors) > 0 {
		b.WriteString(fmt.Sprintf("  • Threat actor activity: %s (+1)\n", strings.Join(event.ThreatActors, ", ")))
	}
	b.WriteString("  • Recent publication (+1)\n")

	b.WriteString(fmt.Sprintf("\nImpact: %d/%d\n", result.Impact, e.cfg.MaxImpact))
	if event.CVSS >= 9.0 {
		b.WriteString(fmt.Sprintf("  • CVSS %.1f (+3)\n", event.CVSS))
	} else if event.CVSS >= 7.0 {
		b.WriteString(fmt.Sprintf("  • CVSS %.1f (+2)\n", event.CVSS))
	}
	for _, m := range matches {
		if m.AppName != "" {
			for _, app := range org.TechStack {
				if app.Name == m.AppName && app.Criticality == "critical" {
					b.WriteString(fmt.Sprintf("  • %s is critical infrastructure (+2)\n", app.Name))
				}
			}
		}
	}

	b.WriteString(fmt.Sprintf("\nExposure: %d/%d\n", result.Exposure, e.cfg.MaxExposure))
	for _, m := range matches {
		if m.AppName != "" {
			for _, app := range org.TechStack {
				if app.Name == m.AppName && app.InternetFacing {
					b.WriteString(fmt.Sprintf("  • %s is internet-facing (+2)\n", app.Name))
				}
			}
		}
	}

	b.WriteString(fmt.Sprintf("\nConfidence: %d/%d (%s)\n", result.Confidence, e.cfg.MaxConfidence, result.ConfidenceLabel))
	b.WriteString(fmt.Sprintf("  • Source: %s (%s confidence)\n", event.Source, event.SourceConfidence))
	for _, m := range matches {
		if m.KEVMatch {
			b.WriteString("  • CISA KEV confirmed (+3)\n")
		}
	}
	if event.Source == "misp" {
		b.WriteString("  • MISP community trust (+1)\n")
	}
	b.WriteString("  • Default baseline (+1)\n")

	b.WriteString(fmt.Sprintf("\nAction: %s\n", result.Action))
	b.WriteString(fmt.Sprintf("  • SSVC path: %s\n", result.SSVCTrace))

	b.WriteString(fmt.Sprintf("\nScore: (%d × %d × %d) / (%d × %d × %d) = %.2f → %s",
		result.Likelihood, result.Impact, result.Exposure,
		e.cfg.MaxLikelihood, e.cfg.MaxImpact, e.cfg.MaxExposure,
		result.RiskScore, strings.ToUpper(result.Severity)))

	return b.String()
}
