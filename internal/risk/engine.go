// Package risk provides the threat prioritization engine.
// It computes severity and confidence using four dimensions:
// Likelihood, Impact, Exposure, and Confidence.
//
// Formula: risk_score = (L × I × E) / (maxL × maxI × maxE)
// Output: severity label + confidence label + explanation
package risk

import (
	"fmt"
	"strings"
	"time"

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

// Contribution is a single (reason, delta) factor that fed a dimension score.
// The dimension score is the capped sum of its contributions, and the
// human-readable explanation is rendered from these same values — so the
// breakdown always reconciles with the number it explains.
type Contribution struct {
	Reason string `json:"reason"`
	Delta  int    `json:"delta"`
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

	// Per-dimension factors — the single source of truth that both the
	// dimension score and the explanation are derived from.
	LikelihoodFactors []Contribution `json:"likelihood_factors"`
	ImpactFactors     []Contribution `json:"impact_factors"`
	ExposureFactors   []Contribution `json:"exposure_factors"`
	ConfidenceFactors []Contribution `json:"confidence_factors"`
}

// sumCapped sums a dimension's contributions and clamps to [0, max].
func sumCapped(factors []Contribution, max int) int {
	s := 0
	for _, f := range factors {
		s += f.Delta
	}
	if s > max {
		s = max
	}
	if s < 0 {
		s = 0
	}
	return s
}

// rawSum returns the uncapped sum, used to disclose when a cap was applied.
func rawSum(factors []Contribution) int {
	s := 0
	for _, f := range factors {
		s += f.Delta
	}
	return s
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

	result.LikelihoodFactors = e.likelihoodFactors(event, matches)
	result.ImpactFactors = e.impactFactors(event, org, matches)
	result.ExposureFactors = e.exposureFactors(event, org, matches)
	result.ConfidenceFactors = e.confidenceFactors(event, matches)

	result.Likelihood = sumCapped(result.LikelihoodFactors, e.cfg.MaxLikelihood)
	result.Impact = sumCapped(result.ImpactFactors, e.cfg.MaxImpact)
	result.Exposure = sumCapped(result.ExposureFactors, e.cfg.MaxExposure)
	result.Confidence = sumCapped(result.ConfidenceFactors, e.cfg.MaxConfidence)

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

// likelihoodFactors returns the contributions that make up the likelihood
// dimension. Each entry was actually applied, so the list reconciles with
// sumCapped(...) exactly (barring the disclosed cap).
func (e *Engine) likelihoodFactors(event model.ThreatEvent, matches []model.Match) []Contribution {
	var f []Contribution

	kev := false
	for _, m := range matches {
		if m.KEVMatch {
			f = append(f, Contribution{"Active exploitation confirmed by CISA KEV", 3})
			kev = true
			break
		}
	}
	// exploit:in-the-wild only counts when KEV did not already establish active
	// exploitation (avoids double-counting the same signal).
	if !kev {
		for _, tag := range event.Tags {
			if tag == "exploit:in-the-wild" {
				f = append(f, Contribution{"Active exploitation tag (exploit:in-the-wild)", 3})
				break
			}
		}
	}
	for _, tag := range event.Tags {
		if tag == "exploit:weaponized" {
			f = append(f, Contribution{"Weaponization confirmed (exploit:weaponized)", 2})
			break
		}
	}
	if len(event.ThreatActors) > 0 {
		f = append(f, Contribution{"Threat actor activity: " + strings.Join(event.ThreatActors, ", "), 1})
	}
	if time.Since(event.Timestamp) < 7*24*time.Hour {
		f = append(f, Contribution{"Recent publication (within 7 days)", 1})
	}
	return f
}

func (e *Engine) impactFactors(event model.ThreatEvent, org model.OrgContext, matches []model.Match) []Contribution {
	var f []Contribution

	switch {
	case event.CVSS >= 9.0:
		f = append(f, Contribution{fmt.Sprintf("CVSS %.1f (critical)", event.CVSS), 3})
	case event.CVSS >= 7.0:
		f = append(f, Contribution{fmt.Sprintf("CVSS %.1f (high)", event.CVSS), 2})
	case event.CVSS >= 4.0:
		f = append(f, Contribution{fmt.Sprintf("CVSS %.1f (medium)", event.CVSS), 1})
	}

	hasCritical, hasHigh := false, false
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
		f = append(f, Contribution{"Matched a critical-infrastructure asset", 2})
	} else if hasHigh {
		f = append(f, Contribution{"Matched a high-criticality asset", 1})
	}

	// Baseline: a matched asset carries at least some impact even without a
	// CVSS or criticality signal.
	if rawSum(f) == 0 && len(matches) > 0 {
		f = append(f, Contribution{"Matched asset in tech stack (baseline)", 1})
	}

	for _, m := range matches {
		if m.AppName == "" {
			continue
		}
		for _, app := range org.TechStack {
			if app.Name == m.AppName && (app.DataSensitivity == "critical" || app.DataSensitivity == "high") {
				f = append(f, Contribution{"Matched asset handles sensitive data", 1})
				return f
			}
		}
	}
	return f
}

func (e *Engine) exposureFactors(event model.ThreatEvent, org model.OrgContext, matches []model.Match) []Contribution {
	var f []Contribution

	hasAnyMatch, internetFacing := false, false
	for _, m := range matches {
		if m.AppName == "" {
			continue
		}
		for _, app := range org.TechStack {
			if app.Name == m.AppName {
				hasAnyMatch = true
				if app.InternetFacing {
					internetFacing = true
				}
			}
		}
	}
	if internetFacing {
		f = append(f, Contribution{"Matched asset is internet-facing", 2})
	} else if hasAnyMatch || len(matches) > 0 {
		f = append(f, Contribution{"Matched asset in tech stack (baseline)", 1})
	}

	for _, tag := range event.Tags {
		if strings.Contains(tag, "phishing") || strings.Contains(tag, "credential") {
			f = append(f, Contribution{"Phishing/credential-theft vector", 1})
			break
		}
	}
	return f
}

func (e *Engine) confidenceFactors(event model.ThreatEvent, matches []model.Match) []Contribution {
	var f []Contribution

	switch event.SourceConfidence {
	case "high":
		f = append(f, Contribution{"Source confidence: high", 3})
	case "medium":
		f = append(f, Contribution{"Source confidence: medium", 2})
	case "low":
		// contributes nothing
	default:
		f = append(f, Contribution{"Source confidence: unspecified", 1})
	}

	// Baseline bump, matching the original model: applied only while the running
	// total is below the cap.
	if rawSum(f) < e.cfg.MaxConfidence {
		f = append(f, Contribution{"Baseline reliability", 1})
	}
	return f
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
// It renders the same Contribution lists that produced each dimension score,
// so the "+N" factors always reconcile with the number they explain.
func (e *Engine) Explain(result ScoreResult, event model.ThreatEvent, matches []model.Match, org model.OrgContext) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("%s (confidence: %s)\n\n", strings.ToUpper(result.Severity), result.ConfidenceLabel))
	b.WriteString(fmt.Sprintf("%s\n\n", event.Title))

	writeDimension(&b, "Likelihood", result.Likelihood, e.cfg.MaxLikelihood, result.LikelihoodFactors)
	b.WriteString("\n")
	writeDimension(&b, "Impact", result.Impact, e.cfg.MaxImpact, result.ImpactFactors)
	b.WriteString("\n")
	writeDimension(&b, "Exposure", result.Exposure, e.cfg.MaxExposure, result.ExposureFactors)
	b.WriteString("\n")
	writeDimension(&b, fmt.Sprintf("Confidence (%s)", result.ConfidenceLabel),
		result.Confidence, e.cfg.MaxConfidence, result.ConfidenceFactors)

	b.WriteString(fmt.Sprintf("\nAction: %s\n", result.Action))
	b.WriteString(fmt.Sprintf("  • SSVC path: %s\n", result.SSVCTrace))

	b.WriteString(fmt.Sprintf("\nScore: (%d × %d × %d) / (%d × %d × %d) = %.2f → %s",
		result.Likelihood, result.Impact, result.Exposure,
		e.cfg.MaxLikelihood, e.cfg.MaxImpact, e.cfg.MaxExposure,
		result.RiskScore, strings.ToUpper(result.Severity)))

	return b.String()
}

// writeDimension renders one dimension: its score, each contributing factor
// with its delta, and — when the raw factor sum exceeds the cap — a note
// disclosing that the score was capped. This keeps the breakdown honest.
func writeDimension(b *strings.Builder, name string, score, max int, factors []Contribution) {
	b.WriteString(fmt.Sprintf("%s: %d/%d\n", name, score, max))
	if len(factors) == 0 {
		b.WriteString("  • No contributing factors\n")
		return
	}
	for _, f := range factors {
		b.WriteString(fmt.Sprintf("  • %s (%+d)\n", f.Reason, f.Delta))
	}
	if raw := rawSum(factors); raw > max {
		b.WriteString(fmt.Sprintf("  • (factors sum to %d, capped at %d)\n", raw, max))
	}
}
