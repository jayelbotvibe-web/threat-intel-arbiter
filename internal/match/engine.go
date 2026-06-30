// Package match provides the pluggable threat matching engine.
// Matchers implement the Matcher interface and are run against every
// ThreatEvent to produce Match results.
package match

import (
	"log"

	"github.com/jayelbotvibe-web/threatlib/internal/model"
)

// Engine runs a set of matchers against each threat event.
type Engine struct {
	matchers []model.Matcher
}

// NewEngine creates a matching engine with the given matchers.
func NewEngine(matchers ...model.Matcher) *Engine {
	return &Engine{matchers: matchers}
}

// Run executes all matchers against a threat event and returns combined results.
func (e *Engine) Run(event model.ThreatEvent, org model.OrgContext) []model.Match {
	var allMatches []model.Match

	for _, m := range e.matchers {
		matches := m.Match(event, org)
		if len(matches) > 0 {
			log.Printf("match: %s produced %d matches for event %s", m.Name(), len(matches), event.ID)
		}
		allMatches = append(allMatches, matches...)
	}

	return allMatches
}

// MatcherNames returns the names of all registered matchers.
func (e *Engine) MatcherNames() []string {
	names := make([]string, len(e.matchers))
	for i, m := range e.matchers {
		names[i] = m.Name()
	}
	return names
}
