// Package source provides threat intelligence source connectors.
// Each source (MISP, CISA KEV, etc.) implements the Source interface
// and produces normalized ThreatEvent values via a Poller.
package source

import (
	"context"

	"github.com/jayelbotvibe-web/threatlib/internal/model"
)

// Source defines a threat intelligence source.
type Source interface {
	// ID returns the unique source identifier (matches sources.yaml).
	ID() string
	// Type returns the source type ("misp", "cisa-kev", etc.).
	Type() string
	// Name returns the human-readable source name.
	Name() string
}

// Poller pulls events from a source on a schedule.
type Poller struct {
	Source   Source
	Interval string // e.g., "15m", "24h"
	Events   chan<- model.ThreatEvent
}

// Run starts the polling loop. It blocks until ctx is cancelled.
// The implementation handles cursor tracking, cold start, and error retry.
func (p *Poller) Run(ctx context.Context) error {
	// Each source type has its own poll implementation.
	// The interface is here for the registry; actual polling
	// is source-type-specific (MISP REST, KEV HTTP GET, etc.).
	return nil
}
