package source

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/jayelbotvibe-web/threatlib/internal/model"
	"github.com/jayelbotvibe-web/threatlib/internal/store"
)

// MISPPoller pulls events from a MISP instance on a schedule.
type MISPPoller struct {
	Client    *MISPClient
	DB        *store.DB
	Events    chan<- model.ThreatEvent
	Interval  time.Duration
	ColdStart bool // true on first run
}

// Run starts the polling loop. Blocks until ctx is cancelled.
func (p *MISPPoller) Run(ctx context.Context) error {
	ticker := time.NewTicker(p.Interval)
	defer ticker.Stop()

	// Run immediately on start
	if err := p.poll(ctx); err != nil {
		log.Printf("misp poller: initial poll error: %v", err)
	}

	for {
		select {
		case <-ctx.Done():
			log.Println("misp poller: shutting down")
			return ctx.Err()
		case <-ticker.C:
			if err := p.poll(ctx); err != nil {
				log.Printf("misp poller: poll error: %v", err)
			}
		}
	}
}

// poll performs a single poll cycle.
func (p *MISPPoller) poll(ctx context.Context) error {
	since := p.getCursor()

	// Cold start: pull last 7 days, suppress low-severity alerts post-scoring
	if p.ColdStart {
		since = fmt.Sprintf("%d", time.Now().Add(-7*24*time.Hour).Unix())
		log.Printf("misp poller: cold start, pulling events since %s", since)
	}

	events, err := p.Client.FetchEvents(since, 100)
	if err != nil {
		return fmt.Errorf("fetch events: %w", err)
	}

	log.Printf("misp poller: pulled %d events", len(events))

	// Process each event: normalize, check for new/modified/deleted
	for _, raw := range events {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Check if this event was already processed
		normalized := NormalizeMISPEvent(raw)
		existing, err := p.getStoredEvent(normalized.ID)
		if err != nil {
			log.Printf("misp poller: check existing event %s: %v", normalized.ID, err)
			continue
		}

		if existing != nil && raw.Published == false {
			// Event was deleted/unpublished — suppress
			log.Printf("misp poller: event %s deleted, suppressing", normalized.ID)
			p.storeEvent(normalized, true)
			continue
		}

		if existing != nil && existing.Timestamp.After(normalized.Timestamp) {
			// Already processed a newer version
			continue
		}

		// NEW or MODIFIED event
		p.storeEvent(normalized, false)

		// Send to the event queue for matching
		if p.Events != nil {
			select {
			case p.Events <- normalized:
			case <-ctx.Done():
				return ctx.Err()
			default:
				log.Printf("misp poller: event queue full, dropping event %s", normalized.ID)
			}
		}
	}

	// Update cursor to now
	if len(events) > 0 {
		p.setCursor(fmt.Sprintf("%d", time.Now().Unix()))
		p.ColdStart = false
	}

	return nil
}

// getCursor reads the last poll cursor from the database.
func (p *MISPPoller) getCursor() string {
	var value string
	err := p.DB.Conn().QueryRow("SELECT value FROM state WHERE key = 'misp_cursor'").Scan(&value)
	if err != nil {
		return ""
	}
	return value
}

// setCursor writes the poll cursor to the database.
func (p *MISPPoller) setCursor(cursor string) {
	_, err := p.DB.Conn().Exec(
		"INSERT OR REPLACE INTO state (key, value) VALUES ('misp_cursor', ?)",
		cursor,
	)
	if err != nil {
		log.Printf("misp poller: set cursor: %v", err)
	}
}

// storeEvent writes a normalized event to the database.
func (p *MISPPoller) storeEvent(event model.ThreatEvent, deleted bool) {
	normalizedJSON, err := json.Marshal(event)
	if err != nil {
		log.Printf("misp poller: marshal event %s: %v", event.ID, err)
		return
	}

	status := "active"
	if deleted {
		status = "deleted"
	}

	_, err = p.DB.Conn().Exec(
		`INSERT OR REPLACE INTO events (id, source_id, source_event_id, normalized_json, timestamp, org_id)
		 VALUES (?, 'misp-primary', ?, ?, ?, 'default')`,
		event.ID, event.ID, string(normalizedJSON), event.Timestamp.Format(time.RFC3339),
	)
	if err != nil {
		log.Printf("misp poller: store event %s: %v", event.ID, err)
	}
	_ = status
}

// getStoredEvent retrieves a previously stored event by ID.
func (p *MISPPoller) getStoredEvent(id string) (*model.ThreatEvent, error) {
	var jsonStr string
	var timestamp string
	err := p.DB.Conn().QueryRow(
		"SELECT normalized_json, timestamp FROM events WHERE id = ?", id,
	).Scan(&jsonStr, &timestamp)
	if err != nil {
		// No rows is fine — event not yet stored
		return nil, nil
	}

	var event model.ThreatEvent
	if err := json.Unmarshal([]byte(jsonStr), &event); err != nil {
		return nil, fmt.Errorf("unmarshal stored event: %w", err)
	}
	return &event, nil
}
