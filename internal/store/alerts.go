package store

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/jayelbotvibe-web/threatlib/internal/model"
)

// SaveAlert stores an alert in the database. Returns false if the alert
// was suppressed by deduplication (same hash within TTL).
func (db *DB) SaveAlert(alert model.Alert, ttl time.Duration) (bool, error) {
	// Check dedup
	cutoff := time.Now().Add(-ttl).Format(time.RFC3339)
	var count int
	err := db.conn.QueryRow(
		"SELECT COUNT(*) FROM dedup_hashes WHERE hash = ? AND created_at > ?",
		alert.ID, cutoff,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("dedup check: %w", err)
	}
	if count > 0 {
		return false, nil // suppressed
	}

	// Store dedup hash
	_, err = db.conn.Exec(
		"INSERT OR REPLACE INTO dedup_hashes (hash, created_at) VALUES (?, ?)",
		alert.ID, time.Now().Format(time.RFC3339),
	)
	if err != nil {
		return false, fmt.Errorf("insert dedup hash: %w", err)
	}

	// Store alert
	matchedJSON, _ := json.Marshal(alert.MatchedApps)
	routedJSON, _ := json.Marshal(alert.RoutedTo)

	_, err = db.conn.Exec(
		`INSERT OR REPLACE INTO alerts
		(id, event_id, severity, confidence, explanation, status, matched_apps, routed_to, created_at, org_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'default')`,
		alert.ID, alert.EventID, alert.Severity, alert.Confidence,
		alert.Explanation, alert.Status,
		string(matchedJSON), string(routedJSON),
		alert.CreatedAt,
	)
	if err != nil {
		return false, fmt.Errorf("insert alert: %w", err)
	}

	return true, nil
}

// CleanDedup removes expired dedup hashes.
func (db *DB) CleanDedup(ttl time.Duration) error {
	cutoff := time.Now().Add(-ttl).Format(time.RFC3339)
	_, err := db.conn.Exec("DELETE FROM dedup_hashes WHERE created_at < ?", cutoff)
	return err
}
