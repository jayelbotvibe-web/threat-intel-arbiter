// Package store provides SQLite database access for threatlib.
// Uses modernc.org/sqlite (pure Go, no CGO).
package store

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// DB wraps the SQLite connection.
type DB struct {
	conn *sql.DB
}

// Open opens (or creates) the SQLite database at the given path
// and runs any pending migrations.
func Open(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}

	db := &DB{conn: conn}
	if err := db.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return db, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	return db.conn.Close()
}

// migrate runs schema migrations.
func (db *DB) migrate() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS sources (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			name TEXT NOT NULL,
			confidence TEXT NOT NULL DEFAULT 'medium',
			config_json TEXT NOT NULL DEFAULT '{}',
			enabled INTEGER NOT NULL DEFAULT 1
		)`,

		`CREATE TABLE IF NOT EXISTS events (
			id TEXT PRIMARY KEY,
			source_id TEXT NOT NULL REFERENCES sources(id),
			source_event_id TEXT NOT NULL,
			normalized_json TEXT NOT NULL,
			timestamp TEXT NOT NULL,
			org_id TEXT NOT NULL DEFAULT 'default'
		)`,

		`CREATE TABLE IF NOT EXISTS alerts (
			id TEXT PRIMARY KEY,
			event_id TEXT NOT NULL REFERENCES events(id),
			severity TEXT NOT NULL,
			confidence TEXT NOT NULL,
			explanation TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'new',
			matched_apps TEXT NOT NULL DEFAULT '[]',
			routed_to TEXT NOT NULL DEFAULT '[]',
			created_at TEXT NOT NULL,
			acknowledged_at TEXT,
			resolved_at TEXT,
			org_id TEXT NOT NULL DEFAULT 'default'
		)`,

		`CREATE TABLE IF NOT EXISTS tech_stack (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			version TEXT NOT NULL DEFAULT '',
			vendor TEXT NOT NULL DEFAULT '',
			category TEXT NOT NULL DEFAULT '',
			criticality TEXT NOT NULL DEFAULT 'medium',
			owner_team TEXT NOT NULL DEFAULT '',
			internet_facing INTEGER NOT NULL DEFAULT 0,
			hosts TEXT NOT NULL DEFAULT '',
			data_sensitivity TEXT NOT NULL DEFAULT 'medium',
			org_id TEXT NOT NULL DEFAULT 'default'
		)`,

		`CREATE TABLE IF NOT EXISTS routing_rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			priority INTEGER NOT NULL DEFAULT 0,
			severity TEXT NOT NULL,
			confidence_levels TEXT NOT NULL,
			channels TEXT NOT NULL,
			slack_channel TEXT NOT NULL DEFAULT '',
			email_to TEXT NOT NULL DEFAULT '',
			format TEXT NOT NULL DEFAULT 'realtime',
			org_id TEXT NOT NULL DEFAULT 'default'
		)`,

		`CREATE TABLE IF NOT EXISTS risk_config (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			config_json TEXT NOT NULL,
			org_id TEXT NOT NULL DEFAULT 'default'
		)`,

		`CREATE TABLE IF NOT EXISTS matchers_config (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			config_json TEXT NOT NULL,
			org_id TEXT NOT NULL DEFAULT 'default'
		)`,

		`CREATE TABLE IF NOT EXISTS dedup_hashes (
			hash TEXT PRIMARY KEY,
			created_at TEXT NOT NULL
		)`,

		`CREATE TABLE IF NOT EXISTS sighting_cache (
			cve TEXT PRIMARY KEY,
			count INTEGER NOT NULL DEFAULT 0,
			updated_at TEXT NOT NULL
		)`,

		`CREATE TABLE IF NOT EXISTS notification_targets (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			name TEXT NOT NULL,
			config_json TEXT NOT NULL DEFAULT '{}',
			enabled INTEGER NOT NULL DEFAULT 1,
			org_id TEXT NOT NULL DEFAULT 'default'
		)`,

		`CREATE TABLE IF NOT EXISTS state (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,

		// Indexes
		`CREATE INDEX IF NOT EXISTS idx_events_source ON events(source_id)`,
		`CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)`,
		`CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_dedup_created ON dedup_hashes(created_at)`,
	}

	for i, m := range migrations {
		if _, err := db.conn.Exec(m); err != nil {
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
	}
	return nil
}

// Conn returns the underlying database connection for direct queries.
func (db *DB) Conn() *sql.DB {
	return db.conn
}
