// Package store — server-side settings persistence.
//
// Replaces browser localStorage for webhook URLs, API keys, and EDR credentials.
// Secrets are stored in SQLite and never echoed in full to the UI (last 4 chars only).
package store

import (
	"fmt"
	"regexp"
)

// Setting keys used by the settings table.
const (
	SettingSlackWebhook   = "slack_webhook_url"
	SettingTeamsWebhook   = "teams_webhook_url"
	SettingEmailTarget    = "email_target"
	SettingCSClientID     = "cs_client_id"
	SettingCSSecret       = "cs_secret"
	SettingCSBaseURL      = "cs_base_url"
	SettingAdminKeyMasked = "admin_key_masked"
)

// secretKeyPattern matches setting keys whose values are always masked.
// Covers webhook URLs, tokens, keys, secrets, passwords, and API keys.
var secretKeyPattern = regexp.MustCompile(`(?i)(webhook|token|key|secret|password|api_key)`)

// GetSetting reads a single setting value. Returns empty string if not found.
func (db *DB) GetSetting(key string) (string, error) {
	var value string
	err := db.conn.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&value)
	if err != nil {
		// sql.ErrNoRows is fine — return empty
		return "", nil
	}
	return value, nil
}

// SetSetting writes a setting value (upsert).
func (db *DB) SetSetting(key, value string) error {
	_, err := db.conn.Exec(
		"INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
		key, value,
	)
	if err != nil {
		return fmt.Errorf("set setting %s: %w", key, err)
	}
	return nil
}

// GetAllSettings returns all settings as a map.
func (db *DB) GetAllSettings() (map[string]string, error) {
	rows, err := db.conn.Query("SELECT key, value FROM settings ORDER BY key")
	if err != nil {
		return nil, fmt.Errorf("query settings: %w", err)
	}
	defer rows.Close()

	out := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// GetMaskedSetting returns a setting value with secrets masked (last 4 chars).
func (db *DB) GetMaskedSetting(key string) (string, error) {
	v, err := db.GetSetting(key)
	if err != nil {
		return "", err
	}
	return maskValue(key, v), nil
}

// GetAllSettingsMasked returns all settings with secret values masked.
func (db *DB) GetAllSettingsMasked() (map[string]string, error) {
	all, err := db.GetAllSettings()
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(all))
	for k, v := range all {
		out[k] = maskValue(k, v)
	}
	return out, nil
}

// SeedSetting sets a setting only if it doesn't already exist (first-run seed).
func (db *DB) SeedSetting(key, value string) error {
	if value == "" {
		return nil
	}
	existing, _ := db.GetSetting(key)
	if existing != "" {
		return nil // already set, don't overwrite
	}
	return db.SetSetting(key, value)
}

// isSecretKey returns true if the key name indicates a secret value
// (webhook URLs, tokens, keys, secrets, passwords, API keys).
func isSecretKey(key string) bool {
	return secretKeyPattern.MatchString(key)
}

// maskValue returns a masked version for secret keys. Non-secret keys are
// returned as-is. Empty values stay empty (nil mask reveals existence).
func maskValue(key, value string) string {
	if value == "" {
		return ""
	}
	if isSecretKey(key) {
		if len(value) <= 4 {
			return "****"
		}
		return "****" + value[len(value)-4:]
	}
	return value
}
