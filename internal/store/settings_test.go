package store

import (
	"testing"
)

func TestSettings_CRUD(t *testing.T) {
	db := openTestDB(t)

	// Get non-existent key returns empty
	v, err := db.GetSetting("nonexistent")
	if err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	if v != "" {
		t.Errorf("expected empty, got %q", v)
	}

	// Set + get
	if err := db.SetSetting("test_key", "test_value"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	v, err = db.GetSetting("test_key")
	if err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	if v != "test_value" {
		t.Errorf("expected 'test_value', got %q", v)
	}

	// Overwrite
	if err := db.SetSetting("test_key", "updated"); err != nil {
		t.Fatalf("SetSetting overwrite: %v", err)
	}
	v, _ = db.GetSetting("test_key")
	if v != "updated" {
		t.Errorf("expected 'updated', got %q", v)
	}
}

func TestSettings_SeedSetting(t *testing.T) {
	db := openTestDB(t)

	// Seed: first write succeeds
	if err := db.SeedSetting("seed_key", "first"); err != nil {
		t.Fatalf("SeedSetting: %v", err)
	}
	v, _ := db.GetSetting("seed_key")
	if v != "first" {
		t.Errorf("expected 'first', got %q", v)
	}

	// Seed: second write is no-op (value already set)
	if err := db.SeedSetting("seed_key", "second"); err != nil {
		t.Fatalf("SeedSetting: %v", err)
	}
	v, _ = db.GetSetting("seed_key")
	if v != "first" {
		t.Errorf("SeedSetting overwrote existing: expected 'first', got %q", v)
	}
}

func TestSettings_Masking(t *testing.T) {
	// Secret keys are masked
	masked := maskValue(SettingCSSecret, "super-secret-password-1234")
	if masked != "****1234" {
		t.Errorf("secret masking: got %q, want ****1234", masked)
	}

	// Short secret
	masked = maskValue(SettingCSSecret, "abc")
	if masked != "****" {
		t.Errorf("short secret masking: got %q, want ****", masked)
	}

	// Non-secret keys pass through
	clear := maskValue(SettingSlackWebhook, "https://hooks.slack.com/xyz")
	if clear != "https://hooks.slack.com/xyz" {
		t.Errorf("non-secret masked incorrectly: got %q", clear)
	}

	// Empty values stay empty
	empty := maskValue(SettingCSSecret, "")
	if empty != "" {
		t.Errorf("empty secret should stay empty, got %q", empty)
	}
}

func TestSettings_GetAllMasked(t *testing.T) {
	db := openTestDB(t)

	db.SetSetting(SettingSlackWebhook, "https://hooks.slack.com/TEST123")
	db.SetSetting(SettingCSSecret, "my-cs-secret-5678")

	all, err := db.GetAllSettingsMasked()
	if err != nil {
		t.Fatalf("GetAllSettingsMasked: %v", err)
	}

	if all[SettingSlackWebhook] != "https://hooks.slack.com/TEST123" {
		t.Errorf("webhook should not be masked: %q", all[SettingSlackWebhook])
	}
	if all[SettingCSSecret] != "****5678" {
		t.Errorf("secret should be masked: %q", all[SettingCSSecret])
	}
}

// openTestDB creates an in-memory SQLite database for tests.
func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}
