package store

import (
	"testing"
	"time"

	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/model"
)

// TestSaveAlert_PersistsSSVCAction guards the fix for the dropped SSVC action:
// the INSERT previously omitted the action column, so every alert read back as
// the default (Track) and the dashboard's Act/Attend buckets were always empty.
func TestSaveAlert_PersistsSSVCAction(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	alert := model.Alert{
		ID:          "alert-act-1",
		EventID:     "CVE-2024-3400",
		Severity:    "critical",
		Confidence:  "high",
		Action:      "Act",
		Explanation: "exploited + exposed",
		Status:      "new",
		CreatedAt:   time.Now().Format(time.RFC3339),
	}
	saved, err := db.SaveAlert(alert, time.Hour)
	if err != nil || !saved {
		t.Fatalf("SaveAlert saved=%v err=%v", saved, err)
	}

	var action string
	if err := db.conn.QueryRow("SELECT action FROM alerts WHERE id = ?", alert.ID).Scan(&action); err != nil {
		t.Fatalf("read action back: %v", err)
	}
	if action != "Act" {
		t.Errorf("persisted action = %q, want \"Act\"", action)
	}
}

// TestSuppressAlertsForEvent_ReturnsError confirms the suppress call now
// surfaces success/failure instead of silently swallowing it.
func TestSuppressAlertsForEvent_ReturnsError(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := db.SuppressAlertsForEvent("no-such-event"); err != nil {
		t.Errorf("SuppressAlertsForEvent returned error on valid no-op: %v", err)
	}
}
