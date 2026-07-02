package source

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/model"
	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/store"
)

// fixtureServer creates an httptest server that serves MISP fixture JSON files.
// It mimics the MISP REST API endpoints that Threat Intel Arbiter uses.
func fixtureServer(t *testing.T) *httptest.Server {
	t.Helper()

	// Load all fixture files into memory
	fixtures := loadFixtures(t, "../testdata")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Accept API key in Authorization header (MISP-style)
		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/events/restSearch" || r.URL.Path == "/events/index":
			// Return all non-deleted events in proper MISP format
			var allItems []json.RawMessage
			for name, data := range fixtures {
				if name == "misp_event_deleted.json" {
					continue
				}
				// Each fixture is {"response": [{...}]} — extract the inner items
				var wrapper struct {
					Response []json.RawMessage `json:"response"`
				}
				if err := json.Unmarshal(data, &wrapper); err != nil {
					continue
				}
				allItems = append(allItems, wrapper.Response...)
			}
			resp := map[string]interface{}{"response": allItems}
			b, _ := json.Marshal(resp)
			w.Write(b)

		case r.URL.Path == "/events/restSearch/deleted":
			// Return deleted events
			if data, ok := fixtures["misp_event_deleted.json"]; ok {
				resp := map[string]interface{}{"response": data}
				b, _ := json.Marshal(resp)
				w.Write(b)
			} else {
				w.Write([]byte(`{"response":[]}`))
			}

		case r.URL.Path == "/warninglists/index":
			w.Write([]byte(`{"response":[]}`))

		case r.URL.Path == "/noticelists/index":
			w.Write([]byte(`{"response":[]}`))

		default:
			http.NotFound(w, r)
		}
	})

	return httptest.NewServer(handler)
}

// loadFixtures reads all JSON fixture files from a directory.
// It tries multiple paths to handle different test execution environments.
func loadFixtures(t *testing.T, relativeDir string) map[string]json.RawMessage {
	t.Helper()

	// Try relative to project root (works with go test ./internal/source/)
	candidates := []string{
		filepath.Join("..", "..", "testdata"),     // from internal/source/
		filepath.Join("testdata"),                   // from project root
	}

	// Also try absolute path from the source file
	_, thisFile, _, _ := runtime.Caller(0)
	srcDir := filepath.Dir(thisFile)
	candidates = append(candidates, filepath.Join(srcDir, "..", "..", "testdata"))

	var absDir string
	for _, d := range candidates {
		resolved, err := filepath.Abs(d)
		if err != nil {
			continue
		}
		if _, err := os.Stat(resolved); err == nil {
			absDir = resolved
			break
		}
	}

	if absDir == "" {
		t.Fatalf("testdata directory not found (tried: %v)", candidates)
	}

	fixtures := make(map[string]json.RawMessage)
	entries, err := os.ReadDir(absDir)
	if err != nil {
		t.Fatalf("read testdata dir %s: %v", absDir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(absDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read fixture %s: %v", path, err)
		}
		fixtures[entry.Name()] = data
	}
	return fixtures
}

func TestMISPClientFetchEvents(t *testing.T) {
	srv := fixtureServer(t)
	defer srv.Close()

	client := NewMISPClient(srv.URL, "test-api-key")
	events, err := client.FetchEvents("", 100)
	if err != nil {
		t.Fatalf("FetchEvents: %v", err)
	}

	if len(events) == 0 {
		t.Fatal("expected events, got none")
	}

	t.Logf("fetched %d events", len(events))
	for _, ev := range events {
		t.Logf("  event: %s — %s", ev.UUID, ev.Info)
	}

	// Verify we got the critical Apache event
	found := false
	for _, ev := range events {
		if ev.UUID == "a1b2c3d4-e5f6-7890-abcd-ef1234567890" {
			found = true
			break
		}
	}
	if !found {
		t.Error("missing critical Apache event (UUID a1b2c3d4...)")
	}
}

func TestNormalizeMISPEvent_CriticalApache(t *testing.T) {
	// Load the critical Apache fixture
	fixtures := loadFixtures(t, "")
	data, ok := fixtures["misp_event_critical_apache.json"]
	if !ok {
		t.Fatal("fixture misp_event_critical_apache.json not found")
	}

	var wrapper struct {
		Response []struct {
			Event MISPEvent `json:"Event"`
		} `json:"response"`
	}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if len(wrapper.Response) == 0 {
		t.Fatal("no events in fixture")
	}

	raw := wrapper.Response[0].Event
	event := NormalizeMISPEvent(raw)

	// Check canonical fields
	if event.ID != "a1b2c3d4-e5f6-7890-abcd-ef1234567890" {
		t.Errorf("ID = %s, want a1b2c3d4...", event.ID)
	}
	if event.Source != "misp" {
		t.Errorf("Source = %s, want misp", event.Source)
	}
	if len(event.CVEs) == 0 {
		t.Error("no CVEs extracted")
	}
	if event.CVSS != 9.8 {
		t.Errorf("CVSS = %.1f, want 9.8", event.CVSS)
	}
	if len(event.Tags) < 3 {
		t.Errorf("Tags = %d, want at least 3", len(event.Tags))
	}
	if len(event.ThreatActors) == 0 {
		t.Error("no threat actors extracted from galaxies")
	}

	// Check specific tags
	hasExploit := false
	hasSector := false
	for _, tag := range event.Tags {
		if tag == "exploit:in-the-wild" {
			hasExploit = true
		}
		if tag == "eu-nis-oes:eu-nis-oes-manufacturing" {
			hasSector = true
		}
	}
	if !hasExploit {
		t.Error("missing exploit:in-the-wild tag")
	}
	if !hasSector {
		t.Error("missing sector tag")
	}

	t.Logf("normalized event: ID=%s CVEs=%v CVSS=%.1f Tags=%d Actors=%v",
		event.ID, event.CVEs, event.CVSS, len(event.Tags), event.ThreatActors)
}

func TestNormalizeMISPEvent_SectorOnly(t *testing.T) {
	fixtures := loadFixtures(t, "")
	data, ok := fixtures["misp_event_sector_actor.json"]
	if !ok {
		t.Fatal("fixture misp_event_sector_actor.json not found")
	}

	var wrapper struct {
		Response []struct {
			Event MISPEvent `json:"Event"`
		} `json:"response"`
	}
	json.Unmarshal(data, &wrapper)
	raw := wrapper.Response[0].Event
	event := NormalizeMISPEvent(raw)

	// This event has NO CVE — CVEs should be empty, threat actor should be present
	if len(event.CVEs) != 0 {
		t.Errorf("expected 0 CVEs, got %v", event.CVEs)
	}
	if len(event.ThreatActors) == 0 {
		t.Error("expected threat actors for sector-only event")
	}
	if event.ThreatActors[0] != "APT41" {
		t.Errorf("threat actor = %s, want APT41", event.ThreatActors[0])
	}

	hasSector := false
	for _, tag := range event.Tags {
		if tag == "eu-nis-oes:eu-nis-oes-manufacturing" {
			hasSector = true
		}
	}
	if !hasSector {
		t.Error("missing sector tag on sector-only event")
	}

	t.Logf("sector-only event: CVEs=%d Actors=%v Tags=%v",
		len(event.CVEs), event.ThreatActors, event.Tags)
}

func TestMISPPoller_FirstRun(t *testing.T) {
	srv := fixtureServer(t)
	defer srv.Close()

	// Open temporary database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	events := make(chan model.ThreatEvent, 100)
	poller := &MISPPoller{
		Client:    NewMISPClient(srv.URL, "test-api-key"),
		DB:        db,
		Events:    events,
		Interval:  15 * time.Minute,
		ColdStart: true,
	}

	// Run one poll (not the loop — just the poll method)
	ctx := t.Context()
	if err := poller.poll(ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}

	// Collect events from the channel (non-blocking)
	var received []model.ThreatEvent
	close(events)
	for ev := range events {
		received = append(received, ev)
		normalized := NormalizeMISPEvent(MISPEvent{
			UUID: ev.ID,
			Info: ev.Title,
		})
		_ = normalized
	}

	t.Logf("poller produced %d events", len(received))

	// We expect at least the non-deleted events
	if len(received) < 4 {
		t.Errorf("expected at least 4 events, got %d", len(received))
	}

	// Verify cursor was set (cold start should become false after first poll)
	if poller.ColdStart {
		t.Error("cold start should be false after first poll")
	}

	// Verify events stored in DB
	var count int
	db.Conn().QueryRow("SELECT COUNT(*) FROM events").Scan(&count)
	t.Logf("events in DB: %d", count)
	if count == 0 {
		t.Error("no events stored in database")
	}
}

func TestMISPPoller_SecondRun_NoColdStart(t *testing.T) {
	srv := fixtureServer(t)
	defer srv.Close()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	events := make(chan model.ThreatEvent, 100)
	poller := &MISPPoller{
		Client:    NewMISPClient(srv.URL, "test-api-key"),
		DB:        db,
		Events:    events,
		Interval:  15 * time.Minute,
		ColdStart: true,
	}

	ctx := t.Context()

	// First poll: cold start
	if err := poller.poll(ctx); err != nil {
		t.Fatalf("first poll: %v", err)
	}
	if poller.ColdStart {
		t.Fatal("cold start should be false after first poll")
	}
	// Drain events
	close(events)
	for range events {
	}

	// Second poll: should NOT cold start
	events2 := make(chan model.ThreatEvent, 100)
	poller.Events = events2

	if err := poller.poll(ctx); err != nil {
		t.Fatalf("second poll: %v", err)
	}
	if poller.ColdStart {
		t.Error("cold start should remain false on second poll")
	}

	// Verify cursor was persisted
	cursor := poller.getCursor()
	if cursor == "" {
		t.Error("cursor should be set after cold start")
	}
	t.Logf("second poll cursor: %s", cursor)
}

func TestMISPPoller_CursorPersistsAcrossRestart(t *testing.T) {
	srv := fixtureServer(t)
	defer srv.Close()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}

	events := make(chan model.ThreatEvent, 100)
	poller := &MISPPoller{
		Client:    NewMISPClient(srv.URL, "test-api-key"),
		DB:        db,
		Events:    events,
		Interval:  15 * time.Minute,
		ColdStart: true,
	}

	ctx := t.Context()

	// First poll: cold start, saves cursor
	if err := poller.poll(ctx); err != nil {
		t.Fatalf("first poll: %v", err)
	}
	close(events)
	for range events {
	}
	db.Close()

	// Simulate restart: reopen DB, new poller with ColdStart=true
	db2, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer db2.Close()

	events2 := make(chan model.ThreatEvent, 100)
	poller2 := &MISPPoller{
		Client:    NewMISPClient(srv.URL, "test-api-key"),
		DB:        db2,
		Events:    events2,
		Interval:  15 * time.Minute,
		ColdStart: true, // main.go always sets this true
	}

	// Run() should detect existing cursor and skip cold start
	// (We test the logic directly since Run() blocks)
	if poller2.ColdStart && poller2.getCursor() != "" {
		poller2.ColdStart = false // this is what Run() does now
	}
	if poller2.ColdStart {
		t.Error("cursor persisted across restart — cold start should be skipped")
	}
	t.Log("cursor persisted across simulated restart")
}

func TestMISPClient_AuthFailure(t *testing.T) {
	// Server that rejects requests without auth
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"response":[]}`))
	}))
	defer srv.Close()

	// Client with no API key
	client := NewMISPClient(srv.URL, "")
	_, err := client.FetchEvents("", 10)
	if err == nil {
		t.Error("expected auth error, got nil")
	}
	t.Logf("auth error (expected): %v", err)
}
