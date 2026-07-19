package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/store"
)

// newTestServer creates a test server with a temporary database.
func newTestServer(t *testing.T) (*Server, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	srv := NewServer(db, tmpDir, "test-admin-key")
	return srv, func() { db.Close() }
}

// loginHelper performs a login request and returns the session cookie.
func loginHelper(t *testing.T, srv *Server, username, password string) string {
	t.Helper()
	body := strings.NewReader(`{"username":"` + username + `","password":"` + password + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("login failed: %d — %s", w.Code, w.Body.String())
	}

	cookies := w.Result().Cookies()
	for _, c := range cookies {
		if c.Name == "arbiter_session" {
			return c.Value
		}
	}
	t.Fatal("no arbiter_session cookie in login response")
	return ""
}

// TestDeletedUserSessionRejected verifies that a deleted user's session is rejected.
func TestDeletedUserSessionRejected(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	// Create a user, login, delete the user, then try accessing a protected endpoint
	password := "testpass123"
	if err := srv.DB.CreateUser("test-user", password, "reader"); err != nil {
		t.Fatalf("create user: %v", err)
	}

	sessionCookie := loginHelper(t, srv, "test-user", password)

	// Verify session works before deletion
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.AddCookie(&http.Cookie{Name: "arbiter_session", Value: sessionCookie})
	w := httptest.NewRecorder()
	srv.Mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("session should work before deletion, got %d", w.Code)
	}

	// Delete the user (simulate admin action)
	if err := srv.DB.DeleteUser("test-user"); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	srv.DB.DeleteSessionsForUser("test-user")

	// Now try accessing with the old session cookie
	req2 := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req2.AddCookie(&http.Cookie{Name: "arbiter_session", Value: sessionCookie})
	w2 := httptest.NewRecorder()
	srv.Mux.ServeHTTP(w2, req2)

	if w2.Code == http.StatusOK {
		t.Error("deleted user's session should be rejected, got 200 OK")
	}
	t.Logf("deleted user session returned %d (expected 401)", w2.Code)
}

// TestDemotedAdminLosesAdminEndpoints verifies that a demoted admin cannot
// access admin endpoints with their old session.
func TestDemotedAdminLosesAdminEndpoints(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	password := "adminpass123"
	if err := srv.DB.CreateUser("power-user", password, "admin"); err != nil {
		t.Fatalf("create user: %v", err)
	}

	sessionCookie := loginHelper(t, srv, "power-user", password)

	// Verify admin access works
	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	req.AddCookie(&http.Cookie{Name: "arbiter_session", Value: sessionCookie})
	w := httptest.NewRecorder()
	srv.Mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("admin should access /admin/users, got %d", w.Code)
	}

	// Demote to reader and invalidate sessions
	if err := srv.DB.UpdateUser("power-user", "", "reader"); err != nil {
		t.Fatalf("update user: %v", err)
	}
	srv.DB.DeleteSessionsForUser("power-user")

	// Old session should now fail (session deleted from DB)
	req2 := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	req2.AddCookie(&http.Cookie{Name: "arbiter_session", Value: sessionCookie})
	w2 := httptest.NewRecorder()
	srv.Mux.ServeHTTP(w2, req2)

	if w2.Code != http.StatusUnauthorized && w2.Code != http.StatusForbidden {
		t.Errorf("demoted admin should get 401/403 on admin endpoint, got %d", w2.Code)
	}
	t.Logf("demoted admin session returned %d (expected 401 or 403)", w2.Code)

	// Login again with new role — should get reader privileges
	sessionCookie2 := loginHelper(t, srv, "power-user", password)

	// Reader hitting admin endpoint should get 403
	req3 := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	req3.AddCookie(&http.Cookie{Name: "arbiter_session", Value: sessionCookie2})
	w3 := httptest.NewRecorder()
	srv.Mux.ServeHTTP(w3, req3)

	if w3.Code != http.StatusForbidden {
		t.Errorf("reader should get 403 on admin endpoint, got %d", w3.Code)
	}
	t.Logf("reader hitting /admin/users returned %d (expected 403)", w3.Code)
}

// minimizeJSON removes whitespace from JSON for readable test output.
func minimizeJSON(s string) string {
	var v interface{}
	json.Unmarshal([]byte(s), &v)
	b, _ := json.Marshal(v)
	return string(b)
}

// TestReaderSettingsMasksWebhooks verifies that webhook URLs and other
// bearer credentials are masked in /api/settings responses.
func TestReaderSettingsMasksWebhooks(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	// Seed settings with secrets
	srv.DB.SetSetting(store.SettingSlackWebhook, "https://hooks.slack.com/services/TEST/B123/abc123xyz")
	srv.DB.SetSetting(store.SettingTeamsWebhook, "https://example.webhook.office.com/webhookb2/test")
	srv.DB.SetSetting(store.SettingCSSecret, "super-secret-api-key-12345")
	srv.DB.SetSetting(store.SettingCSClientID, "client-id-abcdef")
	srv.DB.SetSetting(store.SettingEmailTarget, "soc@example.com") // not a secret

	// Create reader user and login
	password := "readerpass"
	srv.DB.CreateUser("reader-user", password, "reader")
	cookie := loginHelper(t, srv, "reader-user", password)

	// GET /api/settings as reader
	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	req.AddCookie(&http.Cookie{Name: "arbiter_session", Value: cookie})
	w := httptest.NewRecorder()
	srv.Mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("settings GET returned %d", w.Code)
	}

	var resp struct {
		Settings map[string]string `json:"settings"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	// Slack webhook URL should be masked (it's a webhook = bearer credential)
	if slack, ok := resp.Settings[store.SettingSlackWebhook]; ok {
		if strings.Contains(slack, "hooks.slack.com") {
			t.Errorf("slack webhook URL leaked in reader response: %s", slack)
		}
		t.Logf("slack webhook: %s (expected masked)", slack)
	}

	// Teams webhook URL should be masked
	if teams, ok := resp.Settings[store.SettingTeamsWebhook]; ok {
		if strings.Contains(teams, "webhook.office.com") {
			t.Errorf("teams webhook URL leaked in reader response: %s", teams)
		}
		t.Logf("teams webhook: %s (expected masked)", teams)
	}

	// CS secret should be masked
	if csSecret, ok := resp.Settings[store.SettingCSSecret]; ok {
		if strings.Contains(csSecret, "super-secret") {
			t.Errorf("CS secret leaked in reader response: %s", csSecret)
		}
		t.Logf("cs_secret: %s (expected masked)", csSecret)
	}

	// CS client ID should be masked (matches 'key' or 'id' pattern? — actually 'client_id' contains no secret keyword)
	// per the regex (?i)(webhook|token|key|secret|password|api_key), 'client_id' does NOT match
	// but 'cs_client_id' DOES contain 'id'... wait, the regex is for the setting KEY name, not value
	// 'cs_client_id' — does it match? Let's check: 'client_id' — contains... no it doesn't contain
	// webhook, token, key, secret, password, or api_key. So it should NOT be masked.
	// Actually 'cs_client_id' does NOT match the pattern. That's fine per spec.

	// Email target should NOT be masked (it's not a secret key)
	if email, ok := resp.Settings[store.SettingEmailTarget]; ok {
		if email != "soc@example.com" {
			t.Errorf("email target incorrectly masked: %s", email)
		}
		t.Logf("email_target: %s (expected unmasked)", email)
	}
}

// TestRateLimiterEviction verifies that the rate limiter's background evictor
// prunes stale keys to prevent memory-exhaustion DoS from attacker-controlled
// username/IP flooding.
func TestRateLimiterEviction(t *testing.T) {
	rl := newRateLimiter()

	// Inject many distinct keys with old timestamps
	oldTime := time.Now().Add(-10 * time.Minute) // well outside the 5m window
	rl.mu.Lock()
	for i := 0; i < 500; i++ {
		key := "user:attacker-" + fmt.Sprint(i)
		rl.attempts[key] = []time.Time{oldTime}
	}
	rl.mu.Unlock()

	if rl.size() != 500 {
		t.Fatalf("expected 500 keys after injection, got %d", rl.size())
	}

	// Trigger eviction directly
	rl.evict()

	// All 500 keys should be gone — timestamps are outside the window
	remaining := rl.size()
	if remaining != 0 {
		t.Errorf("expected 0 keys after eviction of stale entries, got %d", remaining)
	}

	// Add one fresh key — should survive eviction
	rl.allow("user:valid-user", 20, 5*time.Minute)
	rl.evict()
	if rl.size() != 1 {
		t.Errorf("expected 1 fresh key to survive eviction, got %d", rl.size())
	}
}

// TestMaskAdminKey verifies safe masking of the admin key for /api/settings
// responses, including short and empty keys that could panic on slice bounds.
func TestMaskAdminKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want string
	}{
		{"empty", "", ""},
		{"one char", "x", "x"}, // fully shown since len < 4
		{"three chars", "abc", "abc"},
		{"four chars", "abcd", "abcd"}, // exactly 4 = show all
		{"five chars", "abcde", "*bcde"},
		{"long key", "secret-admin-key-12345", "******************2345"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := maskAdminKey(tt.key)
			if got != tt.want {
				t.Errorf("maskAdminKey(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}
