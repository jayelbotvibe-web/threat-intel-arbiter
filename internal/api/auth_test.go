package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

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
