package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestGetClientIP_StripsPort guards the rate-limit fix: r.RemoteAddr is
// "host:port", and keying the limiter on it verbatim would give every new
// connection (fresh ephemeral port) its own bucket, defeating per-IP throttling.
func TestGetClientIP_StripsPort(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/", nil) // RemoteAddr = 192.0.2.1:1234
	if got := s.getClientIP(req); got != "192.0.2.1" {
		t.Errorf("getClientIP = %q, want 192.0.2.1 (port must be stripped)", got)
	}
}

// TestGetClientIP_XFFRightmostWhenTrusted guards the spoofing fix: when a proxy
// is trusted, only the rightmost (proxy-appended) XFF entry is authoritative;
// the leftmost is client-supplied and forgeable.
func TestGetClientIP_XFFRightmostWhenTrusted(t *testing.T) {
	s := &Server{TrustProxy: true}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.5") // spoofed, real
	if got := s.getClientIP(req); got != "10.0.0.5" {
		t.Errorf("getClientIP = %q, want 10.0.0.5 (rightmost trusted entry)", got)
	}
}

// TestGetClientIP_IgnoresXFFWhenUntrusted ensures a forged header is ignored
// unless TRUSTED_PROXY is explicitly set.
func TestGetClientIP_IgnoresXFFWhenUntrusted(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := s.getClientIP(req); got != "192.0.2.1" {
		t.Errorf("getClientIP = %q, want 192.0.2.1 (XFF ignored when untrusted)", got)
	}
}

// TestLoginNoEnumerationOracle guards the fix that closes the 401-vs-429
// username-enumeration oracle: a nonexistent user hitting the per-account
// limit must return 429, exactly like a real user would — not a distinguishing 401.
func TestLoginNoEnumerationOracle(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	var last int
	for i := 0; i < 21; i++ { // per-account limit is 20; the 21st must be throttled
		body := strings.NewReader(`{"username":"ghost-user","password":"nope"}`)
		req := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.Mux.ServeHTTP(w, req)
		last = w.Code
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("21st login for nonexistent user = %d, want 429 (no 401-vs-429 oracle)", last)
	}
}
