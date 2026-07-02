package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/store"
)

// ─── Auth handlers (public) ───

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(loginPageHTML))
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	user, err := s.DB.GetUser(body.Username)
	if err != nil || user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	// Rate limiting: 10 attempts per 5 minutes per account, 20 per IP
	ip := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		ip = strings.Split(fwd, ",")[0]
	}
	if !s.limiter.allow("user:"+body.Username, 20, 5*time.Minute) ||
		!s.limiter.allow("ip:"+ip, 50, 5*time.Minute) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many attempts, try again later"})
		return
	}

	if !s.DB.VerifyPassword(body.Username, body.Password) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	// Reset rate limit on successful login
	s.limiter.reset("user:" + body.Username)
	s.limiter.reset("ip:" + ip)

	// Transparently upgrade legacy SHA-256 hashes to Argon2id
	if store.IsLegacyHash(user.PasswordHash) {
		newHash := store.RehashPassword(body.Password)
		s.DB.Conn().Exec("UPDATE users SET password_hash = ? WHERE username = ?", newHash, user.Username)
		log.Printf("auth: upgraded password hash for %s (SHA-256 → Argon2id)", user.Username)
	}

	token, err := s.DB.CreateSession(user.Username, user.Role)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session error"})
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "arbiter_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteStrictMode,
		MaxAge:   12 * 3600, // 12 hours
	})
	log.Printf("auth: %s logged in as %s", body.Username, user.Role)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "role": user.Role, "username": user.Username})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("arbiter_session"); err == nil {
		s.DB.DeleteSession(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:   "arbiter_session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	username, role, ok := s.sessionFromCookie(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no session"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"username": username, "role": role})
}

// ─── User management (admin only) ───

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		users, err := s.DB.ListUsers()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"users": users})

	case http.MethodPost:
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if body.Username == "" || body.Password == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username and password required"})
			return
		}
		if body.Role != "admin" && body.Role != "reader" {
			body.Role = "reader"
		}
		if err := s.DB.CreateUser(body.Username, body.Password, body.Role); err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		log.Printf("auth: admin created user %s (%s)", body.Username, body.Role)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "username": body.Username})

	case http.MethodPut:
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if body.Role != "admin" && body.Role != "reader" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "role must be admin or reader"})
			return
		}
		if err := s.DB.UpdateUser(body.Username, body.Password, body.Role); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		log.Printf("auth: updated user %s (%s)", body.Username, body.Role)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})

	case http.MethodDelete:
		var body struct {
			Username string `json:"username"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if err := s.DB.DeleteUser(body.Username); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		log.Printf("auth: deleted user %s", body.Username)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// ─── Middleware ───

// sessionFromCookie extracts and validates the session token from request cookies.
func (s *Server) sessionFromCookie(r *http.Request) (username, role string, ok bool) {
	cookie, err := r.Cookie("arbiter_session")
	if err != nil {
		return "", "", false
	}
	return s.DB.GetSession(cookie.Value)
}

// requireAuth is middleware that requires a valid session or admin API key.
// Session cookies are used for web dashboard access.
// X-Arbiter-Key header is used for programmatic/CLI access (backward compat).
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check session cookie first
		_, _, ok := s.sessionFromCookie(r)
		if ok {
			s.DB.CleanExpiredSessions()
			next(w, r)
			return
		}
		// Fall back to admin API key for programmatic access
		if s.AdminKey != "" && r.Header.Get("X-Arbiter-Key") == s.AdminKey {
			next(w, r)
			return
		}
		// API requests get 401, browser requests get redirected
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/admin/") {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		} else {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		}
	}
}

// requireAdmin is middleware that requires an admin role or API key.
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// API key always has admin privileges
		if s.AdminKey != "" && r.Header.Get("X-Arbiter-Key") == s.AdminKey {
			next(w, r)
			return
		}
		_, role, ok := s.sessionFromCookie(r)
		if !ok || role != "admin" {
			http.Error(w, `{"error":"admin required"}`, http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// loginPageHTML is the standalone login page served at /login.
const loginPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Threat Intel Arbiter — Login</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #e2e8f0; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
.card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 2rem; width: 360px; }
h1 { font-size: 1.2rem; margin-bottom: 0.5rem; }
.sub { font-size: 0.75rem; color: #64748b; margin-bottom: 1.5rem; }
input { width: 100%; background: #0f172a; border: 1px solid #475569; color: #e2e8f0; border-radius: 6px; padding: 10px 12px; font-size: 14px; margin-bottom: 0.75rem; }
input:focus { outline: none; border-color: #22d3ee; }
button { width: 100%; background: #0e7490; color: white; border: none; border-radius: 6px; padding: 10px; font-size: 14px; font-weight: 600; cursor: pointer; }
button:hover { filter: brightness(1.2); }
.error { color: #fca5a5; font-size: 0.75rem; margin-bottom: 0.5rem; display: none; }
</style>
</head>
<body>
<div class="card">
  <h1>Threat Intel Arbiter</h1>
  <p class="sub">Sign in to access the dashboard</p>
  <p class="error" id="error">Invalid credentials</p>
  <input type="text" id="username" placeholder="Username" autofocus onkeydown="if(event.key==='Enter')login()">
  <input type="password" id="password" placeholder="Password" onkeydown="if(event.key==='Enter')login()">
  <button onclick="login()">Sign In</button>
</div>
<script>
async function login() {
  const u = document.getElementById('username').value;
  const p = document.getElementById('password').value;
  if (!u || !p) return;
  const r = await fetch('/auth/login', {
    method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({username:u, password:p})
  });
  if (r.ok) {
    window.location.href = '/';
  } else {
    document.getElementById('error').style.display = 'block';
  }
}
</script>
</body>
</html>`
