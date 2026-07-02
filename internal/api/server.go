package api

import (
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/config"
	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/model"
	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/store"
)

//go:embed dashboard.html
var dashboardFS embed.FS

// Server holds the HTTP server dependencies.
type Server struct {
	DB         *store.DB
	Mux        *http.ServeMux
	AdminKey   string
	ConfigDir  string
	EventQueue chan<- model.ThreatEvent
	limiter    *rateLimiter
	TrustProxy bool // if true, trust X-Forwarded-For / X-Forwarded-Proto headers
}

// NewServer creates an HTTP server for the Threat Intel Arbiter API.
func NewServer(db *store.DB, configDir string, adminKey string) *Server {
	s := &Server{
		DB:         db,
		Mux:        http.NewServeMux(),
		AdminKey:   adminKey,
		ConfigDir:  configDir,
		limiter:    newRateLimiter(),
		TrustProxy: os.Getenv("TRUSTED_PROXY") == "true",
	}
	// Background session cleanup every 5 minutes (not on every request)
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			db.CleanExpiredSessions()
		}
	}()
	s.registerRoutes()
	return s
}

// SetEventQueue sets the event queue for triggering manual pulls.
func (s *Server) SetEventQueue(q chan<- model.ThreatEvent) {
	s.EventQueue = q
}

// getClientIP returns the client IP, honoring TrustProxy.
func (s *Server) getClientIP(r *http.Request) string {
	if s.TrustProxy {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			return strings.TrimSpace(strings.Split(fwd, ",")[0])
		}
	}
	return r.RemoteAddr
}

// isSecure returns true if the connection is TLS or proxied via HTTPS.
func (s *Server) isSecure(r *http.Request) bool {
	return r.TLS != nil || (s.TrustProxy && r.Header.Get("X-Forwarded-Proto") == "https")
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe(addr string) error {
	log.Printf("api: listening on %s", addr)
	return http.ListenAndServe(addr, s.Mux)
}

func (s *Server) registerRoutes() {
	// Wrap all handlers with security headers
	secure := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; object-src 'none'; base-uri 'none'; connect-src 'self'")
			next(w, r)
		}
	}
	// Auth endpoints (public — no session required)
	s.Mux.HandleFunc("/login", secure(s.handleLogin))
	s.Mux.HandleFunc("/auth/login", secure(s.handleLogin))
	s.Mux.HandleFunc("/auth/logout", secure(s.handleLogout))
	s.Mux.HandleFunc("/auth/session", secure(s.handleSession))

	// Dashboard
	s.Mux.HandleFunc("/", secure(s.requireAuth(s.serveDashboard)))

	// Health (public — no auth)
	s.Mux.HandleFunc("/health", secure(s.handleHealth))

	// API endpoints (auth required)
	s.Mux.HandleFunc("/api/status", s.requireAuth(s.handleStatus))
	s.Mux.HandleFunc("/api/alerts", s.requireAuth(s.handleAlerts))
	s.Mux.HandleFunc("/api/alerts/", s.requireAuth(s.handleAlertDetail))
	s.Mux.HandleFunc("/api/techstack", s.requireAuth(s.handleTechStack))
	s.Mux.HandleFunc("/api/stats", s.requireAuth(s.handleStats))

	// Admin write endpoints (admin role required — session or API key)
	s.Mux.HandleFunc("/admin/import", s.requireAuth(s.requireAdmin(s.handleAdminImport)))
	s.Mux.HandleFunc("/admin/ack/", s.requireAuth(s.requireAdmin(s.handleAdminAck)))
	s.Mux.HandleFunc("/admin/pull", s.requireAuth(s.requireAdmin(s.handleAdminPull)))
	s.Mux.HandleFunc("/admin/techstack", s.requireAuth(s.requireAdmin(s.handleAdminTechStack)))
	s.Mux.HandleFunc("/admin/users", s.requireAuth(s.requireAdmin(s.handleAdminUsers)))
}

// serveDashboard returns the embedded dashboard HTML for authenticated users.
func (s *Server) serveDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	html, _ := fs.ReadFile(dashboardFS, "dashboard.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(html)
}

// auth wraps a handler with API key authentication.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.AdminKey == "" {
			http.Error(w, `{"error":"admin key not configured"}`, http.StatusInternalServerError)
			return
		}
		key := r.Header.Get("X-Arbiter-Key")
		if key == "" || key != s.AdminKey {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// ─────────────────────────────────────────────────────────────
// Admin handlers
// ─────────────────────────────────────────────────────────────

func (s *Server) handleAdminImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	apps, err := configParseTechStack(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	added, removed, err := s.DB.ImportTechStack(apps)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	log.Printf("admin: import %d apps (%d added, %d removed)", len(apps), added, removed)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "ok",
		"imported": len(apps),
		"added":    added,
		"removed":  removed,
	})
}

func (s *Server) handleAdminAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Extract alert ID from URL: /admin/ack/<alert_id>
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/admin/ack/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, `{"error":"alert ID required"}`, http.StatusBadRequest)
		return
	}
	alertID := parts[0]

	var body struct {
		Status string `json:"status"` // "acked", "false_pos", "resolved"
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.Status == "" {
		body.Status = "acked"
	}

	_, err := s.DB.Conn().Exec("UPDATE alerts SET status = ? WHERE id = ?", body.Status, alertID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	log.Printf("admin: ack alert %s → %s", alertID, body.Status)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "alert_id": alertID, "new_status": body.Status})
}

func (s *Server) handleAdminPull(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"message": "pull triggered (MISP poller will pull on next tick if configured)",
	})
}

func (s *Server) handleAdminTechStack(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		// Add single app
		var app model.App
		if err := json.NewDecoder(r.Body).Decode(&app); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if app.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
			return
		}
		inet := 0
		if app.InternetFacing {
			inet = 1
		}
		_, err := s.DB.Conn().Exec(
			`INSERT INTO tech_stack (name, version, vendor, category, criticality, owner_team, internet_facing, hosts, data_sensitivity, org_id)
			 VALUES (?,?,?,?,?,?,?,?,?,'default')`,
			app.Name, app.Version, app.Vendor, app.Category, app.Criticality, app.OwnerTeam, inet, app.Hosts, app.DataSensitivity)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		log.Printf("admin: added app %s", app.Name)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "action": "added", "name": app.Name})

	case http.MethodPut:
		// Update single app
		var app model.App
		if err := json.NewDecoder(r.Body).Decode(&app); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if app.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
			return
		}
		inet := 0
		if app.InternetFacing {
			inet = 1
		}
		res, err := s.DB.Conn().Exec(
			`UPDATE tech_stack SET version=?, vendor=?, category=?, criticality=?, owner_team=?, internet_facing=?, hosts=?, data_sensitivity=?
			 WHERE name=? AND org_id='default'`,
			app.Version, app.Vendor, app.Category, app.Criticality, app.OwnerTeam, inet, app.Hosts, app.DataSensitivity, app.Name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "app not found"})
			return
		}
		log.Printf("admin: updated app %s", app.Name)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "action": "updated", "name": app.Name})

	case http.MethodDelete:
		// Remove single app — name in JSON body
		var body struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if body.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
			return
		}
		res, err := s.DB.Conn().Exec("DELETE FROM tech_stack WHERE name=? AND org_id='default'", body.Name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "app not found"})
			return
		}
		log.Printf("admin: removed app %s", body.Name)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "action": "removed", "name": body.Name})

	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

// ─────────────────────────────────────────────────────────────
// Public read handlers
// ─────────────────────────────────────────────────────────────

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Minimal public health — liveness only
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleStatus returns detailed system status (requires auth).
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	var alertCount, newAlerts, deadLetterCount int
	s.DB.Conn().QueryRow("SELECT COUNT(*) FROM alerts").Scan(&alertCount)
	s.DB.Conn().QueryRow("SELECT COUNT(*) FROM alerts WHERE status='new'").Scan(&newAlerts)
	s.DB.Conn().QueryRow("SELECT COUNT(*) FROM dedup_hashes").Scan(&deadLetterCount)

	var lastPull string
	s.DB.Conn().QueryRow("SELECT value FROM state WHERE key='misp_cursor'").Scan(&lastPull)

	var kevCount int
	s.DB.Conn().QueryRow("SELECT COUNT(*) FROM alerts WHERE event_id LIKE 'CVE-%'").Scan(&kevCount)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":           "ok",
		"alerts_total":     alertCount,
		"alerts_new":       newAlerts,
		"last_misp_pull":   lastPull,
		"kev_entries":      kevCount,
		"dedup_entries":    deadLetterCount,
	})
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// Build WHERE clause from filters
	conditions := []string{"1=1"}
	args := []interface{}{}

	if search := q.Get("q"); search != "" {
		conditions = append(conditions, "(event_id LIKE ? OR explanation LIKE ?)")
		like := "%" + search + "%"
		args = append(args, like, like)
	}
	if app := q.Get("app"); app != "" {
		conditions = append(conditions, "matched_apps LIKE ?")
		args = append(args, "%"+app+"%")
	}
	if status := q.Get("status"); status != "" {
		conditions = append(conditions, "status = ?")
		args = append(args, status)
	}
	if sev := q.Get("severity"); sev != "" {
		conditions = append(conditions, "severity = ?")
		args = append(args, sev)
	}

	query := `SELECT id, event_id, severity, confidence, status, matched_apps, created_at, explanation, action
		FROM alerts WHERE ` + strings.Join(conditions, " AND ") + ` ORDER BY created_at DESC LIMIT 200`

	rows, err := s.DB.Conn().Query(query, args...)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	type alertRow struct {
		ID          string `json:"id"`
		EventID     string `json:"event_id"`
		Severity    string `json:"severity"`
		Confidence  string `json:"confidence"`
		Status      string `json:"status"`
		MatchedApps string `json:"matched_apps"`
		CreatedAt   string `json:"created_at"`
		Explanation string `json:"explanation"`
		Action      string `json:"action"`
		RiskScore   float64 `json:"risk_score"`
		SSVCAction  string  `json:"ssvc_action"`
		CVE         string  `json:"cve"`
	}

	var alerts []alertRow
	for rows.Next() {
		var a alertRow
		if err := rows.Scan(&a.ID, &a.EventID, &a.Severity, &a.Confidence, &a.Status, &a.MatchedApps, &a.CreatedAt, &a.Explanation, &a.Action); err != nil {
			continue
		}
		a.RiskScore = parseRiskScore(a.Explanation)
		a.SSVCAction = ssvcShort(a.Action)
		a.CVE = extractCVE(a.EventID)
		alerts = append(alerts, a)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"alerts": alerts,
		"count":  len(alerts),
	})
}

// parseRiskScore extracts the risk score from the explanation text.
// Looks for "Risk Score: 0.71" pattern.
func parseRiskScore(explanation string) float64 {
	idx := strings.Index(explanation, "Risk Score: ")
	if idx < 0 {
		return 0
	}
	start := idx + len("Risk Score: ")
	end := start
	for end < len(explanation) && ((explanation[end] >= '0' && explanation[end] <= '9') || explanation[end] == '.') {
		end++
	}
	if end > start {
		var f float64
		fmt.Sscanf(explanation[start:end], "%f", &f)
		return f
	}
	return 0
}

// ssvcShort maps full SSVC action labels to short codes.
func ssvcShort(action string) string {
	switch action {
	case "Act Now":
		return "act"
	case "Schedule", "Attend":
		return "attend"
	default:
		return "track"
	}
}

// extractCVE pulls a CVE ID from an event ID if present.
func extractCVE(eventID string) string {
	if strings.HasPrefix(eventID, "CVE-") {
		return eventID
	}
	// Also check for KEV format like "CVE-2024-3400"
	idx := strings.Index(eventID, "CVE-")
	if idx >= 0 {
		end := idx + 4
		for end < len(eventID) && ((eventID[end] >= '0' && eventID[end] <= '9') || eventID[end] == '-') {
			end++
		}
		return eventID[idx:end]
	}
	return eventID
}

func (s *Server) handleAlertDetail(w http.ResponseWriter, r *http.Request) {
	// Extract alert ID from URL: /api/alerts/<alert_id>
	id := strings.TrimPrefix(r.URL.Path, "/api/alerts/")
	if id == "" {
		http.Error(w, `{"error":"alert ID required"}`, http.StatusBadRequest)
		return
	}

	var detail struct {
		ID          string `json:"id"`
		EventID     string `json:"event_id"`
		Severity    string `json:"severity"`
		Confidence  string `json:"confidence"`
		Status      string `json:"status"`
		MatchedApps string `json:"matched_apps"`
		CreatedAt   string `json:"created_at"`
		Explanation string `json:"explanation"`
		Action      string `json:"action"`
		RoutedTo    string `json:"routed_to"`
	}

	err := s.DB.Conn().QueryRow(
		`SELECT id, event_id, severity, confidence, status, matched_apps, created_at, explanation, action, routed_to
		 FROM alerts WHERE id = ?`, id,
	).Scan(&detail.ID, &detail.EventID, &detail.Severity, &detail.Confidence, &detail.Status, &detail.MatchedApps, &detail.CreatedAt, &detail.Explanation, &detail.Action, &detail.RoutedTo)
	if err == sql.ErrNoRows {
		http.Error(w, `{"error":"alert not found"}`, http.StatusNotFound)
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, detail)
}

func (s *Server) handleTechStack(w http.ResponseWriter, r *http.Request) {
	apps, err := s.DB.ListTechStack()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	type appSummary struct {
		Name           string `json:"name"`
		Version        string `json:"version"`
		Vendor         string `json:"vendor"`
		Category       string `json:"category"`
		Criticality    string `json:"criticality"`
		OwnerTeam      string `json:"owner_team"`
		InternetFacing bool   `json:"internet_facing"`
		Hosts          string `json:"hosts"`
		DataSensitivity string `json:"data_sensitivity"`
	}

	var list []appSummary
	for _, a := range apps {
		list = append(list, appSummary{
			Name:            a.Name,
			Version:         a.Version,
			Vendor:          a.Vendor,
			Category:        a.Category,
			Criticality:     a.Criticality,
			OwnerTeam:       a.OwnerTeam,
			InternetFacing:  a.InternetFacing,
			Hosts:           a.Hosts,
			DataSensitivity: a.DataSensitivity,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"apps":  list,
		"count": len(list),
	})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	var total, critical, high, medium, low int

	s.DB.Conn().QueryRow("SELECT COUNT(*) FROM alerts").Scan(&total)
	s.DB.Conn().QueryRow("SELECT COUNT(*) FROM alerts WHERE severity='critical'").Scan(&critical)
	s.DB.Conn().QueryRow("SELECT COUNT(*) FROM alerts WHERE severity='high'").Scan(&high)
	s.DB.Conn().QueryRow("SELECT COUNT(*) FROM alerts WHERE severity='medium'").Scan(&medium)
	s.DB.Conn().QueryRow("SELECT COUNT(*) FROM alerts WHERE severity='low'").Scan(&low)

	var eventCount int
	s.DB.Conn().QueryRow("SELECT COUNT(*) FROM events").Scan(&eventCount)

	var appCount int
	s.DB.Conn().QueryRow("SELECT COUNT(*) FROM tech_stack").Scan(&appCount)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"alerts": map[string]int{
			"total":    total,
			"critical": critical,
			"high":     high,
			"medium":   medium,
			"low":      low,
		},
		"events_stored": eventCount,
		"apps_tracked":  appCount,
	})
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// configParseTechStack parses a CSV tech stack from a reader.
// Delegates to the config package parser.
func configParseTechStack(r io.Reader) ([]model.App, error) {
	return config.ParseTechStackReader(r)
}
