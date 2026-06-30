package api

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"strings"

	"github.com/jayelbotvibe-web/threatlib/internal/config"
	"github.com/jayelbotvibe-web/threatlib/internal/model"
	"github.com/jayelbotvibe-web/threatlib/internal/store"
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
}

// NewServer creates an HTTP server for the threatlib API.
func NewServer(db *store.DB, configDir string, adminKey string) *Server {
	s := &Server{
		DB:        db,
		Mux:       http.NewServeMux(),
		AdminKey:  adminKey,
		ConfigDir: configDir,
	}
	s.registerRoutes()
	return s
}

// SetEventQueue sets the event queue for triggering manual pulls.
func (s *Server) SetEventQueue(q chan<- model.ThreatEvent) {
	s.EventQueue = q
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe(addr string) error {
	log.Printf("api: listening on %s", addr)
	return http.ListenAndServe(addr, s.Mux)
}

func (s *Server) registerRoutes() {
	// Dashboard
	dashboardHTML, _ := fs.ReadFile(dashboardFS, "dashboard.html")
	s.Mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(dashboardHTML)
	})

	// Public read endpoints
	s.Mux.HandleFunc("/health", s.handleHealth)
	s.Mux.HandleFunc("/api/alerts", s.handleAlerts)
	s.Mux.HandleFunc("/api/techstack", s.handleTechStack)
	s.Mux.HandleFunc("/api/stats", s.handleStats)

	// Admin write endpoints (auth required)
	s.Mux.HandleFunc("/admin/import", s.auth(s.handleAdminImport))
	s.Mux.HandleFunc("/admin/ack/", s.auth(s.handleAdminAck))
	s.Mux.HandleFunc("/admin/pull", s.auth(s.handleAdminPull))
}

// auth wraps a handler with API key authentication.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.AdminKey == "" {
			http.Error(w, `{"error":"admin key not configured"}`, http.StatusInternalServerError)
			return
		}
		key := r.Header.Get("X-Threatlib-Key")
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

	// Parse uploaded CSV
	apps, err := config.ParseTechStackReader(r.Body)
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
		"status":  "ok",
		"imported": len(apps),
		"added":   added,
		"removed": removed,
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

	// Parse optional body for resolution status
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
		"status": "ok",
		"message": "pull triggered (MISP poller will pull on next tick if configured)",
	})
}

// ─────────────────────────────────────────────────────────────
// Public read handlers (unchanged)
// ─────────────────────────────────────────────────────────────

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	var alertCount, deadLetterCount int
	s.DB.Conn().QueryRow("SELECT COUNT(*) FROM alerts").Scan(&alertCount)
	s.DB.Conn().QueryRow("SELECT COUNT(*) FROM dedup_hashes").Scan(&deadLetterCount)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":        "ok",
		"alerts_total":  alertCount,
		"dedup_entries": deadLetterCount,
	})
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	rows, err := s.DB.Conn().Query(
		`SELECT id, event_id, severity, confidence, status, matched_apps, created_at
		 FROM alerts ORDER BY created_at DESC LIMIT 50`)
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
	}

	var alerts []alertRow
	for rows.Next() {
		var a alertRow
		if err := rows.Scan(&a.ID, &a.EventID, &a.Severity, &a.Confidence, &a.Status, &a.MatchedApps, &a.CreatedAt); err != nil {
			continue
		}
		alerts = append(alerts, a)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"alerts": alerts,
		"count":  len(alerts),
	})
}

func (s *Server) handleTechStack(w http.ResponseWriter, r *http.Request) {
	apps, err := s.DB.ListTechStack()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	type appSummary struct {
		Name        string `json:"name"`
		Version     string `json:"version"`
		Criticality string `json:"criticality"`
		Internet    bool   `json:"internet_facing"`
	}

	var list []appSummary
	for _, a := range apps {
		list = append(list, appSummary{
			Name:        a.Name,
			Version:     a.Version,
			Criticality: a.Criticality,
			Internet:    a.InternetFacing,
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
