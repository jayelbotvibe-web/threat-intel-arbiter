// Threat Intel Arbiter — Threat Prioritization Engine
// Single Go binary. Deploy in 60 seconds. MISP + KEV sources in v1.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/api"
	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/config"
	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/filter"
	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/match"
	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/model"
	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/notify"
	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/risk"
	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/source"
	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/store"
)

func main() {
	configDir := flag.String("config", "./config", "path to configuration directory")
	dbPath := flag.String("db", "./data/arbiter.db", "path to SQLite database file")
	apiPort := flag.String("port", ":8080", "HTTP server address")
	adminKey := flag.String("key", os.Getenv("ARBITER_ADMIN_KEY"), "admin API key")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("arbiter starting...")

	// Load all configuration
	cfg, apps, err := config.LoadAll(*configDir)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	log.Printf("config loaded: org=%s sector=%s", cfg.Org.Name, cfg.Org.Sector)

	// Open database
	db, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer db.Close()
	log.Printf("database opened: %s", *dbPath)

	// Import tech stack
	added, removed, err := db.ImportTechStack(apps)
	if err != nil {
		log.Fatalf("import tech stack: %v", err)
	}
	log.Printf("tech stack loaded: %d apps (%d added, %d removed)", len(apps), added, removed)

	// Build org context from config
	orgCtx := cfg.Org.ToOrgContext(apps)

	// Initialize filter
	f := filter.New()
	f.LoadWarningCVEs("CVE-2024-99999", "CVE-2023-00001")
	log.Printf("filter initialized: %d warning CVEs", 2)

	// Event queue between poller and matcher
	eventQueue := make(chan model.ThreatEvent, 5000)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start MISP poller if configured in sources.yaml
	for _, src := range cfg.Sources.Sources {
		if !src.Enabled || src.Type != "misp" {
			continue
		}
		mispKey := os.Getenv(src.AuthKeyEnv)
		if mispKey == "" {
			log.Printf("source %s: env %s not set, skipping", src.ID, src.AuthKeyEnv)
			continue
		}
		client := source.NewMISPClient(src.URL, mispKey)
		poller := &source.MISPPoller{
			Client:    client,
			DB:        db,
			Events:    eventQueue,
			Interval:  15 * time.Minute,
			ColdStart: true,
		}
		go func() {
			log.Printf("starting MISP poller: %s (%s)", src.Name, src.URL)
			if err := poller.Run(ctx); err != nil {
				log.Printf("misp poller stopped: %v", err)
			}
		}()
	}

	// Start KEV poller if any KEV source is configured
	for _, src := range cfg.Sources.Sources {
		if !src.Enabled || src.Type != "cisa-kev" {
			continue
		}
		kevClient := source.NewKEVClient(src.URL)
		kevPoller := &source.KEVPoller{
			Client:   kevClient,
			Events:   eventQueue,
			Interval: 24 * time.Hour,
		}
		go func() {
			log.Printf("starting KEV poller: %s", src.URL)
			if err := kevPoller.Run(ctx); err != nil {
				log.Printf("kev poller stopped: %v", err)
			}
		}()
	}

	// Build matchers from config
	var matchers []model.Matcher
	for _, m := range cfg.Matchers.Matchers {
		if !m.Enabled {
			continue
		}
		switch m.Name {
		case "CVEMatcher":
			matchers = append(matchers, match.NewCVEMatcher())
		case "SectorMatcher":
			matchers = append(matchers, &match.SectorMatcher{})
		case "KEVMatcher":
			// TODO: load KEV CVEs from real KEV catalog or config
			matchers = append(matchers, match.NewKEVMatcher([]string{
				"CVE-2024-38472", "CVE-2024-28941", "CVE-2024-27318",
			}))
		}
	}
	matchEngine := match.NewEngine(matchers...)
	log.Printf("match engine ready: %d matchers (%v)", len(matchers), matchEngine.MatcherNames())

	riskEngine := risk.NewEngine()

	// Build router from routing.yaml
	var rules []notify.Rule
	for _, r := range cfg.Routing.Rules {
		rules = append(rules, notify.Rule{
			Severity: r.Severity, Confidence: r.Confidence,
			Channels: r.Channels, Format: r.Format,
		})
	}
	if len(rules) == 0 {
		// Default: all severities to console
		rules = []notify.Rule{
			{Severity: "critical", Confidence: []string{"high", "medium", "low"}, Channels: []string{"console"}, Format: "realtime"},
			{Severity: "high", Confidence: []string{"high", "medium", "low"}, Channels: []string{"console"}, Format: "realtime"},
			{Severity: "medium", Channels: []string{"console"}, Format: "realtime"},
		}
	}
	router := notify.NewRouter(rules)
	router.Register("console", notify.NewConsoleNotifier("console"))
	router.Register("slack", notify.NewSlackNotifier(""))
	router.Register("teams", notify.NewTeamsNotifier(""))
	router.Register("email", notify.NewEmailNotifier("", "", "", ""))
	csNotifier := notify.NewCrowdstrikeNotifier()
	log.Printf("notification router ready: %d rules, notifiers: console, slack, teams, email, crowdstrike(mock=%v)", len(rules), csNotifier.Mock)

	// Start event processor goroutine — full pipeline
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case event := <-eventQueue:
				match.TagEvent(&event)
				if !f.Allow(event) {
					log.Printf("filter: dropped event %s", event.ID)
					continue
				}
				matches := matchEngine.Run(event, orgCtx)
				if len(matches) == 0 {
					continue
				}
				result := riskEngine.Score(event, orgCtx, matches)
				alert := risk.NewAlert(event, result, matches)
				if _, err := db.SaveAlert(alert, 7*24*time.Hour); err != nil {
					log.Printf("alert save: %v", err)
				}
				routed := router.Route(alert)
				if len(routed) > 0 {
					log.Printf("alert: %s · %s → %v", alert.Severity, alert.Confidence, routed)
				}
				// Send IOCs to Crowdstrike for EDR integration
				if csNotifier != nil {
					if sent, err := csNotifier.Notify(event, alert.Severity, alert.Confidence); err != nil {
						log.Printf("crowdstrike: notify error: %v", err)
					} else if sent > 0 {
						log.Printf("crowdstrike: sent %d IOCs from %s", sent, event.ID)
					}
				}
			}
		}
	}()

	// Start HTTP server
	server := api.NewServer(db, *configDir, *adminKey)
	server.SetEventQueue(eventQueue)
	go func() {
		if err := server.ListenAndServe(*apiPort); err != nil && err != http.ErrServerClosed {
			log.Printf("api server: %v", err)
		}
	}()

	log.Println("arbiter ready")

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Printf("received %v, shutting down...", sig)
	case <-ctx.Done():
		log.Println("context cancelled, shutting down...")
	}

	cancel()
	log.Println("arbiter stopped")
}
