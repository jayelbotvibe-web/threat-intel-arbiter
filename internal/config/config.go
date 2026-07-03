package config

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/model"
)

// ─────────────────────────────────────────────────────────────
// Config holds all parsed configuration.
// ─────────────────────────────────────────────────────────────

type Config struct {
	Org      OrgConfig
	Sources  SourcesConfig
	Routing  RoutingConfig
	Risk     RiskConfig
	Matchers MatchersConfig
}

// ─────────────────────────────────────────────────────────────
// Org
// ─────────────────────────────────────────────────────────────

type OrgConfig struct {
	Name            string `json:"name"`
	Sector          string `json:"sector"`
	Country         string `json:"country"`
	Timezone        string `json:"timezone"`
	DataSensitivity string `json:"data_sensitivity"`
}

func LoadOrg(path string) (OrgConfig, error) {
	var wrapper struct {
		Org OrgConfig `json:"org"`
	}
	if err := loadJSON(path, &wrapper); err != nil {
		return OrgConfig{}, err
	}
	return wrapper.Org, nil
}

func (o OrgConfig) ToOrgContext(apps []model.App) model.OrgContext {
	return model.OrgContext{
		OrgID:           "default",
		Name:            o.Name,
		Sector:          o.Sector,
		Country:         o.Country,
		Timezone:        o.Timezone,
		DataSensitivity: o.DataSensitivity,
		TechStack:       apps,
	}
}

// ─────────────────────────────────────────────────────────────
// Sources
// ─────────────────────────────────────────────────────────────

type SourceEntry struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Name         string `json:"name"`
	URL          string `json:"url"`
	AuthKeyEnv   string `json:"auth_key_env"`
	Confidence   string `json:"confidence"`
	Enabled      bool   `json:"enabled"`
	PullInterval string `json:"pull_interval"`
}

type SourcesConfig struct {
	Sources []SourceEntry `json:"sources"`
}

func LoadSources(path string) (SourcesConfig, error) {
	var cfg SourcesConfig
	if err := loadJSON(path, &cfg); err != nil {
		return SourcesConfig{}, err
	}
	return cfg, nil
}

// ─────────────────────────────────────────────────────────────
// Routing
// ─────────────────────────────────────────────────────────────

type RoutingRule struct {
	Severity   string   `json:"severity"`
	Confidence []string `json:"confidence"`
	Channels   []string `json:"channels"`
	Format     string   `json:"format"`
}

type RoutingConfig struct {
	Rules []RoutingRule `json:"rules"`
}

func LoadRouting(path string) (RoutingConfig, error) {
	var cfg RoutingConfig
	if err := loadJSON(path, &cfg); err != nil {
		return RoutingConfig{}, err
	}
	return cfg, nil
}

// ─────────────────────────────────────────────────────────────
// Risk
// ─────────────────────────────────────────────────────────────

type RiskConfig struct {
	Dimensions struct {
		Likelihood struct {
			Max     int            `json:"max"`
			Factors map[string]int `json:"factors"`
		} `json:"likelihood"`
		Impact struct {
			Max     int            `json:"max"`
			Factors map[string]int `json:"factors"`
		} `json:"impact"`
		Exposure struct {
			Max     int            `json:"max"`
			Factors map[string]int `json:"factors"`
		} `json:"exposure"`
		Confidence struct {
			Max     int            `json:"max"`
			Factors map[string]int `json:"factors"`
		} `json:"confidence"`
	} `json:"dimensions"`
	Severity struct {
		Thresholds map[string]float64 `json:"thresholds"`
	} `json:"severity"`
}

func LoadRisk(path string) (RiskConfig, error) {
	var cfg RiskConfig
	if err := loadJSON(path, &cfg); err != nil {
		return RiskConfig{}, err
	}
	return cfg, nil
}

// ─────────────────────────────────────────────────────────────
// Matchers
// ─────────────────────────────────────────────────────────────

type MatcherEntry struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

type MatchersConfig struct {
	Matchers []MatcherEntry `json:"matchers"`
}

func LoadMatchers(path string) (MatchersConfig, error) {
	var cfg MatchersConfig
	if err := loadJSON(path, &cfg); err != nil {
		return MatchersConfig{}, err
	}
	return cfg, nil
}

// ─────────────────────────────────────────────────────────────
// Load all config from a directory.
// ─────────────────────────────────────────────────────────────

func LoadAll(configDir string) (*Config, []model.App, error) {
	cfg := &Config{}

	org, err := LoadOrg(configDir + "/org.json")
	if err != nil {
		return nil, nil, fmt.Errorf("org: %w", err)
	}
	cfg.Org = org

	sources, err := LoadSources(configDir + "/sources.json")
	if err != nil {
		return nil, nil, fmt.Errorf("sources: %w", err)
	}
	cfg.Sources = sources

	routing, err := LoadRouting(configDir + "/routing.json")
	if err != nil {
		return nil, nil, fmt.Errorf("routing: %w", err)
	}
	cfg.Routing = routing

	risk, err := LoadRisk(configDir + "/risk.json")
	if err != nil {
		return nil, nil, fmt.Errorf("risk: %w", err)
	}
	cfg.Risk = risk

	matchers, err := LoadMatchers(configDir + "/matchers.json")
	if err != nil {
		return nil, nil, fmt.Errorf("matchers: %w", err)
	}
	cfg.Matchers = matchers

	apps, err := ParseTechStack(configDir + "/techstack.csv")
	if err != nil {
		return nil, nil, fmt.Errorf("techstack: %w", err)
	}

	return cfg, apps, nil
}

// ─────────────────────────────────────────────────────────────
// JSON helper
// ─────────────────────────────────────────────────────────────

func loadJSON(path string, v interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}
