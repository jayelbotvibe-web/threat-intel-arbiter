// Package config parses and validates threatlib configuration files.
package config

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jayelbotvibe-web/threatlib/internal/model"
)

// ParseTechStack reads a CSV file and returns the application inventory.
// Expected columns: name,version,vendor,category,criticality,owner_team,internet_facing,hosts,data_sensitivity
func ParseTechStack(path string) ([]model.App, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	return ParseTechStackReader(f)
}

// ParseTechStackReader reads a CSV from an io.Reader.
func ParseTechStackReader(r io.Reader) ([]model.App, error) {
	reader := csv.NewReader(r)
	reader.TrimLeadingSpace = true

	// Read header
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	// Map column indices
	cols := make(map[string]int)
	for i, h := range header {
		cols[strings.TrimSpace(strings.ToLower(h))] = i
	}

	var apps []model.App
	line := 1
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		line++

		app := model.App{
			Name:            getCol(record, cols, "name"),
			Version:         getCol(record, cols, "version"),
			Vendor:          getCol(record, cols, "vendor"),
			Category:        getCol(record, cols, "category"),
			Criticality:     getCol(record, cols, "criticality"),
			OwnerTeam:       getCol(record, cols, "owner_team"),
			InternetFacing:  getColBool(record, cols, "internet_facing"),
			Hosts:           getCol(record, cols, "hosts"),
			DataSensitivity: getCol(record, cols, "data_sensitivity"),
		}

		if app.Name == "" {
			continue // skip empty rows
		}

		// Validate criticality
		switch app.Criticality {
		case "critical", "high", "medium", "low":
		default:
			app.Criticality = "medium"
		}

		// Validate data_sensitivity
		switch app.DataSensitivity {
		case "critical", "high", "medium", "low":
		default:
			app.DataSensitivity = "medium"
		}

		apps = append(apps, app)
	}

	return apps, nil
}

// ComputeDelta compares a new tech stack against the existing one and returns
// lists of added, removed, and modified apps.
func ComputeDelta(newApps, existingApps []model.App) (added, removed, modified []model.App) {
	existingMap := make(map[string]model.App)
	for _, app := range existingApps {
		existingMap[appKey(app)] = app
	}

	newMap := make(map[string]model.App)
	for _, app := range newApps {
		key := appKey(app)
		newMap[key] = app

		existing, exists := existingMap[key]
		if !exists {
			added = append(added, app)
		} else if appChanged(app, existing) {
			modified = append(modified, app)
		}
	}

	for key, app := range existingMap {
		if _, exists := newMap[key]; !exists {
			removed = append(removed, app)
		}
	}

	return added, removed, modified
}

// appKey returns a unique key for an app (vendor + name combination).
func appKey(app model.App) string {
	return strings.ToLower(strings.TrimSpace(app.Vendor)) + ":" + strings.ToLower(strings.TrimSpace(app.Name))
}

// appChanged returns true if criticality, internet_facing, or data_sensitivity changed.
func appChanged(new, old model.App) bool {
	return new.Criticality != old.Criticality ||
		new.InternetFacing != old.InternetFacing ||
		new.DataSensitivity != old.DataSensitivity ||
		new.Version != old.Version
}

// getCol returns a column value by name, or empty string if not found.
func getCol(record []string, cols map[string]int, name string) string {
	idx, ok := cols[name]
	if !ok || idx >= len(record) {
		return ""
	}
	return strings.TrimSpace(record[idx])
}

// getColBool returns a boolean column value.
func getColBool(record []string, cols map[string]int, name string) bool {
	val := strings.ToLower(getCol(record, cols, name))
	return val == "true" || val == "yes" || val == "1"
}
