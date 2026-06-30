package store

import (
	"fmt"

	"github.com/jayelbotvibe-web/threatlib/internal/model"
)

// ImportTechStack replaces the tech stack with the given apps and returns delta info.
func (db *DB) ImportTechStack(apps []model.App) (added, removed int, err error) {
	tx, err := db.conn.Begin()
	if err != nil {
		return 0, 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Read existing apps for delta computation
	existing, err := db.ListTechStack()
	if err != nil {
		return 0, 0, fmt.Errorf("list existing: %w", err)
	}

	// Build set of new app keys
	newKeys := make(map[string]bool)
	for _, app := range apps {
		key := appKey(app)
		newKeys[key] = true
	}

	// Count removed apps (in existing but not in new)
	for _, existing := range existing {
		key := appKey(existing)
		if !newKeys[key] {
			removed++
		}
	}

	// Count added apps (in new but not in existing)
	existingKeys := make(map[string]bool)
	for _, existing := range existing {
		existingKeys[appKey(existing)] = true
	}
	for _, app := range apps {
		key := appKey(app)
		if !existingKeys[key] {
			added++
		}
	}

	// Delete old stack and insert new
	if _, err := tx.Exec("DELETE FROM tech_stack"); err != nil {
		return 0, 0, fmt.Errorf("delete old: %w", err)
	}

	stmt, err := tx.Prepare(`INSERT INTO tech_stack
		(name, version, vendor, category, criticality, owner_team, internet_facing, hosts, data_sensitivity, org_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'default')`)
	if err != nil {
		return 0, 0, fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()

	for _, app := range apps {
		inet := 0
		if app.InternetFacing {
			inet = 1
		}
		if _, err := stmt.Exec(app.Name, app.Version, app.Vendor, app.Category,
			app.Criticality, app.OwnerTeam, inet, app.Hosts, app.DataSensitivity); err != nil {
			return 0, 0, fmt.Errorf("insert %s: %w", app.Name, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("commit: %w", err)
	}

	return added, removed, nil
}

// ListTechStack returns all applications in the tech stack.
func (db *DB) ListTechStack() ([]model.App, error) {
	rows, err := db.conn.Query(`SELECT name, version, vendor, category, criticality,
		owner_team, internet_facing, hosts, data_sensitivity FROM tech_stack ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	var apps []model.App
	for rows.Next() {
		var app model.App
		var inet int
		if err := rows.Scan(&app.Name, &app.Version, &app.Vendor, &app.Category,
			&app.Criticality, &app.OwnerTeam, &inet, &app.Hosts, &app.DataSensitivity); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		app.InternetFacing = inet == 1
		apps = append(apps, app)
	}
	return apps, rows.Err()
}

// FindAppsByVendorProduct finds tech stack entries matching a vendor and product name.
func (db *DB) FindAppsByVendorProduct(vendor, product string) ([]model.App, error) {
	rows, err := db.conn.Query(`SELECT name, version, vendor, category, criticality,
		owner_team, internet_facing, hosts, data_sensitivity FROM tech_stack
		WHERE (LOWER(vendor) = LOWER(?) OR LOWER(name) = LOWER(?))
		ORDER BY name`, vendor, product)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	var apps []model.App
	for rows.Next() {
		var app model.App
		var inet int
		if err := rows.Scan(&app.Name, &app.Version, &app.Vendor, &app.Category,
			&app.Criticality, &app.OwnerTeam, &inet, &app.Hosts, &app.DataSensitivity); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		app.InternetFacing = inet == 1
		apps = append(apps, app)
	}
	return apps, rows.Err()
}

// appKey returns a unique key for an app.
func appKey(app model.App) string {
	return app.Vendor + ":" + app.Name
}
