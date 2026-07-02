package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

// User represents a dashboard user account.
type User struct {
	Username     string `json:"username"`
	PasswordHash string `json:"-"`
	Role         string `json:"role"` // "admin" or "reader"
}

// CreateUser inserts a new user with a hashed password.
func (db *DB) CreateUser(username, password, role string) error {
	hash := hashPassword(password)
	_, err := db.conn.Exec(
		"INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
		username, hash, role,
	)
	return err
}

// GetUser returns a user by username, or nil if not found.
func (db *DB) GetUser(username string) (*User, error) {
	var u User
	err := db.conn.QueryRow(
		"SELECT username, password_hash, role FROM users WHERE username = ?", username,
	).Scan(&u.Username, &u.PasswordHash, &u.Role)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// ListUsers returns all users.
func (db *DB) ListUsers() ([]User, error) {
	rows, err := db.conn.Query("SELECT username, role FROM users ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.Username, &u.Role); err != nil {
			continue
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// UpdateUser updates a user's password and/or role.
func (db *DB) UpdateUser(username, password, role string) error {
	if password != "" {
		hash := hashPassword(password)
		_, err := db.conn.Exec("UPDATE users SET password_hash=?, role=? WHERE username=?",
			hash, role, username)
		return err
	}
	_, err := db.conn.Exec("UPDATE users SET role=? WHERE username=?", role, username)
	return err
}

// DeleteUser removes a user. Cannot delete the last admin.
func (db *DB) DeleteUser(username string) error {
	// Prevent deleting the last admin
	var adminCount int
	db.conn.QueryRow("SELECT COUNT(*) FROM users WHERE role='admin' AND username != ?", username).Scan(&adminCount)
	if adminCount == 0 {
		return fmt.Errorf("cannot delete the last admin user")
	}
	_, err := db.conn.Exec("DELETE FROM users WHERE username=?", username)
	return err
}

// VerifyPassword checks a password against the stored hash.
func (db *DB) VerifyPassword(username, password string) bool {
	u, err := db.GetUser(username)
	if err != nil || u == nil {
		return false
	}
	return verifyHash(password, u.PasswordHash)
}

// ─── Sessions ───

// CreateSession generates a token and stores it with expiry.
func (db *DB) CreateSession(username, role string) (string, error) {
	token := generateToken()
	expires := time.Now().Add(12 * time.Hour).Format(time.RFC3339)
	_, err := db.conn.Exec(
		"INSERT INTO sessions (token, username, role, expires_at) VALUES (?, ?, ?, ?)",
		token, username, role, expires,
	)
	if err != nil {
		return "", err
	}
	return token, nil
}

// GetSession returns username+role for a valid token, or empty if expired/invalid.
func (db *DB) GetSession(token string) (username, role string, ok bool) {
	var expires string
	err := db.conn.QueryRow(
		"SELECT username, role, expires_at FROM sessions WHERE token = ?", token,
	).Scan(&username, &role, &expires)
	if err != nil {
		return "", "", false
	}
	exp, err := time.Parse(time.RFC3339, expires)
	if err != nil || time.Now().After(exp) {
		db.conn.Exec("DELETE FROM sessions WHERE token = ?", token)
		return "", "", false
	}
	return username, role, true
}

// DeleteSession removes a session token (logout).
func (db *DB) DeleteSession(token string) {
	db.conn.Exec("DELETE FROM sessions WHERE token = ?", token)
}

// CleanExpiredSessions removes expired sessions.
func (db *DB) CleanExpiredSessions() {
	db.conn.Exec("DELETE FROM sessions WHERE expires_at < ?", time.Now().Format(time.RFC3339))
}

// ─── Password hashing (stdlib: SHA-256 + random salt) ───

func hashPassword(password string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	h := sha256.Sum256(append(salt, []byte(password)...))
	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(h[:])
}

func verifyHash(password, stored string) bool {
	parts := splitN(stored, ":", 2)
	if len(parts) != 2 {
		return false
	}
	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return false
	}
	h := sha256.Sum256(append(salt, []byte(password)...))
	return hex.EncodeToString(h[:]) == parts[1]
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func splitN(s, sep string, n int) []string {
	result := []string{}
	for i := 0; i < n-1; i++ {
		idx := indexOf(s, sep)
		if idx < 0 {
			result = append(result, s)
			return result
		}
		result = append(result, s[:idx])
		s = s[idx+len(sep):]
	}
	result = append(result, s)
	return result
}

func indexOf(s, sep string) int {
	for i := 0; i <= len(s)-len(sep); i++ {
		if s[i:i+len(sep)] == sep {
			return i
		}
	}
	return -1
}

// seedDefaultAdmin creates the default admin user if no users exist.
func (db *DB) seedDefaultAdmin() error {
	var count int
	db.conn.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if count > 0 {
		return nil
	}
	// Default admin: admin / arbiter (user must change on first login)
	return db.CreateUser("admin", "arbiter", "admin")
}
