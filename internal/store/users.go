package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
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

// CreateSession generates a token, stores its SHA-256 hash in DB, returns raw token for cookie.
func (db *DB) CreateSession(username, role string) (string, error) {
	token := generateToken()
	tokenHash := sha256Hex(token)
	expires := time.Now().Add(12 * time.Hour).Format(time.RFC3339)
	_, err := db.conn.Exec(
		"INSERT INTO sessions (token, username, role, expires_at) VALUES (?, ?, ?, ?)",
		tokenHash, username, role, expires,
	)
	if err != nil {
		return "", err
	}
	return token, nil
}

// GetSession looks up a session by hashing the raw token from the cookie.
func (db *DB) GetSession(token string) (username, role string, ok bool) {
	tokenHash := sha256Hex(token)
	var expires string
	err := db.conn.QueryRow(
		"SELECT username, role, expires_at FROM sessions WHERE token = ?", tokenHash,
	).Scan(&username, &role, &expires)
	if err != nil {
		return "", "", false
	}
	exp, err := time.Parse(time.RFC3339, expires)
	if err != nil || time.Now().After(exp) {
		db.conn.Exec("DELETE FROM sessions WHERE token = ?", tokenHash)
		return "", "", false
	}
	return username, role, true
}

// DeleteSession removes a session by hashing the raw token.
func (db *DB) DeleteSession(token string) {
	tokenHash := sha256Hex(token)
	db.conn.Exec("DELETE FROM sessions WHERE token = ?", tokenHash)
}

// CleanExpiredSessions removes expired sessions.
func (db *DB) CleanExpiredSessions() {
	db.conn.Exec("DELETE FROM sessions WHERE expires_at < ?", time.Now().Format(time.RFC3339))
}

// ─── Password hashing (Argon2id with legacy SHA-256 support) ───

const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MB
	argonThreads = 4
	argonKeyLen  = 32
	argonPrefix  = "$argon2id$v=19$m=65536,t=3,p=4$"
)

func hashPassword(password string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return argonPrefix + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash)
}

func verifyHash(password, stored string) bool {
	if strings.HasPrefix(stored, "$argon2id$") {
		return verifyArgon2(password, stored)
	}
	// Legacy SHA-256 hash
	return verifyLegacy(password, stored)
}

func verifyArgon2(password, stored string) bool {
	rest := strings.TrimPrefix(stored, argonPrefix)
	parts := strings.SplitN(rest, "$", 2)
	if len(parts) != 2 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, uint32(len(expected)))
	return subtle.ConstantTimeCompare(hash, expected) == 1
}

func verifyLegacy(password, stored string) bool {
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

// IsLegacyHash returns true if the stored hash uses the old SHA-256 format.
func IsLegacyHash(stored string) bool {
	return !strings.HasPrefix(stored, "$argon2id$") && strings.Contains(stored, ":")
}

// RehashPassword re-hashes a password with Argon2id and returns the new hash.
func RehashPassword(password string) string {
	return hashPassword(password)
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
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
// Generates a random 16-character password printed once to stdout.
func (db *DB) seedDefaultAdmin() error {
	var count int
	db.conn.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if count > 0 {
		return nil
	}
	pw := randomPassword(16)
	log.Printf("============================================================")
	log.Printf("  FIRST RUN: default admin user created")
	log.Printf("  Username: admin")
	log.Printf("  Password: %s", pw)
	log.Printf("  CHANGE THIS PASSWORD IMMEDIATELY via the Users panel")
	log.Printf("  This message appears once — the password is NOT stored in logs")
	log.Printf("============================================================")
	return db.CreateUser("admin", pw, "admin")
}

func randomPassword(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}
