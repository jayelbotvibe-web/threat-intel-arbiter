package store

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/argon2"
)

// newTestDB creates a temporary in-memory DB for tests.
func newTestDB(t *testing.T) (*DB, func()) {
	t.Helper()
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	return db, func() { db.Close() }
}

// TestUpdateUser_CannotDemoteLastAdmin verifies that demoting the last admin
// to reader is blocked to prevent lockout.
func TestUpdateUser_CannotDemoteLastAdmin(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	// Create a single admin user (seeded admin)
	admin, err := db.GetUser("admin")
	if err != nil || admin == nil {
		t.Fatalf("admin not seeded: %v", err)
	}
	if admin.Role != "admin" {
		t.Fatalf("seeded admin role = %s, want admin", admin.Role)
	}

	// Try to demote the last admin to reader
	err = db.UpdateUser("admin", "", "reader")
	if err == nil {
		t.Fatal("expected error when demoting last admin, got nil")
	}
	t.Logf("correctly blocked: %v", err)

	// Verify admin is still admin
	admin, _ = db.GetUser("admin")
	if admin.Role != "admin" {
		t.Errorf("admin role changed to %s, want admin", admin.Role)
	}
}

// TestUpdateUser_CanDemoteWhenOtherAdminExists verifies demotion succeeds
// when another admin exists.
func TestUpdateUser_CanDemoteWhenOtherAdminExists(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	// Create second admin
	if err := db.CreateUser("admin2", "pass123", "admin"); err != nil {
		t.Fatalf("create admin2: %v", err)
	}

	// Demote first admin to reader — should succeed
	if err := db.UpdateUser("admin", "", "reader"); err != nil {
		t.Fatalf("expected success when other admin exists, got: %v", err)
	}

	admin, _ := db.GetUser("admin")
	if admin.Role != "reader" {
		t.Errorf("admin role = %s, want reader", admin.Role)
	}
}

// TestDeleteUser_CannotDeleteLastAdmin verifies the existing guard still works.
func TestDeleteUser_CannotDeleteLastAdmin(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	err := db.DeleteUser("admin")
	if err == nil {
		t.Fatal("expected error when deleting last admin, got nil")
	}
	t.Logf("correctly blocked: %v", err)
}

// TestVerifyArgon2_ParsesParamsFromHash verifies that verifyArgon2 reads
// m/t/p parameters from the stored hash string rather than using package
// constants, so verification stays correct if cost constants ever change.
func TestVerifyArgon2_ParsesParamsFromHash(t *testing.T) {
	// Build a hash with different params than the current package constants.
	// Package defaults: m=65536,t=3,p=4. Custom params: m=32768,t=5,p=1.
	customSalt := make([]byte, 16)
	rand.Read(customSalt)

	customHash := argon2.IDKey([]byte("testpassword"), customSalt, 5, 32*1024, 1, 32)

	// Custom prefix with different m/t/p than the package constant argonPrefix
	customStored := "$argon2id$v=19$m=32768,t=5,p=1$" +
		base64.RawStdEncoding.EncodeToString(customSalt) + "$" +
		base64.RawStdEncoding.EncodeToString(customHash)

	// verifyArgon2 must parse params from the hash string, not use the
	// package-level argonPrefix constant which has m=65536,t=3,p=4.
	if !verifyArgon2("testpassword", customStored) {
		t.Error("verifyArgon2 rejected a hash with non-default params — " +
			"it may be ignoring hash-encoded m/t/p and using package constants")
	}

	// Wrong password should still fail
	if verifyArgon2("wrongpassword", customStored) {
		t.Error("verifyArgon2 accepted wrong password with non-default params")
	}
}
