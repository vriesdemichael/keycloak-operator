package userimport

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeFile(t *testing.T, dir string, name string, content any) string {
	t.Helper()
	data, err := json.Marshal(content)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	return path
}

func TestLoadUsersFile_ValidArray(t *testing.T) {
	dir := t.TempDir()
	users := []map[string]any{
		{"username": "alice", "email": "alice@example.com"},
		{"username": "bob"},
	}
	path := writeFile(t, dir, "users.json", users)

	res, err := LoadUsersFile(path, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.UserCount != 2 {
		t.Errorf("expected 2 users, got %d", res.UserCount)
	}
	if len(res.Users) != 2 {
		t.Errorf("expected 2 entries in Users slice, got %d", len(res.Users))
	}
}

func TestLoadUsersFile_EmptyArray(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "users.json", []any{})

	res, err := LoadUsersFile(path, 0)
	if err != nil {
		t.Fatalf("unexpected error for empty array: %v", err)
	}
	if res.UserCount != 0 {
		t.Errorf("expected 0 users, got %d", res.UserCount)
	}
}

func TestLoadUsersFile_JSONObject_Rejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "obj.json")
	if err := os.WriteFile(path, []byte(`{"username":"x"}`), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadUsersFile(path, 0)
	if err == nil {
		t.Fatal("expected error for JSON object input, got nil")
	}
}

func TestLoadUsersFile_MissingUsername(t *testing.T) {
	dir := t.TempDir()
	users := []map[string]any{
		{"email": "no-username@example.com"},
	}
	path := writeFile(t, dir, "users.json", users)

	_, err := LoadUsersFile(path, 0)
	if err == nil {
		t.Fatal("expected error for missing username field")
	}
}

func TestLoadUsersFile_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte(`not json`), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadUsersFile(path, 0)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoadUsersFile_MaxAgeEnforced(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "users.json", []map[string]any{{"username": "x"}})

	// Set mtime to 2 hours ago
	twoHoursAgo := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(path, twoHoursAgo, twoHoursAgo); err != nil {
		t.Fatal(err)
	}

	_, err := LoadUsersFile(path, 1*time.Hour)
	if err == nil {
		t.Fatal("expected age-check error for file older than maxAge")
	}
}

func TestLoadUsersFile_MaxAgeZeroSkipsCheck(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "users.json", []map[string]any{{"username": "x"}})

	// Set mtime to 48 hours ago — would fail if check were active
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}

	res, err := LoadUsersFile(path, 0)
	if err != nil {
		t.Fatalf("maxAge=0 should skip age check, got: %v", err)
	}
	if res.UserCount != 1 {
		t.Errorf("expected 1 user, got %d", res.UserCount)
	}
}

func TestLoadUsersFile_FileNotFound(t *testing.T) {
	_, err := LoadUsersFile("/nonexistent/path/users.json", 0)
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}
