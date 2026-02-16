package export

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParse_MinimalRealm(t *testing.T) {
	data := []byte(`{"realm": "test-realm", "enabled": true}`)
	exp, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if exp.GetString("realm") != "test-realm" {
		t.Errorf("GetString(realm) = %q, want %q", exp.GetString("realm"), "test-realm")
	}
}

func TestParse_MissingRealmField(t *testing.T) {
	data := []byte(`{"name": "not-a-realm"}`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("Parse() expected error for missing 'realm' field, got nil")
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	data := []byte(`{invalid json}`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("Parse() expected error for invalid JSON, got nil")
	}
}

func TestGetString(t *testing.T) {
	exp := &RealmExport{Raw: map[string]any{
		"realm":       "my-realm",
		"displayName": "Display Name",
		"notString":   42,
	}}

	tests := []struct {
		key  string
		want string
	}{
		{"realm", "my-realm"},
		{"displayName", "Display Name"},
		{"notString", ""}, // non-string returns ""
		{"missing", ""},   // missing key returns ""
	}

	for _, tt := range tests {
		got := exp.GetString(tt.key)
		if got != tt.want {
			t.Errorf("GetString(%q) = %q, want %q", tt.key, got, tt.want)
		}
	}
}

func TestGetBool(t *testing.T) {
	exp := &RealmExport{Raw: map[string]any{
		"enabled":  true,
		"disabled": false,
		"notBool":  "true",
	}}

	tests := []struct {
		key        string
		defaultVal bool
		want       bool
	}{
		{"enabled", false, true},
		{"disabled", true, false},
		{"notBool", false, false}, // non-bool returns default
		{"missing", true, true},   // missing returns default
	}

	for _, tt := range tests {
		got := exp.GetBool(tt.key, tt.defaultVal)
		if got != tt.want {
			t.Errorf("GetBool(%q, %v) = %v, want %v", tt.key, tt.defaultVal, got, tt.want)
		}
	}
}

func TestGetInt(t *testing.T) {
	exp := &RealmExport{Raw: map[string]any{
		"count":  float64(42),
		"zero":   float64(0),
		"notInt": "hello",
	}}

	tests := []struct {
		key        string
		defaultVal int
		want       int
	}{
		{"count", 0, 42},
		{"zero", 99, 0},
		{"notInt", 7, 7},    // non-numeric returns default
		{"missing", 10, 10}, // missing returns default
	}

	for _, tt := range tests {
		got := exp.GetInt(tt.key, tt.defaultVal)
		if got != tt.want {
			t.Errorf("GetInt(%q, %d) = %d, want %d", tt.key, tt.defaultVal, got, tt.want)
		}
	}
}

func TestGetArray(t *testing.T) {
	exp := &RealmExport{Raw: map[string]any{
		"items":    []any{"a", "b", "c"},
		"notArray": "hello",
	}}

	arr := exp.GetArray("items")
	if len(arr) != 3 {
		t.Errorf("GetArray(items) len = %d, want 3", len(arr))
	}

	nilArr := exp.GetArray("notArray")
	if nilArr != nil {
		t.Errorf("GetArray(notArray) expected nil, got %v", nilArr)
	}

	nilArr2 := exp.GetArray("missing")
	if nilArr2 != nil {
		t.Errorf("GetArray(missing) expected nil, got %v", nilArr2)
	}
}

func TestGetMap(t *testing.T) {
	exp := &RealmExport{Raw: map[string]any{
		"config": map[string]any{"key": "value"},
		"notMap": "hello",
	}}

	m := exp.GetMap("config")
	if m == nil || m["key"] != "value" {
		t.Errorf("GetMap(config) = %v, expected map with key=value", m)
	}

	nilMap := exp.GetMap("notMap")
	if nilMap != nil {
		t.Errorf("GetMap(notMap) expected nil, got %v", nilMap)
	}
}

func TestHasKey(t *testing.T) {
	exp := &RealmExport{Raw: map[string]any{
		"present":  "value",
		"nilValue": nil,
	}}

	if !exp.HasKey("present") {
		t.Error("HasKey(present) = false, want true")
	}
	if exp.HasKey("nilValue") {
		t.Error("HasKey(nilValue) = true, want false (nil value)")
	}
	if exp.HasKey("absent") {
		t.Error("HasKey(absent) = true, want false")
	}
}

func TestClients(t *testing.T) {
	exp := &RealmExport{Raw: map[string]any{
		"clients": []any{
			map[string]any{"clientId": "client-a"},
			map[string]any{"clientId": "client-b"},
			"not-a-map", // should be skipped
		},
	}}

	clients := exp.Clients()
	if len(clients) != 2 {
		t.Fatalf("Clients() len = %d, want 2", len(clients))
	}
	if clients[0]["clientId"] != "client-a" {
		t.Errorf("Clients()[0].clientId = %v, want client-a", clients[0]["clientId"])
	}
}

func TestClients_Nil(t *testing.T) {
	exp := &RealmExport{Raw: map[string]any{}}
	if exp.Clients() != nil {
		t.Error("Clients() on empty export should return nil")
	}
}

func TestUsers(t *testing.T) {
	exp := &RealmExport{Raw: map[string]any{
		"users": []any{
			map[string]any{"username": "admin"},
		},
	}}

	users := exp.Users()
	if len(users) != 1 {
		t.Fatalf("Users() len = %d, want 1", len(users))
	}
	if users[0]["username"] != "admin" {
		t.Errorf("Users()[0].username = %v, want admin", users[0]["username"])
	}
}

func TestComponents(t *testing.T) {
	exp := &RealmExport{Raw: map[string]any{
		"components": map[string]any{
			"org.keycloak.storage.UserStorageProvider": []any{},
		},
	}}

	c := exp.Components()
	if c == nil {
		t.Fatal("Components() returned nil")
	}
	if _, ok := c["org.keycloak.storage.UserStorageProvider"]; !ok {
		t.Error("Components() missing expected key")
	}
}

func TestParseFile_MinimalFixture(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "minimal-realm.json")
	exp, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile() error: %v", err)
	}
	if exp.GetString("realm") != "minimal-test" {
		t.Errorf("realm = %q, want %q", exp.GetString("realm"), "minimal-test")
	}
	if !exp.GetBool("enabled", false) {
		t.Error("enabled should be true")
	}
	clients := exp.Clients()
	if len(clients) != 2 {
		t.Errorf("expected 2 clients, got %d", len(clients))
	}
}

func TestParseFile_MediumFixture(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "medium-realm.json")
	exp, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile() error: %v", err)
	}
	if exp.GetString("realm") != "medium-test" {
		t.Errorf("realm = %q, want %q", exp.GetString("realm"), "medium-test")
	}

	// Verify SMTP is parsed
	smtp := exp.GetMap("smtpServer")
	if smtp == nil {
		t.Fatal("smtpServer should not be nil")
	}
	if smtp["host"] != "smtp.example.com" {
		t.Errorf("smtp host = %v, want smtp.example.com", smtp["host"])
	}

	// Verify users
	users := exp.Users()
	if len(users) != 2 {
		t.Errorf("expected 2 users, got %d", len(users))
	}
}

func TestParseFile_MaximalFixture(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "maximal-realm.json")
	exp, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile() error: %v", err)
	}
	if exp.GetString("realm") != "maximal-test" {
		t.Errorf("realm = %q, want %q", exp.GetString("realm"), "maximal-test")
	}

	// Verify components
	components := exp.Components()
	if components == nil {
		t.Fatal("components should not be nil")
	}

	// Verify client profiles is a map (wrapped format)
	cpMap := exp.GetMap("clientProfiles")
	if cpMap == nil {
		t.Fatal("clientProfiles should be a map (wrapped format)")
	}

	// Verify identity providers
	idps := exp.GetArray("identityProviders")
	if len(idps) != 2 {
		t.Errorf("expected 2 identity providers, got %d", len(idps))
	}
}

func TestParseFile_NonExistent(t *testing.T) {
	_, err := ParseFile("/nonexistent/path/file.json")
	if err == nil {
		t.Fatal("ParseFile() expected error for non-existent file")
	}
}

func TestParseDirectory(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata")
	exports, err := ParseDirectory(dir)
	if err != nil {
		t.Fatalf("ParseDirectory() error: %v", err)
	}
	if len(exports) != 3 {
		t.Errorf("ParseDirectory() returned %d exports, want 3", len(exports))
	}

	// Verify all three realms are present
	realmNames := make(map[string]bool)
	for _, exp := range exports {
		realmNames[exp.GetString("realm")] = true
	}
	for _, expected := range []string{"minimal-test", "medium-test", "maximal-test"} {
		if !realmNames[expected] {
			t.Errorf("ParseDirectory() missing realm %q", expected)
		}
	}
}

func TestParseDirectory_Empty(t *testing.T) {
	dir := t.TempDir()
	_, err := ParseDirectory(dir)
	if err == nil {
		t.Fatal("ParseDirectory() expected error for empty directory")
	}
}

func TestParseDirectory_NonExistent(t *testing.T) {
	_, err := ParseDirectory("/nonexistent/path")
	if err == nil {
		t.Fatal("ParseDirectory() expected error for non-existent directory")
	}
}

func TestParseDirectory_SkipsNonJSON(t *testing.T) {
	dir := t.TempDir()

	// Write a valid JSON file
	validJSON := []byte(`{"realm": "test-realm", "enabled": true}`)
	if err := os.WriteFile(filepath.Join(dir, "valid.json"), validJSON, 0o644); err != nil {
		t.Fatal(err)
	}

	// Write a non-JSON file
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	exports, err := ParseDirectory(dir)
	if err != nil {
		t.Fatalf("ParseDirectory() error: %v", err)
	}
	if len(exports) != 1 {
		t.Errorf("expected 1 export (JSON only), got %d", len(exports))
	}
}
