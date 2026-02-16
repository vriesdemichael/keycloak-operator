// Package export handles parsing Keycloak realm export JSON files.
package export

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// RealmExport represents a Keycloak realm export JSON structure.
// We use map[string]any for flexibility since the export format varies
// between Keycloak versions and we want to handle unknown fields gracefully.
type RealmExport struct {
	Raw map[string]any
}

// GetString returns a string field from the export, or empty string if missing.
func (r *RealmExport) GetString(key string) string {
	if v, ok := r.Raw[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// GetBool returns a bool field from the export, or the default if missing.
func (r *RealmExport) GetBool(key string, defaultVal bool) bool {
	if v, ok := r.Raw[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return defaultVal
}

// GetInt returns an integer field from the export, or the default if missing.
func (r *RealmExport) GetInt(key string, defaultVal int) int {
	if v, ok := r.Raw[key]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case json.Number:
			if i, err := n.Int64(); err == nil {
				return int(i)
			}
		}
	}
	return defaultVal
}

// GetArray returns an array field from the export, or nil if missing.
func (r *RealmExport) GetArray(key string) []any {
	if v, ok := r.Raw[key]; ok {
		if arr, ok := v.([]any); ok {
			return arr
		}
	}
	return nil
}

// GetMap returns a map field from the export, or nil if missing.
func (r *RealmExport) GetMap(key string) map[string]any {
	if v, ok := r.Raw[key]; ok {
		if m, ok := v.(map[string]any); ok {
			return m
		}
	}
	return nil
}

// HasKey returns true if the export contains the given key with a non-nil value.
func (r *RealmExport) HasKey(key string) bool {
	v, ok := r.Raw[key]
	return ok && v != nil
}

// Clients returns the clients array from the export.
func (r *RealmExport) Clients() []map[string]any {
	arr := r.GetArray("clients")
	if arr == nil {
		return nil
	}
	result := make([]map[string]any, 0, len(arr))
	for _, item := range arr {
		if m, ok := item.(map[string]any); ok {
			result = append(result, m)
		}
	}
	return result
}

// Users returns the users array from the export.
func (r *RealmExport) Users() []map[string]any {
	arr := r.GetArray("users")
	if arr == nil {
		return nil
	}
	result := make([]map[string]any, 0, len(arr))
	for _, item := range arr {
		if m, ok := item.(map[string]any); ok {
			result = append(result, m)
		}
	}
	return result
}

// Components returns the components map from the export.
func (r *RealmExport) Components() map[string]any {
	return r.GetMap("components")
}

// ParseFile reads and parses a single Keycloak realm export JSON file.
func ParseFile(path string) (*RealmExport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading export file %s: %w", path, err)
	}
	return Parse(data)
}

// Parse parses Keycloak realm export JSON bytes.
func Parse(data []byte) (*RealmExport, error) {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing export JSON: %w", err)
	}

	// Validate this looks like a realm export
	if _, ok := raw["realm"]; !ok {
		return nil, fmt.Errorf("JSON does not appear to be a Keycloak realm export: missing 'realm' field")
	}

	return &RealmExport{Raw: raw}, nil
}

// ParseDirectory reads all JSON files in a directory and parses them as realm exports.
func ParseDirectory(dir string) ([]*RealmExport, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading directory %s: %w", dir, err)
	}

	var exports []*RealmExport
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		export, err := ParseFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", entry.Name(), err)
		}
		exports = append(exports, export)
	}

	if len(exports) == 0 {
		return nil, fmt.Errorf("no realm export JSON files found in %s", dir)
	}

	return exports, nil
}
