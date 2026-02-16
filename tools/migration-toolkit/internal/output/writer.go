// Package output handles writing transformation results to disk.
package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Writer handles writing files to an output directory.
type Writer struct {
	baseDir string
}

// NewWriter creates a Writer that writes to the given base directory.
func NewWriter(baseDir string) *Writer {
	return &Writer{baseDir: baseDir}
}

// WriteYAML writes a single YAML document to a file.
func (w *Writer) WriteYAML(relPath string, data any) error {
	path := filepath.Join(w.baseDir, relPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating directory for %s: %w", relPath, err)
	}

	out, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshaling YAML for %s: %w", relPath, err)
	}

	if err := os.WriteFile(path, out, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", relPath, err)
	}
	return nil
}

// WriteYAMLMultiDoc writes multiple YAML documents separated by "---" to a file.
func (w *Writer) WriteYAMLMultiDoc(relPath string, docs []map[string]any) error {
	path := filepath.Join(w.baseDir, relPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating directory for %s: %w", relPath, err)
	}

	var parts []string
	for _, doc := range docs {
		out, err := yaml.Marshal(doc)
		if err != nil {
			return fmt.Errorf("marshaling YAML document: %w", err)
		}
		parts = append(parts, string(out))
	}

	content := strings.Join(parts, "---\n")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", relPath, err)
	}
	return nil
}

// WriteJSON writes formatted JSON to a file.
func (w *Writer) WriteJSON(relPath string, data any) error {
	path := filepath.Join(w.baseDir, relPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating directory for %s: %w", relPath, err)
	}

	out, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling JSON for %s: %w", relPath, err)
	}

	if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", relPath, err)
	}
	return nil
}

// WriteString writes a raw string to a file.
func (w *Writer) WriteString(relPath string, content string) error {
	path := filepath.Join(w.baseDir, relPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating directory for %s: %w", relPath, err)
	}

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", relPath, err)
	}
	return nil
}
