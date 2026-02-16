package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestNewWriter(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(dir)
	if w == nil {
		t.Fatal("expected non-nil Writer")
	}
	if w.baseDir != dir {
		t.Fatalf("expected baseDir %q, got %q", dir, w.baseDir)
	}
}

func TestWriteYAML_Simple(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(dir)

	data := map[string]any{"name": "test", "count": 42}
	if err := w.WriteYAML("test.yaml", data); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(filepath.Join(dir, "test.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	if err := yaml.Unmarshal(content, &got); err != nil {
		t.Fatalf("failed to unmarshal written YAML: %v", err)
	}
	if got["name"] != "test" {
		t.Errorf("expected name=test, got %v", got["name"])
	}
	if got["count"] != 42 {
		t.Errorf("expected count=42, got %v", got["count"])
	}
}

func TestWriteYAML_Nested(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(dir)

	data := map[string]any{
		"metadata": map[string]any{
			"name":      "my-resource",
			"namespace": "default",
		},
		"spec": map[string]any{
			"replicas": 3,
		},
	}
	if err := w.WriteYAML("nested.yaml", data); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(filepath.Join(dir, "nested.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	if err := yaml.Unmarshal(content, &got); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	metadata, ok := got["metadata"].(map[string]any)
	if !ok {
		t.Fatal("expected metadata to be a map")
	}
	if metadata["name"] != "my-resource" {
		t.Errorf("expected metadata.name=my-resource, got %v", metadata["name"])
	}
	if metadata["namespace"] != "default" {
		t.Errorf("expected metadata.namespace=default, got %v", metadata["namespace"])
	}

	spec, ok := got["spec"].(map[string]any)
	if !ok {
		t.Fatal("expected spec to be a map")
	}
	if spec["replicas"] != 3 {
		t.Errorf("expected spec.replicas=3, got %v", spec["replicas"])
	}
}

func TestWriteYAML_CreatesSubdirs(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(dir)

	relPath := filepath.Join("sub", "dir", "file.yaml")
	data := map[string]any{"key": "value"}
	if err := w.WriteYAML(relPath, data); err != nil {
		t.Fatal(err)
	}

	fullPath := filepath.Join(dir, relPath)
	info, err := os.Stat(fullPath)
	if err != nil {
		t.Fatalf("expected file to exist at %s: %v", fullPath, err)
	}
	if info.IsDir() {
		t.Fatal("expected a file, not a directory")
	}

	parentDir := filepath.Dir(fullPath)
	dirInfo, err := os.Stat(parentDir)
	if err != nil {
		t.Fatalf("expected parent directory to exist: %v", err)
	}
	if !dirInfo.IsDir() {
		t.Fatal("expected parent path to be a directory")
	}
}

func TestWriteYAMLMultiDoc_TwoDocs(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(dir)

	docs := []map[string]any{
		{"apiVersion": "v1", "kind": "ConfigMap"},
		{"apiVersion": "v1", "kind": "Secret"},
	}
	if err := w.WriteYAMLMultiDoc("multi.yaml", docs); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(filepath.Join(dir, "multi.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	text := string(content)
	if !strings.Contains(text, "---\n") {
		t.Error("expected multi-doc YAML to contain '---' separator")
	}

	// Split on the separator and verify both docs are present.
	parts := strings.Split(text, "---\n")
	if len(parts) != 2 {
		t.Fatalf("expected 2 parts separated by '---', got %d", len(parts))
	}

	var doc1, doc2 map[string]any
	if err := yaml.Unmarshal([]byte(parts[0]), &doc1); err != nil {
		t.Fatalf("failed to unmarshal first doc: %v", err)
	}
	if err := yaml.Unmarshal([]byte(parts[1]), &doc2); err != nil {
		t.Fatalf("failed to unmarshal second doc: %v", err)
	}
	if doc1["kind"] != "ConfigMap" {
		t.Errorf("expected first doc kind=ConfigMap, got %v", doc1["kind"])
	}
	if doc2["kind"] != "Secret" {
		t.Errorf("expected second doc kind=Secret, got %v", doc2["kind"])
	}
}

func TestWriteYAMLMultiDoc_SingleDoc(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(dir)

	docs := []map[string]any{
		{"only": "one"},
	}
	if err := w.WriteYAMLMultiDoc("single.yaml", docs); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(filepath.Join(dir, "single.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	text := string(content)
	if strings.Contains(text, "---") {
		t.Error("expected single-doc output to not contain '---' separator")
	}

	var got map[string]any
	if err := yaml.Unmarshal(content, &got); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if got["only"] != "one" {
		t.Errorf("expected only=one, got %v", got["only"])
	}
}

func TestWriteJSON_Simple(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(dir)

	data := map[string]any{"host": "localhost", "port": 8080}
	if err := w.WriteJSON("config.json", data); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	if err := json.Unmarshal(content, &got); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	if got["host"] != "localhost" {
		t.Errorf("expected host=localhost, got %v", got["host"])
	}
	// json.Unmarshal decodes numbers as float64.
	if got["port"] != float64(8080) {
		t.Errorf("expected port=8080, got %v", got["port"])
	}
}

func TestWriteJSON_HasTrailingNewline(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(dir)

	data := map[string]any{"key": "value"}
	if err := w.WriteJSON("out.json", data); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(filepath.Join(dir, "out.json"))
	if err != nil {
		t.Fatal(err)
	}

	if len(content) == 0 {
		t.Fatal("expected non-empty file")
	}
	if content[len(content)-1] != '\n' {
		t.Error("expected JSON output to end with a trailing newline")
	}
}

func TestWriteJSON_Indented(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(dir)

	data := map[string]any{"nested": map[string]any{"key": "value"}}
	if err := w.WriteJSON("indented.json", data); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(filepath.Join(dir, "indented.json"))
	if err != nil {
		t.Fatal(err)
	}

	text := string(content)
	// MarshalIndent with 2-space indent produces lines starting with "  ".
	if !strings.Contains(text, "  ") {
		t.Error("expected indented JSON output to contain 2-space indentation")
	}
}

func TestWriteString_Simple(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(dir)

	want := "hello, world!\nline two\n"
	if err := w.WriteString("output.txt", want); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(filepath.Join(dir, "output.txt"))
	if err != nil {
		t.Fatal(err)
	}

	got := string(content)
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestWriteString_CreatesSubdirs(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(dir)

	relPath := filepath.Join("deep", "nested", "path", "file.txt")
	if err := w.WriteString(relPath, "content"); err != nil {
		t.Fatal(err)
	}

	fullPath := filepath.Join(dir, relPath)
	info, err := os.Stat(fullPath)
	if err != nil {
		t.Fatalf("expected file to exist at %s: %v", fullPath, err)
	}
	if info.IsDir() {
		t.Fatal("expected a file, not a directory")
	}

	content, err := os.ReadFile(fullPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "content" {
		t.Errorf("expected %q, got %q", "content", string(content))
	}
}
