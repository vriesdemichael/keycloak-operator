package transform

import (
	"fmt"
	"testing"

	"github.com/vriesdemichael/keycloak-operator/tools/migration-toolkit/internal/export"
)

func TestGenerateSecretManifests_NilInput(t *testing.T) {
	opts := defaultOpts()

	// nil input
	result := GenerateSecretManifests(nil, opts)
	if result != nil {
		t.Errorf("expected nil for nil input, got %v", result)
	}

	// empty slice
	result = GenerateSecretManifests([]SecretEntry{}, opts)
	if result != nil {
		t.Errorf("expected nil for empty input, got %v", result)
	}
}

func TestGenerateSecretManifests_PlainMode(t *testing.T) {
	opts := defaultOpts()
	opts.SecretMode = SecretModePlain

	secrets := []SecretEntry{
		{Name: "my-secret", Key: "password", Value: "s3cret", Description: "test", SourceField: "test.password"},
	}

	manifests := GenerateSecretManifests(secrets, opts)
	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(manifests))
	}

	m := manifests[0]
	if m["apiVersion"] != "v1" {
		t.Errorf("apiVersion = %v, want v1", m["apiVersion"])
	}
	if m["kind"] != "Secret" {
		t.Errorf("kind = %v, want Secret", m["kind"])
	}

	metadata := m["metadata"].(map[string]any)
	if metadata["name"] != "my-secret" {
		t.Errorf("metadata.name = %v, want my-secret", metadata["name"])
	}

	stringData := m["stringData"].(map[string]any)
	if stringData["password"] != "s3cret" {
		t.Errorf("stringData.password = %v, want s3cret", stringData["password"])
	}
}

func TestGenerateSecretManifests_ESOMode(t *testing.T) {
	opts := defaultOpts()
	opts.SecretMode = SecretModeESO
	opts.ESOStore = "my-store"
	opts.ESOStoreKind = "SecretStore"

	secrets := []SecretEntry{
		{Name: "my-secret", Key: "password", Value: "s3cret"},
	}

	manifests := GenerateSecretManifests(secrets, opts)
	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(manifests))
	}

	m := manifests[0]
	if m["apiVersion"] != "external-secrets.io/v1beta1" {
		t.Errorf("apiVersion = %v, want external-secrets.io/v1beta1", m["apiVersion"])
	}
	if m["kind"] != "ExternalSecret" {
		t.Errorf("kind = %v, want ExternalSecret", m["kind"])
	}
}

func TestGenerateSecretManifests_SealedSecretsMode(t *testing.T) {
	opts := defaultOpts()
	opts.SecretMode = SecretModeSealedSecrets

	secrets := []SecretEntry{
		{Name: "my-secret", Key: "password", Value: "s3cret"},
	}

	manifests := GenerateSecretManifests(secrets, opts)
	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(manifests))
	}

	m := manifests[0]
	if m["apiVersion"] != "bitnami.com/v1alpha1" {
		t.Errorf("apiVersion = %v, want bitnami.com/v1alpha1", m["apiVersion"])
	}
	if m["kind"] != "SealedSecret" {
		t.Errorf("kind = %v, want SealedSecret", m["kind"])
	}
}

func TestGeneratePlainSecretManifests_Grouped(t *testing.T) {
	secrets := []SecretEntry{
		{Name: "db-creds", Key: "username", Value: "admin"},
		{Name: "db-creds", Key: "password", Value: "s3cret"},
	}

	manifests := generatePlainSecretManifests(secrets)
	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest (grouped), got %d", len(manifests))
	}

	m := manifests[0]
	metadata := m["metadata"].(map[string]any)
	if metadata["name"] != "db-creds" {
		t.Errorf("metadata.name = %v, want db-creds", metadata["name"])
	}

	stringData := m["stringData"].(map[string]any)
	if len(stringData) != 2 {
		t.Fatalf("expected 2 keys in stringData, got %d", len(stringData))
	}
	if stringData["username"] != "admin" {
		t.Errorf("stringData.username = %v, want admin", stringData["username"])
	}
	if stringData["password"] != "s3cret" {
		t.Errorf("stringData.password = %v, want s3cret", stringData["password"])
	}
}

func TestGeneratePlainSecretManifests_MultipleSecrets(t *testing.T) {
	secrets := []SecretEntry{
		{Name: "secret-a", Key: "key1", Value: "val1"},
		{Name: "secret-b", Key: "key2", Value: "val2"},
	}

	manifests := generatePlainSecretManifests(secrets)
	if len(manifests) != 2 {
		t.Fatalf("expected 2 manifests, got %d", len(manifests))
	}

	names := make(map[string]bool)
	for _, m := range manifests {
		metadata := m["metadata"].(map[string]any)
		names[metadata["name"].(string)] = true
	}
	if !names["secret-a"] {
		t.Error("missing manifest for secret-a")
	}
	if !names["secret-b"] {
		t.Error("missing manifest for secret-b")
	}
}

func TestGenerateESOManifests_StoreConfig(t *testing.T) {
	opts := defaultOpts()
	opts.ESOStore = "vault-backend"
	opts.ESOStoreKind = "SecretStore"

	secrets := []SecretEntry{
		{Name: "my-secret", Key: "token", Value: "abc123"},
	}

	manifests := generateESOManifests(secrets, opts)
	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(manifests))
	}

	spec := manifests[0]["spec"].(map[string]any)
	storeRef := spec["secretStoreRef"].(map[string]any)
	if storeRef["name"] != "vault-backend" {
		t.Errorf("secretStoreRef.name = %v, want vault-backend", storeRef["name"])
	}
	if storeRef["kind"] != "SecretStore" {
		t.Errorf("secretStoreRef.kind = %v, want SecretStore", storeRef["kind"])
	}

	target := spec["target"].(map[string]any)
	if target["name"] != "my-secret" {
		t.Errorf("target.name = %v, want my-secret", target["name"])
	}
}

func TestGenerateESOManifests_DefaultStoreKind(t *testing.T) {
	opts := defaultOpts()
	opts.ESOStore = "my-store"
	opts.ESOStoreKind = "" // should default to ClusterSecretStore

	secrets := []SecretEntry{
		{Name: "my-secret", Key: "token", Value: "abc123"},
	}

	manifests := generateESOManifests(secrets, opts)
	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(manifests))
	}

	spec := manifests[0]["spec"].(map[string]any)
	storeRef := spec["secretStoreRef"].(map[string]any)
	if storeRef["kind"] != "ClusterSecretStore" {
		t.Errorf("secretStoreRef.kind = %v, want ClusterSecretStore (default)", storeRef["kind"])
	}
}

func TestGenerateESOManifests_RemoteRefFormat(t *testing.T) {
	opts := defaultOpts()
	opts.ESOStore = "store"

	secrets := []SecretEntry{
		{Name: "app-creds", Key: "password", Value: "secret"},
		{Name: "app-creds", Key: "username", Value: "admin"},
	}

	manifests := generateESOManifests(secrets, opts)
	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(manifests))
	}

	spec := manifests[0]["spec"].(map[string]any)
	data := spec["data"].([]any)
	if len(data) != 2 {
		t.Fatalf("expected 2 data entries, got %d", len(data))
	}

	expectedKey := "/keycloak/app-creds"
	for _, entry := range data {
		e := entry.(map[string]any)
		remoteRef := e["remoteRef"].(map[string]any)
		if remoteRef["key"] != expectedKey {
			t.Errorf("remoteRef.key = %v, want %v", remoteRef["key"], expectedKey)
		}
		secretKey := e["secretKey"].(string)
		if remoteRef["property"] != secretKey {
			t.Errorf("remoteRef.property = %v, want %v", remoteRef["property"], secretKey)
		}
	}
}

func TestGenerateSealedSecretManifests_Placeholder(t *testing.T) {
	opts := defaultOpts()

	secrets := []SecretEntry{
		{Name: "my-sealed", Key: "api-key", Value: "real-value"},
		{Name: "my-sealed", Key: "token", Value: "real-token"},
	}

	manifests := generateSealedSecretManifests(secrets, opts)
	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(manifests))
	}

	m := manifests[0]
	if m["apiVersion"] != "bitnami.com/v1alpha1" {
		t.Errorf("apiVersion = %v, want bitnami.com/v1alpha1", m["apiVersion"])
	}
	if m["kind"] != "SealedSecret" {
		t.Errorf("kind = %v, want SealedSecret", m["kind"])
	}

	spec := m["spec"].(map[string]any)
	encryptedData := spec["encryptedData"].(map[string]any)

	expectedKeys := map[string]string{
		"api-key": fmt.Sprintf("REPLACE_WITH_SEALED_VALUE_FOR_%s", "api-key"),
		"token":   fmt.Sprintf("REPLACE_WITH_SEALED_VALUE_FOR_%s", "token"),
	}
	for key, expectedVal := range expectedKeys {
		val, ok := encryptedData[key]
		if !ok {
			t.Errorf("missing encryptedData key %q", key)
			continue
		}
		if val != expectedVal {
			t.Errorf("encryptedData[%s] = %v, want %v", key, val, expectedVal)
		}
	}

	// Verify template metadata
	tmpl := spec["template"].(map[string]any)
	tmplMeta := tmpl["metadata"].(map[string]any)
	if tmplMeta["name"] != "my-sealed" {
		t.Errorf("template.metadata.name = %v, want my-sealed", tmplMeta["name"])
	}
}

func TestExtractUsers_WithUsers(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm": "test",
		"users": []any{
			map[string]any{
				"username":  "alice",
				"email":     "alice@example.com",
				"enabled":   true,
				"firstName": "Alice",
			},
			map[string]any{
				"username":  "bob",
				"email":     "bob@example.com",
				"enabled":   false,
				"firstName": "Bob",
			},
		},
	}}

	users := ExtractUsers(exp)
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}

	if users[0]["username"] != "alice" {
		t.Errorf("users[0].username = %v, want alice", users[0]["username"])
	}
	if users[1]["username"] != "bob" {
		t.Errorf("users[1].username = %v, want bob", users[1]["username"])
	}
}

func TestExtractUsers_NoUsers(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm": "test",
	}}

	users := ExtractUsers(exp)
	if users != nil {
		t.Errorf("expected nil for export with no users, got %v", users)
	}
}
