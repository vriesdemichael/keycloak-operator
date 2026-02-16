package transform

import (
	"fmt"

	"github.com/vriesdemichael/keycloak-operator/tools/migration-toolkit/internal/export"
)

// SecretMode defines how secrets should be output.
const (
	SecretModePlain         = "plain"
	SecretModeESO           = "eso"
	SecretModeSealedSecrets = "sealed-secrets"
)

// GenerateSecretManifests creates Kubernetes Secret manifests or
// ExternalSecret/SealedSecret manifests depending on the mode.
func GenerateSecretManifests(secrets []SecretEntry, opts TransformOptions) []map[string]any {
	if len(secrets) == 0 {
		return nil
	}

	var manifests []map[string]any

	switch opts.SecretMode {
	case SecretModeESO:
		manifests = generateESOManifests(secrets, opts)
	case SecretModeSealedSecrets:
		manifests = generateSealedSecretManifests(secrets, opts)
	default:
		manifests = generatePlainSecretManifests(secrets)
	}

	return manifests
}

func generatePlainSecretManifests(secrets []SecretEntry) []map[string]any {
	// Group secrets by name to create one Secret per unique name
	grouped := make(map[string][]SecretEntry)
	for _, s := range secrets {
		grouped[s.Name] = append(grouped[s.Name], s)
	}

	var manifests []map[string]any
	for name, entries := range grouped {
		stringData := make(map[string]any)
		for _, e := range entries {
			stringData[e.Key] = e.Value
		}

		manifest := map[string]any{
			"apiVersion": "v1",
			"kind":       "Secret",
			"metadata": map[string]any{
				"name": name,
			},
			"stringData": stringData,
		}
		manifests = append(manifests, manifest)
	}

	return manifests
}

func generateESOManifests(secrets []SecretEntry, opts TransformOptions) []map[string]any {
	// Group secrets by name
	grouped := make(map[string][]SecretEntry)
	for _, s := range secrets {
		grouped[s.Name] = append(grouped[s.Name], s)
	}

	storeKind := opts.ESOStoreKind
	if storeKind == "" {
		storeKind = "ClusterSecretStore"
	}

	var manifests []map[string]any
	for name, entries := range grouped {
		var data []any
		for _, e := range entries {
			data = append(data, map[string]any{
				"secretKey": e.Key,
				"remoteRef": map[string]any{
					"key":      fmt.Sprintf("/keycloak/%s", name),
					"property": e.Key,
				},
			})
		}

		manifest := map[string]any{
			"apiVersion": "external-secrets.io/v1beta1",
			"kind":       "ExternalSecret",
			"metadata": map[string]any{
				"name": name,
			},
			"spec": map[string]any{
				"secretStoreRef": map[string]any{
					"name": opts.ESOStore,
					"kind": storeKind,
				},
				"target": map[string]any{
					"name": name,
				},
				"data": data,
			},
		}
		manifests = append(manifests, manifest)
	}

	return manifests
}

func generateSealedSecretManifests(secrets []SecretEntry, opts TransformOptions) []map[string]any {
	// Group secrets by name
	grouped := make(map[string][]SecretEntry)
	for _, s := range secrets {
		grouped[s.Name] = append(grouped[s.Name], s)
	}

	var manifests []map[string]any
	for name, entries := range grouped {
		encryptedData := make(map[string]any)
		for _, e := range entries {
			// Placeholder — SealedSecrets require kubeseal to encrypt
			encryptedData[e.Key] = fmt.Sprintf("REPLACE_WITH_SEALED_VALUE_FOR_%s", e.Key)
		}

		manifest := map[string]any{
			"apiVersion": "bitnami.com/v1alpha1",
			"kind":       "SealedSecret",
			"metadata": map[string]any{
				"name": name,
			},
			"spec": map[string]any{
				"encryptedData": encryptedData,
				"template": map[string]any{
					"metadata": map[string]any{
						"name": name,
					},
				},
			},
		}
		manifests = append(manifests, manifest)
	}

	return manifests
}

// ExtractUsers extracts user data from a realm export for manual import.
// Users are NOT managed by the operator (ADR-025), so they are extracted
// as raw JSON for use with Keycloak's Partial Import or database migration.
func ExtractUsers(exp *export.RealmExport) []map[string]any {
	return exp.Users()
}
