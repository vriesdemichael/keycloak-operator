package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/vriesdemichael/keycloak-operator/tools/migration-toolkit/internal/export"
	"github.com/vriesdemichael/keycloak-operator/tools/migration-toolkit/internal/output"
	"github.com/vriesdemichael/keycloak-operator/tools/migration-toolkit/internal/transform"
)

var transformOpts struct {
	inputFile    string
	inputDir     string
	outputDir    string
	operatorNS   string
	realmNS      string
	secretMode   string
	esoStore     string
	esoStoreKind string
	skipInternal bool
	manageSecret bool
	clientGrants []string
}

var transformCmd = &cobra.Command{
	Use:   "transform",
	Short: "Transform Keycloak realm export into Helm chart values",
	Long: `Transform parses a Keycloak realm export JSON file (or directory of files)
and produces Helm chart values.yaml files for the keycloak-realm and
keycloak-client charts.

Secrets are extracted and output according to the chosen --secret-mode:
  plain           Plain Kubernetes Secret manifests (default)
  eso             ExternalSecret manifests (requires --eso-store)
  sealed-secrets  SealedSecret manifests (placeholder values, seal with kubeseal)

A NEXT-STEPS.md is generated documenting manual actions required after
applying the generated values.`,
	RunE: runTransform,
}

func init() {
	f := transformCmd.Flags()
	f.StringVarP(&transformOpts.inputFile, "input", "i", "", "Path to a single realm export JSON file")
	f.StringVar(&transformOpts.inputDir, "input-dir", "", "Path to directory containing realm export JSON files")
	f.StringVarP(&transformOpts.outputDir, "output-dir", "o", "./output", "Output directory for generated files")
	f.StringVar(&transformOpts.operatorNS, "operator-namespace", "keycloak-system", "Namespace where the operator is running")
	f.StringVar(&transformOpts.realmNS, "realm-namespace", "", "Target namespace for realm CRs (defaults to operator namespace)")
	f.StringVar(&transformOpts.secretMode, "secret-mode", "plain", "Secret output mode: plain, eso, sealed-secrets")
	f.StringVar(&transformOpts.esoStore, "eso-store", "", "ExternalSecret store name (required for --secret-mode=eso)")
	f.StringVar(&transformOpts.esoStoreKind, "eso-store-kind", "ClusterSecretStore", "ExternalSecret store kind")
	f.BoolVar(&transformOpts.skipInternal, "skip-internal-clients", true, "Skip Keycloak internal clients (account, admin-cli, etc.)")
	f.BoolVar(&transformOpts.manageSecret, "manage-secrets", false, "Enable manageSecret for confidential clients (default: false for safety)")
	f.StringSliceVar(&transformOpts.clientGrants, "client-grants", nil, "Namespaces authorized to create clients in the realm")

	rootCmd.AddCommand(transformCmd)
}

func runTransform(cmd *cobra.Command, args []string) error {
	// Validate inputs
	if transformOpts.inputFile == "" && transformOpts.inputDir == "" {
		return fmt.Errorf("either --input or --input-dir is required")
	}
	if transformOpts.inputFile != "" && transformOpts.inputDir != "" {
		return fmt.Errorf("--input and --input-dir are mutually exclusive")
	}
	if transformOpts.secretMode == transform.SecretModeESO && transformOpts.esoStore == "" {
		return fmt.Errorf("--eso-store is required when --secret-mode=eso")
	}
	if transformOpts.realmNS == "" {
		transformOpts.realmNS = transformOpts.operatorNS
	}

	// Parse exports
	var exports []*export.RealmExport
	var err error

	if transformOpts.inputFile != "" {
		exp, err := export.ParseFile(transformOpts.inputFile)
		if err != nil {
			return fmt.Errorf("parsing input file: %w", err)
		}
		exports = []*export.RealmExport{exp}
	} else {
		exports, err = export.ParseDirectory(transformOpts.inputDir)
		if err != nil {
			return fmt.Errorf("parsing input directory: %w", err)
		}
	}

	opts := transform.TransformOptions{
		OperatorNamespace:         transformOpts.operatorNS,
		RealmNamespace:            transformOpts.realmNS,
		SkipInternalClients:       transformOpts.skipInternal,
		ManageSecrets:             transformOpts.manageSecret,
		SecretMode:                transformOpts.secretMode,
		ESOStore:                  transformOpts.esoStore,
		ESOStoreKind:              transformOpts.esoStoreKind,
		ClientAuthorizationGrants: transformOpts.clientGrants,
	}

	// Process each realm export
	for _, exp := range exports {
		result := processRealm(exp, opts)
		if err := writeResult(result, transformOpts.outputDir); err != nil {
			return fmt.Errorf("writing output for realm '%s': %w", result.RealmName, err)
		}
		printSummary(result, cmd)
	}

	return nil
}

func processRealm(exp *export.RealmExport, opts transform.TransformOptions) *transform.TransformResult {
	result := &transform.TransformResult{
		RealmName:    exp.GetString("realm"),
		ClientValues: make(map[string]map[string]any),
	}

	// Transform realm
	realmValues, realmSecrets, realmWarnings := transform.TransformRealm(exp, opts)
	result.RealmValues = realmValues
	result.Secrets = append(result.Secrets, realmSecrets...)
	result.Warnings = append(result.Warnings, realmWarnings...)

	// Transform clients
	clientValues, clientSecrets, clientWarnings := transform.TransformAllClients(exp, opts)
	if clientValues != nil {
		result.ClientValues = clientValues
	}
	result.Secrets = append(result.Secrets, clientSecrets...)
	result.Warnings = append(result.Warnings, clientWarnings...)

	// Extract users
	result.Users = transform.ExtractUsers(exp)

	// Collect unsupported features into a structured map
	unsupported := make(map[string]any)
	for _, w := range result.Warnings {
		if w.Category == "unsupported" {
			entry := map[string]any{
				"message": w.Message,
			}
			if w.IssueURL != "" {
				entry["issueUrl"] = w.IssueURL
			}
			unsupported[w.Field] = entry
		}
	}
	if len(unsupported) > 0 {
		result.UnsupportedFeatures = unsupported
	}

	return result
}

func writeResult(result *transform.TransformResult, baseDir string) error {
	realmDir := filepath.Join(baseDir, result.RealmName)

	w := output.NewWriter(realmDir)

	// Write realm values.yaml
	if err := w.WriteYAML("realm-values.yaml", result.RealmValues); err != nil {
		return fmt.Errorf("writing realm values: %w", err)
	}

	// Write per-client values.yaml
	for clientId, clientValues := range result.ClientValues {
		clientDir := filepath.Join("clients", sanitizeFilename(clientId))
		if err := w.WriteYAML(filepath.Join(clientDir, "values.yaml"), clientValues); err != nil {
			return fmt.Errorf("writing client values for '%s': %w", clientId, err)
		}
	}

	// Write users.json if present
	if len(result.Users) > 0 {
		if err := w.WriteJSON("users.json", result.Users); err != nil {
			return fmt.Errorf("writing users: %w", err)
		}
	}

	// Write secret manifests
	secretManifests := transform.GenerateSecretManifests(result.Secrets, transform.TransformOptions{
		SecretMode:   transformOpts.secretMode,
		ESOStore:     transformOpts.esoStore,
		ESOStoreKind: transformOpts.esoStoreKind,
	})
	if len(secretManifests) > 0 {
		if err := w.WriteYAMLMultiDoc("secrets.yaml", secretManifests); err != nil {
			return fmt.Errorf("writing secret manifests: %w", err)
		}
	}

	// Write unsupported-features.json
	if len(result.UnsupportedFeatures) > 0 {
		if err := w.WriteJSON("unsupported-features.json", result.UnsupportedFeatures); err != nil {
			return fmt.Errorf("writing unsupported features: %w", err)
		}
	}

	// Write NEXT-STEPS.md
	nextSteps := output.GenerateNextSteps(result)
	if err := w.WriteString("NEXT-STEPS.md", nextSteps); err != nil {
		return fmt.Errorf("writing NEXT-STEPS.md: %w", err)
	}

	// Write secrets inventory (plaintext values for reference, never commit this)
	if len(result.Secrets) > 0 {
		if err := w.WriteJSON("secrets-inventory.json", result.Secrets); err != nil {
			return fmt.Errorf("writing secrets inventory: %w", err)
		}
	}

	return nil
}

func printSummary(result *transform.TransformResult, cmd *cobra.Command) {
	cmd.Printf("\nRealm: %s\n", result.RealmName)
	cmd.Printf("  Clients:    %d\n", len(result.ClientValues))
	cmd.Printf("  Secrets:    %d\n", len(result.Secrets))
	cmd.Printf("  Users:      %d\n", len(result.Users))

	warningCount := 0
	unsupportedCount := 0
	for _, w := range result.Warnings {
		if w.Category == "unsupported" {
			unsupportedCount++
		} else {
			warningCount++
		}
	}
	cmd.Printf("  Warnings:   %d\n", warningCount)
	cmd.Printf("  Unsupported: %d (see unsupported-features.json)\n", unsupportedCount)

	if len(result.Warnings) > 0 {
		cmd.Println("\nWarnings:")
		for _, w := range result.Warnings {
			prefix := "  WARN"
			if w.Category == "unsupported" {
				prefix = "  UNSUPPORTED"
			} else if w.Category == "info" {
				prefix = "  INFO"
			}
			cmd.Printf("%s [%s]: %s\n", prefix, w.Field, w.Message)
		}
	}

	cmd.Printf("\nOutput written to: %s/%s/\n", transformOpts.outputDir, result.RealmName)
}

func sanitizeFilename(name string) string {
	result := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			result = append(result, c)
		} else if c == ' ' || c == '/' || c == '\\' {
			result = append(result, '-')
		}
	}
	return string(result)
}
