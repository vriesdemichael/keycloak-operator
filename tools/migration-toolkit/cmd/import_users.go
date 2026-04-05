package cmd

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vriesdemichael/keycloak-operator/tools/migration-toolkit/internal/userimport"
	"k8s.io/client-go/tools/clientcmd"
)

var importUsersOpts struct {
	inputFile    string
	keycloakName string
	namespace    string
	realm        string
	serverURL    string
	username     string
	password     string
	mode         string
	batchSize    int
	maxAge       time.Duration
	dryRun       bool
}

var importUsersCmd = &cobra.Command{
	Use:   "import-users",
	Short: "Import users from users.json into a Keycloak realm",
	Long: `import-users reads the users.json file produced by 'keycloak-migrate transform'
and imports users into a Keycloak realm using the Partial Import API.

Credential resolution (in priority order):
  1. --username and --password flags (no cluster access required)
  2. Kube context: reads the Keycloak CR and its admin credentials secret
     from the cluster (requires RBAC permission to read Keycloak CRs and
     Secrets in the target namespace)

The default conflict mode (--mode skip) makes the import idempotent and
safe to re-run after partial failures. Any batch response with errors > 0
causes an immediate hard failure with details.

Examples:
  # Import via kube context (reads credentials from cluster)
  keycloak-migrate import-users \
    --input users.json \
    --keycloak my-keycloak \
    --namespace keycloak-system \
    --realm my-realm

  # Import with explicit credentials (no kube access required)
  keycloak-migrate import-users \
    --input users.json \
    --server-url https://keycloak.example.com \
    --username admin \
    --password "$KC_ADMIN_PASSWORD" \
    --realm my-realm

  # Dry run to preview what would be imported
  keycloak-migrate import-users \
    --input users.json \
    --keycloak my-keycloak \
    --namespace keycloak-system \
    --realm my-realm \
    --dry-run`,
	RunE: runImportUsers,
}

func init() {
	f := importUsersCmd.Flags()
	f.StringVarP(&importUsersOpts.inputFile, "input", "i", "users.json", "Path to users.json (produced by 'keycloak-migrate transform')")
	f.StringVar(&importUsersOpts.keycloakName, "keycloak", "", "Name of the Keycloak CR (required unless --username/--password are set)")
	f.StringVarP(&importUsersOpts.namespace, "namespace", "n", "", "Namespace of the Keycloak CR (defaults to current kube context namespace)")
	f.StringVar(&importUsersOpts.realm, "realm", "", "Target realm name (required)")
	f.StringVar(&importUsersOpts.serverURL, "server-url", "", "Override Keycloak server URL (required when using --username/--password)")
	f.StringVar(&importUsersOpts.username, "username", "", "Admin username (skips kube-based credential resolution)")
	f.StringVar(&importUsersOpts.password, "password", "", "Admin password (skips kube-based credential resolution)")
	f.StringVar(&importUsersOpts.mode, "mode", "skip", "Conflict mode: skip, fail, overwrite")
	f.IntVar(&importUsersOpts.batchSize, "batch-size", 500, "Number of users per Partial Import request")
	f.DurationVar(&importUsersOpts.maxAge, "max-age", 24*time.Hour, "Maximum age of users.json (0 to disable)")
	f.BoolVar(&importUsersOpts.dryRun, "dry-run", false, "Preview import without making changes")

	rootCmd.AddCommand(importUsersCmd)
}

func runImportUsers(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// Validate mode
	mode, err := parseImportMode(importUsersOpts.mode)
	if err != nil {
		return err
	}

	// Validate realm
	if importUsersOpts.realm == "" {
		return fmt.Errorf("--realm is required")
	}

	// Load and validate users.json
	cmd.Printf("Loading %s...\n", importUsersOpts.inputFile)
	loaded, err := userimport.LoadUsersFile(importUsersOpts.inputFile, importUsersOpts.maxAge)
	if err != nil {
		return fmt.Errorf("loading users file: %w", err)
	}
	cmd.Printf("Loaded %d users (file age: %.0f minutes)\n",
		loaded.UserCount, loaded.FileAge.Minutes())

	// Resolve credentials
	var target *userimport.ResolvedTarget

	usingExplicitCreds := importUsersOpts.username != "" || importUsersOpts.password != ""
	if usingExplicitCreds {
		target, err = userimport.ResolveFromFlags(
			importUsersOpts.serverURL,
			importUsersOpts.username,
			importUsersOpts.password,
			importUsersOpts.realm,
		)
		if err != nil {
			return fmt.Errorf("resolving credentials from flags: %w", err)
		}
		cmd.Printf("Using explicit credentials for user %q\n", importUsersOpts.username)
	} else {
		if importUsersOpts.keycloakName == "" {
			return fmt.Errorf("either --keycloak (for kube-based credential resolution) or --username/--password are required")
		}
		ns := importUsersOpts.namespace
		if ns == "" {
			// Fall back to current kube context namespace
			ns, err = currentKubeNamespace()
			if err != nil {
				return fmt.Errorf("determining current namespace (pass --namespace to override): %w", err)
			}
		}
		cmd.Printf("Resolving credentials from Keycloak CR %q in namespace %q...\n",
			importUsersOpts.keycloakName, ns)
		target, err = userimport.ResolveFromCluster(ctx,
			importUsersOpts.keycloakName, ns,
			importUsersOpts.realm,
			importUsersOpts.serverURL,
		)
		if err != nil {
			return fmt.Errorf("resolving credentials from cluster: %w", err)
		}
		cmd.Printf("Resolved server URL: %s\n", target.ServerURL)
	}

	// Execute import
	httpClient := &http.Client{Timeout: 5 * time.Minute}
	opts := userimport.ImportOptions{
		Target:     target,
		Users:      loaded.Users,
		Mode:       mode,
		BatchSize:  importUsersOpts.batchSize,
		DryRun:     importUsersOpts.dryRun,
		Out:        cmd.OutOrStdout(),
		HTTPClient: httpClient,
	}

	result, err := userimport.ImportUsers(ctx, opts)
	if err != nil {
		// Print partial result before returning error so user can see progress
		printImportSummary(cmd, result)
		return err
	}

	printImportSummary(cmd, result)
	return nil
}

func printImportSummary(cmd *cobra.Command, result *userimport.ImportResult) {
	if result == nil {
		return
	}
	cmd.Printf("\nImport summary:\n")
	cmd.Printf("  Total users: %d\n", result.TotalUsers)
	cmd.Printf("  Batches:     %d\n", result.Batches)
	cmd.Printf("  Added:       %d\n", result.Added)
	cmd.Printf("  Skipped:     %d\n", result.Skipped)
	cmd.Printf("  Errors:      %d\n", result.Errors)
	if len(result.ErrorDetails) > 0 {
		cmd.Printf("  Error details:\n")
		for _, d := range result.ErrorDetails {
			cmd.Printf("    %s\n", d)
		}
	}
}

func parseImportMode(s string) (userimport.ImportMode, error) {
	switch strings.ToLower(s) {
	case "skip":
		return userimport.ImportModeSkip, nil
	case "fail":
		return userimport.ImportModeFail, nil
	case "overwrite":
		return userimport.ImportModeOverwrite, nil
	default:
		return "", fmt.Errorf("invalid --mode %q: must be skip, fail, or overwrite", s)
	}
}

func currentKubeNamespace() (string, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	configOverrides := &clientcmd.ConfigOverrides{}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
	ns, _, err := kubeConfig.Namespace()
	if err != nil {
		return "", err
	}
	if ns == "" {
		return "default", nil
	}
	return ns, nil
}
