package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "dev"

var rootCmd = &cobra.Command{
	Use:   "keycloak-migrate",
	Short: "Migration toolkit for Keycloak realm exports",
	Long: `keycloak-migrate transforms Keycloak realm export JSON files into
Helm chart values.yaml files compatible with the keycloak-realm and
keycloak-client Helm charts from the keycloak-operator project.

It extracts secrets, generates NEXT-STEPS.md documentation, and warns
about unsupported features that require manual attention or upstream
issue resolution.`,
}

func Execute() error {
	return rootCmd.Execute()
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of keycloak-migrate",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(os.Stdout, "keycloak-migrate %s\n", version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
