package main

import (
	"os"

	"github.com/vriesdemichael/keycloak-operator/tools/migration-toolkit/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
