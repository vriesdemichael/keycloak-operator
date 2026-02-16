package transform

import (
	"fmt"

	"github.com/vriesdemichael/keycloak-operator/tools/migration-toolkit/internal/export"
)

// checkUnsupportedRealmFeatures checks for features in the export that are not
// yet supported by the operator's Helm charts and emits warnings with GitHub
// issue references.
func checkUnsupportedRealmFeatures(exp *export.RealmExport) []Warning {
	var warnings []Warning

	// Authentication flows (Issue #531)
	if flows := exp.GetArray("authenticationFlows"); flows != nil && len(flows) > 0 {
		warnings = append(warnings, Warning{
			Category: "unsupported",
			Field:    "authenticationFlows",
			Message:  "Custom authentication flows are not yet supported by the operator Helm charts. Custom flows will need to be configured manually.",
			IssueURL: "https://github.com/vriesdemichael/keycloak-operator/issues/531",
		})
	}

	// Required actions (Issue #531)
	if actions := exp.GetArray("requiredActions"); actions != nil && len(actions) > 0 {
		warnings = append(warnings, Warning{
			Category: "unsupported",
			Field:    "requiredActions",
			Message:  "Required actions are not yet supported by the operator Helm charts.",
			IssueURL: "https://github.com/vriesdemichael/keycloak-operator/issues/531",
		})
	}

	// Flow bindings (Issue #531)
	flowBindings := []string{
		"browserFlow", "registrationFlow", "directGrantFlow",
		"resetCredentialsFlow", "clientAuthenticationFlow",
		"dockerAuthenticationFlow", "firstBrokerLoginFlow",
	}
	for _, fb := range flowBindings {
		if v := exp.GetString(fb); v != "" {
			// Only warn about non-default bindings
			defaults := map[string]string{
				"browserFlow":              "browser",
				"registrationFlow":         "registration",
				"directGrantFlow":          "direct grant",
				"resetCredentialsFlow":     "reset credentials",
				"clientAuthenticationFlow": "clients",
				"dockerAuthenticationFlow": "docker auth",
				"firstBrokerLoginFlow":     "first broker login",
			}
			if defaultVal, ok := defaults[fb]; ok && v != defaultVal {
				warnings = append(warnings, Warning{
					Category: "unsupported",
					Field:    fb,
					Message:  "Custom flow binding '" + fb + "' = '" + v + "' is not yet supported. Default '" + defaultVal + "' will be used.",
					IssueURL: "https://github.com/vriesdemichael/keycloak-operator/issues/531",
				})
			}
		}
	}

	// OTP policy (Issue #532)
	if exp.HasKey("otpPolicyType") || exp.HasKey("otpPolicyAlgorithm") ||
		exp.HasKey("otpPolicyDigits") || exp.HasKey("otpPolicyPeriod") {
		warnings = append(warnings, Warning{
			Category: "unsupported",
			Field:    "otpPolicy*",
			Message:  "OTP policy settings are not yet supported by the operator.",
			IssueURL: "https://github.com/vriesdemichael/keycloak-operator/issues/532",
		})
	}

	// WebAuthn policy (Issue #533)
	if exp.HasKey("webAuthnPolicyRpEntityName") || exp.HasKey("webAuthnPolicyPasswordlessRpEntityName") {
		warnings = append(warnings, Warning{
			Category: "unsupported",
			Field:    "webAuthnPolicy*",
			Message:  "WebAuthn policy settings are not yet supported by the operator.",
			IssueURL: "https://github.com/vriesdemichael/keycloak-operator/issues/533",
		})
	}

	// Browser security headers (Issue #534)
	if headers := exp.GetMap("browserSecurityHeaders"); headers != nil && len(headers) > 0 {
		warnings = append(warnings, Warning{
			Category: "unsupported",
			Field:    "browserSecurityHeaders",
			Message:  "Browser security headers are not yet supported by the operator.",
			IssueURL: "https://github.com/vriesdemichael/keycloak-operator/issues/534",
		})
	}

	// Scope mappings (Issue #535)
	if scopeMappings := exp.GetArray("scopeMappings"); scopeMappings != nil && len(scopeMappings) > 0 {
		warnings = append(warnings, Warning{
			Category: "unsupported",
			Field:    "scopeMappings",
			Message:  "Scope mappings are not yet supported by the operator.",
			IssueURL: "https://github.com/vriesdemichael/keycloak-operator/issues/535",
		})
	}
	if clientScopeMappings := exp.GetMap("clientScopeMappings"); clientScopeMappings != nil && len(clientScopeMappings) > 0 {
		warnings = append(warnings, Warning{
			Category: "unsupported",
			Field:    "clientScopeMappings",
			Message:  "Client scope mappings are not yet supported by the operator.",
			IssueURL: "https://github.com/vriesdemichael/keycloak-operator/issues/535",
		})
	}

	// Default roles (Issue #536)
	if exp.HasKey("defaultRole") {
		warnings = append(warnings, Warning{
			Category: "unsupported",
			Field:    "defaultRole",
			Message:  "Default roles are not directly supported. Use defaultGroups with role mappings as a workaround.",
			IssueURL: "https://github.com/vriesdemichael/keycloak-operator/issues/536",
		})
	}

	// Users — not managed by operator
	if users := exp.Users(); len(users) > 0 {
		warnings = append(warnings, Warning{
			Category: "info",
			Field:    "users",
			Message:  fmt.Sprintf("Found %d users in export. Users are extracted to users.json for manual import via Keycloak Admin Console (Partial Import) or database migration. The operator does not manage users (ADR-025).", len(users)),
		})
	}

	return warnings
}
