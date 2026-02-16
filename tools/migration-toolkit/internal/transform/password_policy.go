package transform

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// knownPolicies maps Keycloak policy function names to their Helm values field names.
var knownPolicies = map[string]string{
	"length":                     "length",
	"upperCase":                  "upperCase",
	"lowerCase":                  "lowerCase",
	"digits":                     "digits",
	"specialChars":               "specialChars",
	"notUsername":                "notUsername",
	"notEmail":                   "notEmail",
	"hashIterations":             "hashIterations",
	"passwordHistory":            "passwordHistory",
	"forceExpiredPasswordChange": "forceExpiredPasswordChange",
	"maxLength":                  "maxLength",
	"regexPattern":               "regexPattern",
}

// booleanPolicies are policies that take no argument (their presence means true).
var booleanPolicies = map[string]bool{
	"notUsername": true,
	"notEmail":    true,
}

// policyPattern matches "policyName(value)" in a Keycloak password policy string.
var policyPattern = regexp.MustCompile(`(\w+)\(([^)]*)\)`)

// ParsePasswordPolicy parses a Keycloak password policy string like
// "hashIterations(27500) and length(8) and notUsername" into structured Helm values.
func ParsePasswordPolicy(policyStr string) (map[string]any, []Warning) {
	if policyStr == "" {
		return nil, nil
	}

	result := make(map[string]any)
	var warnings []Warning

	// Split by " and " to get individual policies
	parts := strings.Split(policyStr, " and ")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		matches := policyPattern.FindStringSubmatch(part)
		if matches != nil {
			name := matches[1]
			value := matches[2]

			if helmField, ok := knownPolicies[name]; ok {
				if booleanPolicies[name] {
					result[helmField] = true
				} else if name == "regexPattern" {
					result[helmField] = value
				} else {
					if intVal, err := strconv.Atoi(value); err == nil {
						result[helmField] = intVal
					} else {
						result[helmField] = value
					}
				}
			} else {
				warnings = append(warnings, Warning{
					Category: "unsupported",
					Field:    "passwordPolicy",
					Message:  fmt.Sprintf("Unknown password policy '%s(%s)' - not mapped to Helm values", name, value),
				})
			}
		} else {
			// Bare policy name without parentheses (e.g., "notUsername")
			if helmField, ok := knownPolicies[part]; ok {
				result[helmField] = true
			} else {
				warnings = append(warnings, Warning{
					Category: "unsupported",
					Field:    "passwordPolicy",
					Message:  fmt.Sprintf("Unknown password policy '%s' - not mapped to Helm values", part),
				})
			}
		}
	}

	if len(result) == 0 {
		return nil, warnings
	}
	return result, warnings
}
