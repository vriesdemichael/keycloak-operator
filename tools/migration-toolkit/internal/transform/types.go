// Package transform converts Keycloak realm exports into Helm chart values.
package transform

// InternalClients are Keycloak-managed clients that should be skipped by default.
var InternalClients = map[string]bool{
	"account":                true,
	"account-console":        true,
	"admin-cli":              true,
	"broker":                 true,
	"realm-management":       true,
	"security-admin-console": true,
}

// DeprecatedClientFields are legacy fields that should be silently skipped.
var DeprecatedClientFields = map[string]bool{
	"clientTemplate":            true,
	"surrogateAuthRequired":     true,
	"directGrantsOnly":          true,
	"nodeReRegistrationTimeout": true,
	"registeredNodes":           true,
	"defaultRoles":              true,
}

// Warning represents a non-fatal issue found during transformation.
type Warning struct {
	// Category groups warnings (e.g., "unsupported", "secret", "deprecated")
	Category string `json:"category"`
	// Field is the export JSON field path that triggered the warning
	Field string `json:"field"`
	// Message describes the issue
	Message string `json:"message"`
	// IssueURL links to the GitHub issue tracking support for this feature
	IssueURL string `json:"issueUrl,omitempty"`
}

// SecretEntry represents a secret that was extracted from the export.
type SecretEntry struct {
	// Name is the Kubernetes Secret name
	Name string `json:"name"`
	// Key is the key within the Secret data
	Key string `json:"key"`
	// Value is the plaintext value from the export
	Value string `json:"value"`
	// Description provides context about what this secret is for
	Description string `json:"description"`
	// SourceField is the export JSON path where this was found
	SourceField string `json:"sourceField"`
}

// TransformResult holds all outputs from a realm export transformation.
type TransformResult struct {
	// RealmValues is the keycloak-realm Helm chart values
	RealmValues map[string]any `json:"realmValues"`
	// ClientValues maps clientId to keycloak-client Helm chart values
	ClientValues map[string]map[string]any `json:"clientValues"`
	// Secrets holds extracted secret entries
	Secrets []SecretEntry `json:"secrets"`
	// Users holds extracted user data (for manual import)
	Users []map[string]any `json:"users,omitempty"`
	// Warnings holds non-fatal issues
	Warnings []Warning `json:"warnings"`
	// UnsupportedFeatures holds export data that couldn't be mapped
	UnsupportedFeatures map[string]any `json:"unsupportedFeatures,omitempty"`
	// RealmName is the source realm name from the export
	RealmName string `json:"realmName"`
}

// TransformOptions controls the transformation behavior.
type TransformOptions struct {
	// OperatorNamespace is the namespace where the operator is running
	OperatorNamespace string
	// RealmNamespace is the target namespace for the realm CR
	RealmNamespace string
	// SkipInternalClients skips Keycloak-managed internal clients
	SkipInternalClients bool
	// ManageSecrets enables manageSecret and secretRotation in client output
	ManageSecrets bool
	// SecretMode controls how secrets are output: "plain", "eso", "sealed-secrets"
	SecretMode string
	// ESOStore is the ExternalSecret store name (for eso mode)
	ESOStore string
	// ESOStoreKind is the ExternalSecret store kind (for eso mode)
	ESOStoreKind string
	// ClientAuthorizationGrants is the list of namespaces to authorize for clients
	ClientAuthorizationGrants []string
}

// SanitizeK8sName converts a string to a valid DNS-1123 subdomain name suitable
// for Kubernetes resource names. It lowercases, replaces invalid characters with
// hyphens, collapses consecutive hyphens, trims leading/trailing hyphens, and
// truncates to 253 characters.
func SanitizeK8sName(name string) string {
	if name == "" {
		return "unnamed"
	}

	result := make([]byte, 0, len(name))
	prevHyphen := false

	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			result = append(result, c)
			prevHyphen = false
		case c >= 'A' && c <= 'Z':
			result = append(result, c+32) // lowercase
			prevHyphen = false
		case c == '-', c == '.':
			if !prevHyphen {
				result = append(result, '-')
				prevHyphen = true
			}
		case c == ' ', c == '_':
			if !prevHyphen {
				result = append(result, '-')
				prevHyphen = true
			}
		default:
			// drop invalid characters
		}
	}

	// Trim leading and trailing hyphens
	s := string(result)
	start := 0
	for start < len(s) && s[start] == '-' {
		start++
	}
	end := len(s)
	for end > start && s[end-1] == '-' {
		end--
	}
	s = s[start:end]

	if s == "" {
		return "unnamed"
	}

	// Truncate to 253 characters (DNS-1123 subdomain max)
	if len(s) > 253 {
		s = s[:253]
		// Don't end on a hyphen after truncation
		for len(s) > 0 && s[len(s)-1] == '-' {
			s = s[:len(s)-1]
		}
	}

	return s
}
