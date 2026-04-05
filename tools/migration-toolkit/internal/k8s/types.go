// Package k8s provides minimal Go structs for reading the Keycloak CR
// from a Kubernetes cluster. These are deliberately lightweight — only the
// fields needed for admin credential resolution and URL derivation are defined.
// The full Keycloak CRD is managed by the Python operator.
package k8s

// KeycloakCR is a minimal representation of the Keycloak custom resource
// (apiVersion: vriesdemichael.github.io/v1, kind: Keycloak).
// Only the fields required by the import-users command are populated.
type KeycloakCR struct {
	Spec   KeycloakSpec   `json:"spec"`
	Status KeycloakStatus `json:"status"`
}

// KeycloakSpec holds the relevant parts of the Keycloak CR spec.
type KeycloakSpec struct {
	// Admin holds credentials config (spec.admin).
	Admin KeycloakAdminConfig `json:"admin"`
	// AdminAccess is the legacy alias for Admin (spec.admin_access).
	AdminAccess KeycloakAdminConfig `json:"admin_access"`
	// Ingress holds ingress configuration used to derive the server URL as a fallback.
	Ingress KeycloakIngress `json:"ingress"`
}

// KeycloakAdminConfig holds the admin credentials configuration.
// spec.admin.existingSecret is a secret name containing "username" and "password" keys.
type KeycloakAdminConfig struct {
	ExistingSecret string `json:"existingSecret"`
}

// KeycloakIngress holds the ingress fields relevant to URL derivation.
type KeycloakIngress struct {
	Host       string `json:"host"`
	TLSEnabled bool   `json:"tlsEnabled"`
}

// KeycloakStatus holds the relevant parts of the Keycloak CR status.
type KeycloakStatus struct {
	Phase string `json:"phase"`
	// AdminSecret is the name of the Kubernetes secret holding admin credentials,
	// written by the operator (always "{name}-admin-credentials").
	AdminSecret string            `json:"adminSecret"`
	ExternalUrl string            `json:"externalUrl"`
	InternalUrl string            `json:"internalUrl"`
	Endpoints   KeycloakEndpoints `json:"endpoints"`
}

// KeycloakEndpoints holds the access endpoints for the Keycloak instance.
type KeycloakEndpoints struct {
	Public   string `json:"public"`
	Admin    string `json:"admin"`
	Internal string `json:"internal"`
}
