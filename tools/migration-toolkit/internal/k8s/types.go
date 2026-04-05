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
	Admin    KeycloakAdminConfig `json:"admin"`
	Hostname string              `json:"hostname"`
	TLS      KeycloakTLS         `json:"tls"`
}

// KeycloakAdminConfig holds the admin credentials configuration.
// spec.admin.existingSecret is a secret name containing "username" and "password" keys.
type KeycloakAdminConfig struct {
	ExistingSecret string `json:"existingSecret"`
}

// KeycloakTLS holds TLS configuration.
type KeycloakTLS struct {
	Enabled bool `json:"enabled"`
}

// KeycloakStatus holds the relevant parts of the Keycloak CR status.
type KeycloakStatus struct {
	Phase     string             `json:"phase"`
	Endpoints KeycloakEndpoints  `json:"endpoints"`
}

// KeycloakEndpoints holds the access endpoints for the Keycloak instance.
type KeycloakEndpoints struct {
	Public   string `json:"public"`
	Admin    string `json:"admin"`
	Internal string `json:"internal"`
}
