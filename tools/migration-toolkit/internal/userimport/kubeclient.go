package userimport

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	internalk8s "github.com/vriesdemichael/keycloak-operator/tools/migration-toolkit/internal/k8s"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var keycloakGVR = schema.GroupVersionResource{
	Group:    "vriesdemichael.github.io",
	Version:  "v1",
	Resource: "keycloaks",
}

// ResolvedTarget holds the resolved Keycloak connection information.
type ResolvedTarget struct {
	ServerURL string
	Username  string
	Password  string
	Realm     string
}

// ResolveFromCluster resolves Keycloak credentials and URL by reading the
// Keycloak CR and its admin credentials secret from the current kube context.
// serverURLOverride bypasses URL detection from the CR status/spec.
func ResolveFromCluster(ctx context.Context, keycloakName, namespace, realm, serverURLOverride string) (*ResolvedTarget, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	configOverrides := &clientcmd.ConfigOverrides{}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)

	restConfig, err := kubeConfig.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("loading kubeconfig: %w", err)
	}

	dynClient, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("creating dynamic client: %w", err)
	}

	coreClient, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("creating core client: %w", err)
	}

	// Fetch the Keycloak CR
	unstrObj, err := dynClient.Resource(keycloakGVR).Namespace(namespace).Get(ctx, keycloakName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("getting Keycloak CR %q in namespace %q: %w", keycloakName, namespace, err)
	}

	// Marshal to JSON and unmarshal into our minimal struct
	raw, err := json.Marshal(unstrObj.Object)
	if err != nil {
		return nil, fmt.Errorf("marshalling Keycloak CR: %w", err)
	}
	var kc internalk8s.KeycloakCR
	if err := json.Unmarshal(raw, &kc); err != nil {
		return nil, fmt.Errorf("parsing Keycloak CR: %w", err)
	}

	// Verify the instance is Ready
	if kc.Status.Phase != "Ready" {
		return nil, fmt.Errorf(
			"Keycloak %q is not Ready (current phase: %q). "+
				"Wait for the operator to finish reconciling before importing users",
			keycloakName, kc.Status.Phase,
		)
	}

	// Resolve server URL
	serverURL := serverURLOverride
	if serverURL == "" {
		serverURL = resolveURL(kc)
	}
	if serverURL == "" {
		return nil, fmt.Errorf(
			"cannot determine Keycloak URL for %q: status.externalUrl, status.internalUrl, "+
				"status.endpoints and spec.ingress.host are all empty. "+
				"Pass --server-url to specify the URL explicitly",
			keycloakName,
		)
	}
	serverURL = strings.TrimRight(serverURL, "/")

	// Resolve admin credentials secret name.
	// Priority: spec.admin.existingSecret → spec.admin_access.existingSecret (legacy
	// alias) → status.adminSecret written by the operator → conventional name.
	secretName := kc.Spec.Admin.ExistingSecret
	if secretName == "" {
		secretName = kc.Spec.AdminAccess.ExistingSecret
	}
	if secretName == "" && kc.Status.AdminSecret != "" {
		secretName = kc.Status.AdminSecret
	}
	if secretName == "" {
		secretName = keycloakName + "-admin-credentials"
	}

	secret, err := coreClient.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("reading admin credentials secret %q in namespace %q: %w", secretName, namespace, err)
	}

	username, err := secretKey(secret.Data, "username", secretName)
	if err != nil {
		return nil, err
	}
	password, err := secretKey(secret.Data, "password", secretName)
	if err != nil {
		return nil, err
	}

	return &ResolvedTarget{
		ServerURL: serverURL,
		Username:  username,
		Password:  password,
		Realm:     realm,
	}, nil
}

// ResolveFromFlags builds a ResolvedTarget from explicit credential flags.
// This path requires no kube access.
func ResolveFromFlags(serverURL, username, password, realm string) (*ResolvedTarget, error) {
	if serverURL == "" {
		return nil, fmt.Errorf("--server-url is required when using --username/--password")
	}
	if username == "" {
		return nil, fmt.Errorf("--username is required")
	}
	if password == "" {
		return nil, fmt.Errorf("--password is required")
	}
	if realm == "" {
		return nil, fmt.Errorf("--realm is required")
	}
	return &ResolvedTarget{
		ServerURL: strings.TrimRight(serverURL, "/"),
		Username:  username,
		Password:  password,
		Realm:     realm,
	}, nil
}

func resolveURL(kc internalk8s.KeycloakCR) string {
	// Priority for an out-of-cluster tool:
	//   1. status.endpoints.admin (explicit admin endpoint)
	//   2. status.endpoints.public (explicit public endpoint)
	//   3. status.externalUrl (operator-written external URL)
	//   4. status.endpoints.internal (last resort — may not be reachable externally)
	//   5. status.internalUrl
	//   6. spec.ingress.host (derive from ingress config)
	if u := kc.Status.Endpoints.Admin; u != "" {
		return u
	}
	if u := kc.Status.Endpoints.Public; u != "" {
		return u
	}
	if u := kc.Status.ExternalUrl; u != "" {
		return u
	}
	if u := kc.Status.Endpoints.Internal; u != "" {
		return u
	}
	if u := kc.Status.InternalUrl; u != "" {
		return u
	}
	if kc.Spec.Ingress.Host != "" {
		scheme := "http"
		if kc.Spec.Ingress.TLSEnabled {
			scheme = "https"
		}
		return fmt.Sprintf("%s://%s", scheme, kc.Spec.Ingress.Host)
	}
	return ""
}

// secretKey returns the string value of a key in a Kubernetes Secret's Data map.
// Secret.Data is always base64-decoded by the Kubernetes client library —
// the raw bytes can be used directly as the string value.
func secretKey(data map[string][]byte, key, secretName string) (string, error) {
	raw, ok := data[key]
	if !ok {
		return "", fmt.Errorf("key %q not found in secret %q", key, secretName)
	}
	return string(raw), nil
}
