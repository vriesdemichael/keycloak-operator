package userimport

import (
	"context"
	"encoding/base64"
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
			"cannot determine Keycloak URL for %q: status.endpoints is empty and spec.hostname is not set. "+
				"Pass --server-url to specify the URL explicitly",
			keycloakName,
		)
	}
	serverURL = strings.TrimRight(serverURL, "/")

	// Resolve admin credentials secret name
	secretName := kc.Spec.Admin.ExistingSecret
	if secretName == "" {
		// Fall back to the auto-generated convention used by the operator
		secretName = keycloakName + "-admin-credentials"
	}

	secret, err := coreClient.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("reading admin credentials secret %q in namespace %q: %w", secretName, namespace, err)
	}

	username, err := decodeSecretKey(secret.Data, "username", secretName)
	if err != nil {
		return nil, err
	}
	password, err := decodeSecretKey(secret.Data, "password", secretName)
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
	// Prefer status.endpoints.internal for in-cluster, but the toolkit
	// runs outside the cluster so prefer admin > public > internal.
	if u := kc.Status.Endpoints.Admin; u != "" {
		return u
	}
	if u := kc.Status.Endpoints.Public; u != "" {
		return u
	}
	if u := kc.Status.Endpoints.Internal; u != "" {
		return u
	}
	// Fall back to constructing from spec.hostname
	if kc.Spec.Hostname != "" {
		scheme := "http"
		if kc.Spec.TLS.Enabled {
			scheme = "https"
		}
		return fmt.Sprintf("%s://%s", scheme, kc.Spec.Hostname)
	}
	return ""
}

func decodeSecretKey(data map[string][]byte, key, secretName string) (string, error) {
	raw, ok := data[key]
	if !ok {
		return "", fmt.Errorf("key %q not found in secret %q", key, secretName)
	}
	// Kubernetes secret data is already base64-decoded by the client library,
	// but guard against double-encoding in case the secret was created manually.
	decoded := string(raw)
	if isBase64(decoded) {
		if b, err := base64.StdEncoding.DecodeString(decoded); err == nil {
			return string(b), nil
		}
	}
	return decoded, nil
}

// isBase64 is a heuristic — only used to handle manually created secrets
// where operators may have base64-encoded the value themselves.
func isBase64(s string) bool {
	if len(s) == 0 || len(s)%4 != 0 {
		return false
	}
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
			return false
		}
	}
	return true
}
