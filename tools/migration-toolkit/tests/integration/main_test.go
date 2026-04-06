//go:build integration

// Package integration contains end-to-end integration tests for the
// migration toolkit. Tests exercise the full round-trip pipeline against a
// live Keycloak instance running in a Kind cluster.
//
// Prerequisites (provided by `task toolkit:test:integration`):
//   - Kind cluster running with CNPG and cert-manager installed
//   - Operator image loaded as `keycloak-operator:test`
//   - `keycloak-optimized:{KEYCLOAK_VERSION}` image loaded
//   - REPO_ROOT env var pointing to the repository root
//
// Run: go test -tags integration ./tests/integration/... -v -timeout 600s
package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Package-level variables set by TestMain and accessed by all tests.
var (
	// binaryPath is the absolute path to the compiled keycloak-migrate binary.
	binaryPath string
	// testKCURL is the localhost URL for the port-forwarded test Keycloak.
	testKCURL string
	// testKCUser and testKCPass are the admin credentials.
	testKCUser string
	testKCPass string
	// testKCName and testKCNS are the KC CR name and namespace.
	testKCName string
	testKCNS   string
	// testRealmNS is the namespace where realm/client CRs are applied.
	testRealmNS string
	// repoRoot is the absolute path to the repository root.
	repoRoot string
	// portForwardCancel stops the kubectl port-forward process.
	portForwardCancel context.CancelFunc
)

func TestMain(m *testing.M) {
	code := runTests(m)
	os.Exit(code)
}

func runTests(m *testing.M) int {
	// Resolve repo root from env var (set by Taskfile) or by navigating from
	// this file's path (works when running go test directly).
	repoRoot = os.Getenv("REPO_ROOT")
	if repoRoot == "" {
		_, filename, _, ok := runtime.Caller(0)
		if !ok {
			fmt.Fprintln(os.Stderr, "ERROR: cannot determine source file path; set REPO_ROOT env var")
			return 1
		}
		// main_test.go is at tools/migration-toolkit/tests/integration/main_test.go
		repoRoot = filepath.Clean(filepath.Join(filepath.Dir(filename), "../../../../"))
	}

	// Validate KUBECONFIG
	if err := checkKubeconfig(); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return 1
	}

	// Build toolkit binary
	var err error
	binaryPath, err = buildBinary()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: build binary: %v\n", err)
		return 1
	}
	defer os.RemoveAll(filepath.Dir(binaryPath))

	// Deploy operator + Keycloak
	testKCName = "keycloak"
	testKCNS = fmt.Sprintf("toolkit-int-%d", time.Now().Unix()%100000)
	testRealmNS = fmt.Sprintf("toolkit-realm-%d", time.Now().Unix()%100000)

	fmt.Printf("==> Deploying test infrastructure in namespaces %s, %s\n", testKCNS, testRealmNS)

	if err := createNamespaces(testKCNS, testRealmNS); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: create namespaces: %v\n", err)
		return 1
	}
	defer func() { _ = deleteNamespaces(testKCNS, testRealmNS) }()

	if err := deployOperatorAndKC(testKCNS, testKCName); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: deploy Keycloak: %v\n", err)
		return 1
	}

	fmt.Printf("==> Waiting for Keycloak CR to be Ready (up to 8 minutes)...\n")
	if err := waitForKeycloakReady(testKCName, testKCNS, 8*time.Minute); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Keycloak not ready: %v\n", err)
		dumpKCLogs(testKCNS)
		return 1
	}

	// Read admin credentials from the auto-generated secret
	testKCUser, testKCPass, err = readAdminCredentials(testKCName, testKCNS)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: read admin credentials: %v\n", err)
		return 1
	}

	// Start port-forward
	var localPort int
	var cancelFwd context.CancelFunc
	localPort, cancelFwd, err = startPortForward(testKCName, testKCNS)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: port-forward: %v\n", err)
		return 1
	}
	portForwardCancel = cancelFwd
	defer cancelFwd()

	testKCURL = fmt.Sprintf("http://localhost:%d", localPort)

	fmt.Printf("==> Waiting for Keycloak HTTP ready at %s...\n", testKCURL)
	if err := waitForKCHTTP(testKCURL, 90*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Keycloak HTTP not ready: %v\n", err)
		return 1
	}

	fmt.Printf("==> Infrastructure ready. Running tests...\n")
	return m.Run()
}

// checkKubeconfig ensures a kubeconfig is available.
func checkKubeconfig() error {
	if kc := os.Getenv("KUBECONFIG"); kc != "" {
		return nil
	}
	defaultKC := filepath.Join(os.Getenv("HOME"), ".kube", "config")
	if _, err := os.Stat(defaultKC); err != nil {
		return fmt.Errorf("KUBECONFIG not set and ~/.kube/config not found")
	}
	return nil
}

// buildBinary compiles keycloak-migrate and returns the binary path.
func buildBinary() (string, error) {
	dir, err := os.MkdirTemp("", "keycloak-migrate-test-*")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}

	binPath := filepath.Join(dir, "keycloak-migrate")
	moduleRoot := filepath.Join(repoRoot, "tools/migration-toolkit")

	cmd := exec.Command("go", "build", "-o", binPath, ".")
	cmd.Dir = moduleRoot
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("go build: %w", err)
	}
	return binPath, nil
}

// createNamespaces creates the given namespaces.
func createNamespaces(namespaces ...string) error {
	for _, ns := range namespaces {
		if _, err := kubectl("create", "namespace", ns); err != nil {
			return fmt.Errorf("create namespace %s: %w", ns, err)
		}
	}
	return nil
}

// deleteNamespaces deletes the given namespaces (best-effort).
func deleteNamespaces(namespaces ...string) error {
	var errs []string
	for _, ns := range namespaces {
		if _, err := kubectl("delete", "namespace", ns, "--ignore-not-found"); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("delete namespaces: %s", strings.Join(errs, "; "))
	}
	return nil
}

// deployOperatorAndKC installs the keycloak-operator Helm chart including a KC instance.
func deployOperatorAndKC(ns, kcName string) error {
	keycloakVersion := os.Getenv("KEYCLOAK_VERSION")
	if keycloakVersion == "" {
		keycloakVersion = "26.5.2"
	}

	// Write Helm values to a temp file
	helmValues := fmt.Sprintf(`
namespace:
  name: %s
  create: false
keycloak:
  managed: true
  name: %s
  replicas: 1
  image: keycloak-optimized
  version: %s
  database:
    cnpg:
      enabled: true
      clusterName: keycloak-cnpg
operator:
  replicaCount: 1
  image:
    repository: keycloak-operator
    tag: test
    pullPolicy: Never
  reconciliation:
    jitterMaxSeconds: 0.1
webhooks:
  enabled: true
`, ns, kcName, keycloakVersion)

	valuesFile, err := os.CreateTemp("", "toolkit-test-values-*.yaml")
	if err != nil {
		return fmt.Errorf("create values file: %w", err)
	}
	defer os.Remove(valuesFile.Name())

	if _, err := valuesFile.WriteString(helmValues); err != nil {
		return fmt.Errorf("write values file: %w", err)
	}
	valuesFile.Close()

	chartPath := filepath.Join(repoRoot, "charts/keycloak-operator")
	_, err = helmRun(
		"upgrade", "--install", "toolkit-test-operator",
		chartPath,
		"-n", ns,
		"-f", valuesFile.Name(),
		"--wait", "--timeout", "5m",
	)
	return err
}

// waitForKeycloakReady polls the Keycloak CR until it reports Ready phase.
func waitForKeycloakReady(name, ns string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		phase, err := kubectlGetKeycloakPhase(name, ns)
		if err == nil && phase == "Ready" {
			return nil
		}
		time.Sleep(10 * time.Second)
	}
	phase, _ := kubectlGetKeycloakPhase(name, ns)
	return fmt.Errorf("timeout waiting for Keycloak %s/%s to be Ready (last phase: %q)", ns, name, phase)
}

// kubectlGetKeycloakPhase reads the status.phase of a Keycloak CR.
func kubectlGetKeycloakPhase(name, ns string) (string, error) {
	out, err := kubectl("get", "keycloak", name, "-n", ns,
		"-o", "jsonpath={.status.phase}")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// readAdminCredentials reads admin username and password from the auto-generated secret.
func readAdminCredentials(kcName, ns string) (string, string, error) {
	secretName := kcName + "-admin-credentials"

	user, err := kubectlGetSecretKey(secretName, ns, "username")
	if err != nil {
		return "", "", fmt.Errorf("read username from secret %s: %w", secretName, err)
	}

	pass, err := kubectlGetSecretKey(secretName, ns, "password")
	if err != nil {
		return "", "", fmt.Errorf("read password from secret %s: %w", secretName, err)
	}

	return user, pass, nil
}

// kubectlGetSecretKey fetches a decoded secret key value.
func kubectlGetSecretKey(secret, ns, key string) (string, error) {
	out, err := kubectl("get", "secret", secret, "-n", ns,
		"-o", fmt.Sprintf("jsonpath={.data.%s}", key))
	if err != nil {
		return "", err
	}

	// Decode base64 value using kubectl
	decoded, err := kubectlDecodeBase64(strings.TrimSpace(out))
	if err != nil {
		return "", err
	}
	return decoded, nil
}

// kubectlDecodeBase64 decodes a base64 string using the Go standard library.
func kubectlDecodeBase64(encoded string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	return string(decoded), nil
}

// startPortForward starts `kubectl port-forward` and returns the local port.
func startPortForward(kcName, ns string) (int, context.CancelFunc, error) {
	// Find a free local port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, nil, fmt.Errorf("find free port: %w", err)
	}
	localPort := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	serviceName := kcName + "-keycloak"
	ctx, cancel := context.WithCancel(context.Background())

	cmd := exec.CommandContext(ctx, "kubectl",
		"port-forward",
		"svc/"+serviceName,
		fmt.Sprintf("%d:8080", localPort),
		"-n", ns,
	)
	cmd.Stdout = os.Stderr // redirect to stderr so test output stays clean
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		cancel()
		return 0, nil, fmt.Errorf("start port-forward: %w", err)
	}

	// Wait for TCP port to be reachable
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", localPort), time.Second)
		if err == nil {
			conn.Close()
			return localPort, cancel, nil
		}
		time.Sleep(500 * time.Millisecond)
	}

	cancel()
	return 0, nil, fmt.Errorf("port-forward to %s:%d not reachable after 30s", serviceName, localPort)
}

// waitForKCHTTP polls the Keycloak health endpoint until it responds 200.
func waitForKCHTTP(baseURL string, timeout time.Duration) error {
	client := &http.Client{Timeout: 5 * time.Second}
	endpoint := baseURL + "/health/ready"
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := client.Get(endpoint)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(3 * time.Second)
	}
	return fmt.Errorf("Keycloak HTTP not ready at %s after %v", endpoint, timeout)
}

// kubectl runs a kubectl command and returns its stdout.
func kubectl(args ...string) (string, error) {
	cmd := exec.Command("kubectl", args...)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("kubectl %s: %w\n%s", strings.Join(args, " "), err, ee.Stderr)
		}
		return "", fmt.Errorf("kubectl %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}

// helmRun runs a helm command.
func helmRun(args ...string) (string, error) {
	cmd := exec.Command("helm", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("helm %s: %w", strings.Join(args, " "), err)
	}
	return "", nil
}

// dumpKCLogs prints operator and KC pod logs to stderr for debugging.
func dumpKCLogs(ns string) {
	fmt.Fprintln(os.Stderr, "=== Keycloak operator logs ===")
	out, _ := kubectl("logs", "-l", "app.kubernetes.io/name=keycloak-operator",
		"-n", ns, "--tail=100")
	fmt.Fprintln(os.Stderr, out)

	fmt.Fprintln(os.Stderr, "=== KC resource status ===")
	out, _ = kubectl("get", "keycloaks,keycloakrealms,keycloakclients",
		"-n", ns, "-o", "wide")
	fmt.Fprintln(os.Stderr, out)
}

// waitForKeycloakRealmCRReady polls the KeycloakRealm CR until it reaches Ready.
func waitForKeycloakRealmCRReady(name, ns string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := kubectl("get", "keycloakrealm", name, "-n", ns,
			"-o", "jsonpath={.status.phase}")
		if err == nil && strings.TrimSpace(out) == "Ready" {
			return nil
		}
		time.Sleep(5 * time.Second)
	}
	out, _ := kubectl("get", "keycloakrealm", name, "-n", ns, "-o", "jsonpath={.status}")
	return fmt.Errorf("realm CR %s/%s not Ready after %v (status: %s)", ns, name, timeout, out)
}

// waitForKeycloakClientCRReady polls the KeycloakClient CR until it reaches Ready.
func waitForKeycloakClientCRReady(name, ns string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := kubectl("get", "keycloakclient", name, "-n", ns,
			"-o", "jsonpath={.status.phase}")
		if err == nil && strings.TrimSpace(out) == "Ready" {
			return nil
		}
		time.Sleep(5 * time.Second)
	}
	out, _ := kubectl("get", "keycloakclient", name, "-n", ns, "-o", "jsonpath={.status}")
	return fmt.Errorf("client CR %s/%s not Ready after %v (status: %s)", ns, name, timeout, out)
}

// kcAdminToken obtains a Keycloak admin token using password grant.
func kcAdminToken(baseURL, user, pass string) (string, error) {
	resp, err := http.PostForm(
		baseURL+"/realms/master/protocol/openid-connect/token",
		map[string][]string{
			"grant_type": {"password"},
			"client_id":  {"admin-cli"},
			"username":   {user},
			"password":   {pass},
		},
	)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request returned %d", resp.StatusCode)
	}

	var payload struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	return payload.AccessToken, nil
}
