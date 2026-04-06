//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// runBinary executes the compiled keycloak-migrate binary with the given args.
// Returns combined stdout output and any error.
func runBinary(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(binaryPath, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// runBinaryInDir executes the compiled binary with the given working directory.
func runBinaryInDir(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// kcAdminRequest executes an Admin REST API request and decodes the response body.
func kcAdminRequest(method, path, token string, body io.Reader) (*http.Response, error) {
	url := testKCURL + path
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("new request %s %s: %w", method, url, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request %s %s: %w", method, url, err)
	}
	return resp, nil
}

// kcGetRealm returns the realm representation for the given realm name.
// Uses partial-export for realm settings; supplements with full realm GET.
func kcGetRealm(t *testing.T, token, realm string) map[string]any {
	t.Helper()
	resp, err := kcAdminRequest("GET",
		"/admin/realms/"+realm, token, nil)
	if err != nil {
		t.Fatalf("get realm %s: %v", realm, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get realm %s: status %d", realm, resp.StatusCode)
	}
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode realm response: %v", err)
	}
	return result
}

// kcGetRoles returns realm roles.
func kcGetRoles(t *testing.T, token, realm string) []map[string]any {
	t.Helper()
	resp, err := kcAdminRequest("GET",
		"/admin/realms/"+realm+"/roles", token, nil)
	if err != nil {
		t.Fatalf("get roles for realm %s: %v", realm, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get roles: status %d", resp.StatusCode)
	}
	var result []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode roles: %v", err)
	}
	return result
}

// kcGetClients returns the non-internal clients for a realm.
func kcGetClients(t *testing.T, token, realm string) []map[string]any {
	t.Helper()
	resp, err := kcAdminRequest("GET",
		"/admin/realms/"+realm+"/clients", token, nil)
	if err != nil {
		t.Fatalf("get clients for realm %s: %v", realm, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get clients: status %d", resp.StatusCode)
	}
	var all []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&all); err != nil {
		t.Fatalf("decode clients: %v", err)
	}

	// Filter out Keycloak internal clients.
	internal := map[string]bool{
		"account": true, "account-console": true, "admin-cli": true,
		"broker": true, "master-realm": true, "security-admin-console": true,
	}
	var result []map[string]any
	for _, c := range all {
		if clientID, ok := c["clientId"].(string); ok && !internal[clientID] {
			result = append(result, c)
		}
	}
	return result
}

// kcGetClientSecret returns the client secret for the given client UUID.
func kcGetClientSecret(t *testing.T, token, realm, clientUUID string) string {
	t.Helper()
	resp, err := kcAdminRequest("GET",
		"/admin/realms/"+realm+"/clients/"+clientUUID+"/client-secret",
		token, nil)
	if err != nil {
		t.Fatalf("get client secret %s: %v", clientUUID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get client secret: status %d", resp.StatusCode)
	}
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode client secret: %v", err)
	}
	if v, ok := result["value"].(string); ok {
		return v
	}
	return ""
}

// kcGetUsers returns all users in the given realm (paginated, max 1000).
func kcGetUsers(t *testing.T, token, realm string) []map[string]any {
	t.Helper()
	resp, err := kcAdminRequest("GET",
		"/admin/realms/"+realm+"/users?max=1000", token, nil)
	if err != nil {
		t.Fatalf("get users for realm %s: %v", realm, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get users: status %d", resp.StatusCode)
	}
	var result []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode users: %v", err)
	}
	return result
}

// kcGetUserRoles returns the realm role assignments for a user ID.
func kcGetUserRoles(t *testing.T, token, realm, userID string) []string {
	t.Helper()
	resp, err := kcAdminRequest("GET",
		"/admin/realms/"+realm+"/users/"+userID+"/role-mappings/realm",
		token, nil)
	if err != nil {
		t.Fatalf("get user roles %s: %v", userID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get user roles: status %d", resp.StatusCode)
	}
	var roles []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&roles); err != nil {
		t.Fatalf("decode user roles: %v", err)
	}
	var names []string
	for _, r := range roles {
		if n, ok := r["name"].(string); ok {
			names = append(names, n)
		}
	}
	return names
}

// runTransform runs `keycloak-migrate transform` on the given realm JSON file
// and writes output to outputDir. Returns the outputDir path.
func runTransform(t *testing.T, realmJSON, outputDir string) {
	t.Helper()
	out, err := runBinary(t,
		"transform",
		"--input", realmJSON,
		"--output-dir", outputDir,
		"--operator-namespace", testKCNS,
		"--realm-namespace", testRealmNS,
		"--client-grants", testRealmNS,
	)
	if err != nil {
		t.Fatalf("keycloak-migrate transform failed: %v\noutput:\n%s", err, out)
	}
	t.Logf("transform output:\n%s", out)
}

// helmInstallValues installs a Helm chart release using a values file.
func helmInstallValues(t *testing.T, releaseName, chartPath, ns, valuesFile string) {
	t.Helper()
	cmd := exec.Command("helm",
		"upgrade", "--install", releaseName, chartPath,
		"-n", ns,
		"-f", valuesFile,
		"--wait", "--timeout", "2m",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("helm install %s: %v", releaseName, err)
	}
}

// applyTransformOutput installs the realm and all clients produced by transform.
// Returns the realm name extracted from realm-values.yaml.
func applyTransformOutput(t *testing.T, outputDir string) string {
	t.Helper()

	// Read realm-values.yaml to get realmName for later use
	realmValuesPath := filepath.Join(outputDir, "realm-values.yaml")
	data, err := os.ReadFile(realmValuesPath)
	if err != nil {
		t.Fatalf("read realm-values.yaml: %v", err)
	}
	var realmValues map[string]any
	if err := yaml.Unmarshal(data, &realmValues); err != nil {
		t.Fatalf("parse realm-values.yaml: %v", err)
	}
	realmName, _ := realmValues["realmName"].(string)
	if realmName == "" {
		t.Fatal("realm-values.yaml missing realmName")
	}

	// Install realm chart
	realmChartPath := filepath.Join(repoRoot, "charts/keycloak-realm")
	helmInstallValues(t, "toolkit-test-realm", realmChartPath, testRealmNS, realmValuesPath)

	// Install client charts (one per subdirectory under clients/)
	clientsDir := filepath.Join(outputDir, "clients")
	if entries, err := os.ReadDir(clientsDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			valuesFile := filepath.Join(clientsDir, entry.Name(), "values.yaml")
			if _, err := os.Stat(valuesFile); os.IsNotExist(err) {
				continue
			}
			clientChartPath := filepath.Join(repoRoot, "charts/keycloak-client")
			releaseName := "toolkit-test-client-" + entry.Name()
			helmInstallValues(t, releaseName, clientChartPath, testRealmNS, valuesFile)
		}
	}

	return realmName
}

// waitForRealmReady waits until the realm CR is Ready and clients are Ready.
func waitForRealmReady(t *testing.T, realmName string, timeout time.Duration) {
	t.Helper()
	// Realm CR name is typically the realm name lowercased
	crName := strings.ToLower(realmName)
	if err := waitForKeycloakRealmCRReady(crName, testRealmNS, timeout); err != nil {
		dumpCRStatus(t)
		t.Fatal(err)
	}
}

// dumpCRStatus prints CR statuses for debugging failures.
func dumpCRStatus(t *testing.T) {
	t.Helper()
	out, _ := kubectl("get", "keycloakrealm,keycloakclient", "-n", testRealmNS, "-o", "wide")
	t.Logf("CR statuses:\n%s", out)
	out, _ = kubectl("describe", "keycloakrealm", "-n", testRealmNS)
	t.Logf("Realm CR describe:\n%s", out)
}

// mustToken obtains an admin token or fails the test.
func mustToken(t *testing.T) string {
	t.Helper()
	token, err := kcAdminToken(testKCURL, testKCUser, testKCPass)
	if err != nil {
		t.Fatalf("get admin token: %v", err)
	}
	return token
}

// findClientByID finds a client in the list by clientId.
func findClientByID(clients []map[string]any, clientID string) (map[string]any, bool) {
	for _, c := range clients {
		if id, ok := c["clientId"].(string); ok && id == clientID {
			return c, true
		}
	}
	return nil, false
}

// findUserByUsername finds a user by username.
func findUserByUsername(users []map[string]any, username string) (map[string]any, bool) {
	for _, u := range users {
		if n, ok := u["username"].(string); ok && n == username {
			return u, true
		}
	}
	return nil, false
}

// containsString reports whether a string slice contains the given value.
func containsString(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// testdataPath returns the absolute path to a testdata file.
func testdataPath(name string) string {
	return filepath.Join(repoRoot,
		"tools/migration-toolkit/tests/integration/testdata", name)
}
