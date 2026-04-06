//go:build integration

package integration

import (
	"os"
	"testing"
	"time"
)

// TestBinary_Version verifies the --version flag is accepted and produces output.
// Note: the binary is built without -ldflags injection in the test harness, so
// the version will always be the default "dev". CI release builds embed the real
// version via -ldflags at publish time.
func TestBinary_Version(t *testing.T) {
	out, err := runBinary(t, "--version")
	if err != nil {
		t.Fatalf("--version failed: %v\noutput: %s", err, out)
	}
	if len(out) == 0 {
		t.Fatal("--version produced no output")
	}
	t.Logf("version output: %s", out)
}

// TestRoundTrip_Transform verifies the full pipeline:
//   - transform: source realm JSON → Helm chart values
//   - apply: Helm install realm + client CRs via operator
//   - verify: realm settings, clients, roles match source
//   - client secrets preserved from source export
func TestRoundTrip_Transform(t *testing.T) {
	outputDir, err := os.MkdirTemp("", "toolkit-roundtrip-*")
	if err != nil {
		t.Fatalf("create output dir: %v", err)
	}
	defer os.RemoveAll(outputDir)

	// Step 1: transform
	sourceRealm := testdataPath("source-realm.json")
	runTransform(t, sourceRealm, outputDir)

	// Step 2: apply realm + client CRs via Helm
	realmName := applyTransformOutput(t, outputDir)
	if realmName == "" {
		t.Fatal("no realm name from transform output")
	}
	t.Logf("realm name from transform: %s", realmName)

	// Step 3: wait for realm CR to be Ready
	waitForRealmReady(t, realmName, 3*time.Minute)

	// Step 4: verify via Admin REST API
	token := mustToken(t)

	// --- Realm settings ---
	realm := kcGetRealm(t, token, realmName)
	t.Logf("realm displayName: %v", realm["displayName"])

	if got, want := realm["displayName"], "Toolkit E2E Test Realm"; got != want {
		t.Errorf("displayName: got %q, want %q", got, want)
	}
	if enabled, _ := realm["enabled"].(bool); !enabled {
		t.Error("realm should be enabled")
	}
	if loginTheme, _ := realm["loginTheme"].(string); loginTheme != "" {
		t.Logf("loginTheme preserved: %s", loginTheme)
	}

	// --- Realm roles ---
	roles := kcGetRoles(t, token, realmName)
	roleNames := make(map[string]bool)
	for _, r := range roles {
		if n, ok := r["name"].(string); ok {
			roleNames[n] = true
		}
	}
	for _, expected := range []string{"app-user", "app-admin"} {
		if !roleNames[expected] {
			t.Errorf("expected realm role %q not found; present: %v", expected, roleNames)
		}
	}

	// --- Clients ---
	clients := kcGetClients(t, token, realmName)
	t.Logf("found %d non-internal clients", len(clients))

	// Public client verified
	pubClient, ok := findClientByID(clients, "toolkit-public-app")
	if !ok {
		t.Errorf("public client 'toolkit-public-app' not found")
	} else {
		if public, _ := pubClient["publicClient"].(bool); !public {
			t.Error("toolkit-public-app should be publicClient=true")
		}
		if standard, _ := pubClient["standardFlowEnabled"].(bool); !standard {
			t.Error("toolkit-public-app should have standardFlowEnabled=true")
		}
	}

	// Confidential client + secret verified
	backendClient, ok := findClientByID(clients, "toolkit-backend")
	if !ok {
		t.Errorf("backend client 'toolkit-backend' not found")
	} else {
		if public, _ := backendClient["publicClient"].(bool); public {
			t.Error("toolkit-backend should be publicClient=false")
		}
		if svc, _ := backendClient["serviceAccountsEnabled"].(bool); !svc {
			t.Error("toolkit-backend should have serviceAccountsEnabled=true")
		}

		// Verify client secret was preserved from source export
		clientUUID, _ := backendClient["id"].(string)
		if clientUUID != "" {
			secret := kcGetClientSecret(t, token, realmName, clientUUID)
			const wantSecret = "toolkit-backend-secret-value-e2e"
			if secret != wantSecret {
				t.Errorf("toolkit-backend client secret: got %q, want %q", secret, wantSecret)
			}
		}
	}
}

// TestRoundTrip_ImportUsers verifies the full end-to-end pipeline including
// user import. This builds on TestRoundTrip_Transform by additionally running
// import-users and verifying users, their attributes, and role assignments.
// This test uses a separate realm to avoid interference with TestRoundTrip_Transform.
func TestRoundTrip_ImportUsers(t *testing.T) {
	outputDir, err := os.MkdirTemp("", "toolkit-importusers-*")
	if err != nil {
		t.Fatalf("create output dir: %v", err)
	}
	defer os.RemoveAll(outputDir)

	// Step 1: transform source realm
	sourceRealm := testdataPath("source-realm.json")
	runTransform(t, sourceRealm, outputDir)

	// Step 2-3: apply and wait for Ready (realm CR deployment)
	realmName := applyTransformOutput(t, outputDir)
	waitForRealmReady(t, realmName, 3*time.Minute)

	// Step 4: import-users via explicit credentials
	out, err := runBinary(t,
		"import-users",
		"--input", outputDir+"/users.json",
		"--server-url", testKCURL,
		"--username", testKCUser,
		"--password", testKCPass,
		"--realm", realmName,
	)
	if err != nil {
		t.Fatalf("import-users failed: %v\noutput:\n%s", err, out)
	}
	t.Logf("import-users output:\n%s", out)

	// Step 5: verify users exist with correct attributes and role assignments
	token := mustToken(t)
	users := kcGetUsers(t, token, realmName)
	t.Logf("found %d users in realm", len(users))

	// Verify expected users
	for _, expectedUser := range []struct {
		username  string
		email     string
		roles     []string
		verified  bool
	}{
		{"alice", "alice@toolkit-test.example.com", []string{"app-user"}, true},
		{"bob", "bob@toolkit-test.example.com", []string{"app-user", "app-admin"}, true},
		{"charlie", "charlie@toolkit-test.example.com", []string{}, false},
	} {
		user, found := findUserByUsername(users, expectedUser.username)
		if !found {
			t.Errorf("user %q not found after import", expectedUser.username)
			continue
		}

		if email, _ := user["email"].(string); email != expectedUser.email {
			t.Errorf("user %s email: got %q, want %q", expectedUser.username, email, expectedUser.email)
		}

		verified, _ := user["emailVerified"].(bool)
		if verified != expectedUser.verified {
			t.Errorf("user %s emailVerified: got %v, want %v",
				expectedUser.username, verified, expectedUser.verified)
		}

		if len(expectedUser.roles) > 0 {
			userID, _ := user["id"].(string)
			assignedRoles := kcGetUserRoles(t, token, realmName, userID)
			for _, role := range expectedUser.roles {
				if !containsString(assignedRoles, role) {
					t.Errorf("user %s missing role %q (assigned: %v)",
						expectedUser.username, role, assignedRoles)
				}
			}
		}
	}
}

// TestImportUsers_DryRun verifies that --dry-run exits 0 but creates no users.
func TestImportUsers_DryRun(t *testing.T) {
	outputDir, err := os.MkdirTemp("", "toolkit-dryrun-*")
	if err != nil {
		t.Fatalf("create output dir: %v", err)
	}
	defer os.RemoveAll(outputDir)

	sourceRealm := testdataPath("source-realm.json")
	runTransform(t, sourceRealm, outputDir)
	realmName := applyTransformOutput(t, outputDir)
	waitForRealmReady(t, realmName, 3*time.Minute)

	// Dry run — should succeed with zero side-effects
	out, err := runBinary(t,
		"import-users",
		"--input", outputDir+"/users.json",
		"--server-url", testKCURL,
		"--username", testKCUser,
		"--password", testKCPass,
		"--realm", realmName,
		"--dry-run",
	)
	if err != nil {
		t.Fatalf("dry-run failed unexpectedly: %v\noutput:\n%s", err, out)
	}

	// No users should exist
	token := mustToken(t)
	users := kcGetUsers(t, token, realmName)
	if len(users) > 0 {
		t.Errorf("dry-run created %d users; expected 0", len(users))
	}
}

// TestImportUsers_Idempotent verifies that running import-users twice (mode=skip)
// is a no-op on the second run and terminates successfully.
func TestImportUsers_Idempotent(t *testing.T) {
	outputDir, err := os.MkdirTemp("", "toolkit-idempotent-*")
	if err != nil {
		t.Fatalf("create output dir: %v", err)
	}
	defer os.RemoveAll(outputDir)

	sourceRealm := testdataPath("source-realm.json")
	runTransform(t, sourceRealm, outputDir)
	realmName := applyTransformOutput(t, outputDir)
	waitForRealmReady(t, realmName, 3*time.Minute)

	importArgs := []string{
		"import-users",
		"--input", outputDir + "/users.json",
		"--server-url", testKCURL,
		"--username", testKCUser,
		"--password", testKCPass,
		"--realm", realmName,
		"--mode", "skip",
	}

	// First run
	out, err := runBinary(t, importArgs...)
	if err != nil {
		t.Fatalf("first import run failed: %v\noutput:\n%s", err, out)
	}

	// Count users after first run
	token := mustToken(t)
	usersAfterFirst := kcGetUsers(t, token, realmName)
	countFirst := len(usersAfterFirst)
	t.Logf("users after first import: %d", countFirst)

	// Second run
	out, err = runBinary(t, importArgs...)
	if err != nil {
		t.Fatalf("second import run failed: %v\noutput:\n%s", err, out)
	}

	// User count must not have changed
	usersAfterSecond := kcGetUsers(t, token, realmName)
	if len(usersAfterSecond) != countFirst {
		t.Errorf("idempotency violated: user count changed from %d to %d on second run",
			countFirst, len(usersAfterSecond))
	}
}

// TestImportUsers_ViaKubeContext verifies credential resolution from the Keycloak CR
// using --keycloak and --namespace flags (no explicit username/password).
func TestImportUsers_ViaKubeContext(t *testing.T) {
	outputDir, err := os.MkdirTemp("", "toolkit-kubecontext-*")
	if err != nil {
		t.Fatalf("create output dir: %v", err)
	}
	defer os.RemoveAll(outputDir)

	sourceRealm := testdataPath("source-realm.json")
	runTransform(t, sourceRealm, outputDir)
	realmName := applyTransformOutput(t, outputDir)
	waitForRealmReady(t, realmName, 3*time.Minute)

	// Use kube context credential resolution + explicit --server-url to override
	// internal cluster URL (port-forward makes KC accessible on localhost).
	out, err := runBinary(t,
		"import-users",
		"--input", outputDir+"/users.json",
		"--keycloak", testKCName,
		"--namespace", testKCNS,
		"--server-url", testKCURL,
		"--realm", realmName,
	)
	if err != nil {
		t.Fatalf("import-users via kube context failed: %v\noutput:\n%s", err, out)
	}
	t.Logf("output:\n%s", out)

	// Users should have been imported
	token := mustToken(t)
	users := kcGetUsers(t, token, realmName)
	if len(users) == 0 {
		t.Error("no users found after kube-context import")
	}
}
