package transform

import (
	"strings"
	"testing"

	"github.com/vriesdemichael/keycloak-operator/tools/migration-toolkit/internal/export"
)

func TestCheckUnsupportedFeatures_Empty(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm": "empty-test",
	}}

	warnings := checkUnsupportedRealmFeatures(exp)

	for _, w := range warnings {
		if w.Category == "unsupported" {
			t.Errorf("expected no unsupported warnings for empty export, got: %s", w.Message)
		}
	}
}

func TestCheckUnsupportedFeatures_AuthenticationFlows(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm": "test",
		"authenticationFlows": []any{
			map[string]any{"alias": "custom-flow"},
		},
	}}

	warnings := checkUnsupportedRealmFeatures(exp)

	found := false
	for _, w := range warnings {
		if w.Field == "authenticationFlows" {
			found = true
			if w.Category != "unsupported" {
				t.Errorf("category = %q, want %q", w.Category, "unsupported")
			}
			if !strings.Contains(w.IssueURL, "531") {
				t.Errorf("issueURL = %q, want it to contain 531", w.IssueURL)
			}
		}
	}
	if !found {
		t.Error("expected warning for authenticationFlows, got none")
	}
}

func TestCheckUnsupportedFeatures_RequiredActions(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm": "test",
		"requiredActions": []any{
			map[string]any{"alias": "CONFIGURE_TOTP"},
		},
	}}

	warnings := checkUnsupportedRealmFeatures(exp)

	found := false
	for _, w := range warnings {
		if w.Field == "requiredActions" {
			found = true
			if w.Category != "unsupported" {
				t.Errorf("category = %q, want %q", w.Category, "unsupported")
			}
			if !strings.Contains(w.IssueURL, "531") {
				t.Errorf("issueURL = %q, want it to contain 531", w.IssueURL)
			}
		}
	}
	if !found {
		t.Error("expected warning for requiredActions, got none")
	}
}

func TestCheckUnsupportedFeatures_FlowBindings_Default(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm":                    "test",
		"browserFlow":              "browser",
		"registrationFlow":         "registration",
		"directGrantFlow":          "direct grant",
		"resetCredentialsFlow":     "reset credentials",
		"clientAuthenticationFlow": "clients",
		"dockerAuthenticationFlow": "docker auth",
		"firstBrokerLoginFlow":     "first broker login",
	}}

	warnings := checkUnsupportedRealmFeatures(exp)

	for _, w := range warnings {
		flowFields := map[string]bool{
			"browserFlow": true, "registrationFlow": true, "directGrantFlow": true,
			"resetCredentialsFlow": true, "clientAuthenticationFlow": true,
			"dockerAuthenticationFlow": true, "firstBrokerLoginFlow": true,
		}
		if flowFields[w.Field] {
			t.Errorf("default flow binding %q should not generate warning, got: %s", w.Field, w.Message)
		}
	}
}

func TestCheckUnsupportedFeatures_FlowBindings_Custom(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm":       "test",
		"browserFlow": "my-custom-flow",
	}}

	warnings := checkUnsupportedRealmFeatures(exp)

	found := false
	for _, w := range warnings {
		if w.Field == "browserFlow" {
			found = true
			if w.Category != "unsupported" {
				t.Errorf("category = %q, want %q", w.Category, "unsupported")
			}
			if !strings.Contains(w.Message, "my-custom-flow") {
				t.Errorf("message should mention custom flow name, got: %s", w.Message)
			}
			if !strings.Contains(w.IssueURL, "531") {
				t.Errorf("issueURL = %q, want it to contain 531", w.IssueURL)
			}
		}
	}
	if !found {
		t.Error("expected warning for custom browserFlow, got none")
	}
}

func TestCheckUnsupportedFeatures_OTPPolicy(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm":         "test",
		"otpPolicyType": "totp",
	}}

	warnings := checkUnsupportedRealmFeatures(exp)

	found := false
	for _, w := range warnings {
		if w.Field == "otpPolicy*" {
			found = true
			if w.Category != "unsupported" {
				t.Errorf("category = %q, want %q", w.Category, "unsupported")
			}
			if !strings.Contains(w.IssueURL, "532") {
				t.Errorf("issueURL = %q, want it to contain 532", w.IssueURL)
			}
		}
	}
	if !found {
		t.Error("expected warning for OTP policy, got none")
	}
}

func TestCheckUnsupportedFeatures_WebAuthnPolicy(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm":                      "test",
		"webAuthnPolicyRpEntityName": "my-app",
	}}

	warnings := checkUnsupportedRealmFeatures(exp)

	found := false
	for _, w := range warnings {
		if w.Field == "webAuthnPolicy*" {
			found = true
			if w.Category != "unsupported" {
				t.Errorf("category = %q, want %q", w.Category, "unsupported")
			}
			if !strings.Contains(w.IssueURL, "533") {
				t.Errorf("issueURL = %q, want it to contain 533", w.IssueURL)
			}
		}
	}
	if !found {
		t.Error("expected warning for WebAuthn policy, got none")
	}
}

func TestCheckUnsupportedFeatures_BrowserSecurityHeaders(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm": "test",
		"browserSecurityHeaders": map[string]any{
			"xContentTypeOptions": "nosniff",
		},
	}}

	warnings := checkUnsupportedRealmFeatures(exp)

	found := false
	for _, w := range warnings {
		if w.Field == "browserSecurityHeaders" {
			found = true
			if w.Category != "unsupported" {
				t.Errorf("category = %q, want %q", w.Category, "unsupported")
			}
			if !strings.Contains(w.IssueURL, "534") {
				t.Errorf("issueURL = %q, want it to contain 534", w.IssueURL)
			}
		}
	}
	if !found {
		t.Error("expected warning for browserSecurityHeaders, got none")
	}
}

func TestCheckUnsupportedFeatures_ScopeMappings(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm": "test",
		"scopeMappings": []any{
			map[string]any{"clientScope": "offline_access", "roles": []any{"offline_access"}},
		},
	}}

	warnings := checkUnsupportedRealmFeatures(exp)

	found := false
	for _, w := range warnings {
		if w.Field == "scopeMappings" {
			found = true
			if w.Category != "unsupported" {
				t.Errorf("category = %q, want %q", w.Category, "unsupported")
			}
			if !strings.Contains(w.IssueURL, "535") {
				t.Errorf("issueURL = %q, want it to contain 535", w.IssueURL)
			}
		}
	}
	if !found {
		t.Error("expected warning for scopeMappings, got none")
	}
}

func TestCheckUnsupportedFeatures_ClientScopeMappings(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm": "test",
		"clientScopeMappings": map[string]any{
			"account": []any{
				map[string]any{"client": "account", "roles": []any{"view-profile"}},
			},
		},
	}}

	warnings := checkUnsupportedRealmFeatures(exp)

	found := false
	for _, w := range warnings {
		if w.Field == "clientScopeMappings" {
			found = true
			if w.Category != "unsupported" {
				t.Errorf("category = %q, want %q", w.Category, "unsupported")
			}
			if !strings.Contains(w.IssueURL, "535") {
				t.Errorf("issueURL = %q, want it to contain 535", w.IssueURL)
			}
		}
	}
	if !found {
		t.Error("expected warning for clientScopeMappings, got none")
	}
}

func TestCheckUnsupportedFeatures_DefaultRole(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm": "test",
		"defaultRole": map[string]any{
			"name": "default-roles-test",
		},
	}}

	warnings := checkUnsupportedRealmFeatures(exp)

	found := false
	for _, w := range warnings {
		if w.Field == "defaultRole" {
			found = true
			if w.Category != "unsupported" {
				t.Errorf("category = %q, want %q", w.Category, "unsupported")
			}
			if !strings.Contains(w.IssueURL, "536") {
				t.Errorf("issueURL = %q, want it to contain 536", w.IssueURL)
			}
		}
	}
	if !found {
		t.Error("expected warning for defaultRole, got none")
	}
}

func TestCheckUnsupportedFeatures_Users(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm": "test",
		"users": []any{
			map[string]any{"username": "alice"},
			map[string]any{"username": "bob"},
			map[string]any{"username": "charlie"},
		},
	}}

	warnings := checkUnsupportedRealmFeatures(exp)

	found := false
	for _, w := range warnings {
		if w.Field == "users" {
			found = true
			if w.Category != "info" {
				t.Errorf("users warning category = %q, want %q", w.Category, "info")
			}
			if w.Category == "unsupported" {
				t.Error("users warning should NOT be 'unsupported' category")
			}
			if !strings.Contains(w.Message, "3") {
				t.Errorf("message should contain user count '3', got: %s", w.Message)
			}
			if !strings.Contains(w.Message, "ADR-025") {
				t.Errorf("message should mention ADR-025, got: %s", w.Message)
			}
			if w.IssueURL != "" {
				t.Errorf("users info warning should not have issueURL, got: %s", w.IssueURL)
			}
		}
	}
	if !found {
		t.Error("expected info warning for users, got none")
	}
}

func TestCheckUnsupportedFeatures_AllPresent(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm": "test",
		// authenticationFlows — 1 warning
		"authenticationFlows": []any{map[string]any{"alias": "custom"}},
		// requiredActions — 1 warning
		"requiredActions": []any{map[string]any{"alias": "CONFIGURE_TOTP"}},
		// custom flow binding — 1 warning (only non-default)
		"browserFlow":              "my-custom-browser",
		"registrationFlow":         "registration",       // default, no warning
		"directGrantFlow":          "direct grant",       // default, no warning
		"resetCredentialsFlow":     "reset credentials",  // default, no warning
		"clientAuthenticationFlow": "clients",            // default, no warning
		"dockerAuthenticationFlow": "docker auth",        // default, no warning
		"firstBrokerLoginFlow":     "first broker login", // default, no warning
		// OTP policy — 1 warning
		"otpPolicyType": "totp",
		// WebAuthn — 1 warning
		"webAuthnPolicyRpEntityName": "my-app",
		// Browser security headers — 1 warning
		"browserSecurityHeaders": map[string]any{"xFrameOptions": "SAMEORIGIN"},
		// Scope mappings — 1 warning
		"scopeMappings": []any{map[string]any{"clientScope": "offline_access"}},
		// Client scope mappings — 1 warning
		"clientScopeMappings": map[string]any{"account": []any{}},
		// Default role — 1 warning
		"defaultRole": map[string]any{"name": "default-roles-test"},
		// Users — 1 info warning
		"users": []any{map[string]any{"username": "alice"}},
	}}

	warnings := checkUnsupportedRealmFeatures(exp)

	// Count expected warnings:
	// authenticationFlows(1) + requiredActions(1) + browserFlow custom(1) +
	// otpPolicy(1) + webAuthn(1) + browserSecurityHeaders(1) +
	// scopeMappings(1) + clientScopeMappings(1) + defaultRole(1) + users(1) = 10
	expected := 10
	if len(warnings) != expected {
		t.Errorf("expected %d warnings, got %d", expected, len(warnings))
		for i, w := range warnings {
			t.Logf("  warning[%d]: category=%q field=%q message=%q", i, w.Category, w.Field, w.Message)
		}
	}

	// Verify category distribution
	unsupportedCount := 0
	infoCount := 0
	for _, w := range warnings {
		switch w.Category {
		case "unsupported":
			unsupportedCount++
		case "info":
			infoCount++
		}
	}
	if unsupportedCount != 9 {
		t.Errorf("expected 9 unsupported warnings, got %d", unsupportedCount)
	}
	if infoCount != 1 {
		t.Errorf("expected 1 info warning, got %d", infoCount)
	}
}

func TestCheckUnsupportedFeatures_IssueURLs(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm":                      "test",
		"authenticationFlows":        []any{map[string]any{"alias": "x"}},
		"requiredActions":            []any{map[string]any{"alias": "x"}},
		"browserFlow":                "custom-browser",
		"otpPolicyType":              "totp",
		"webAuthnPolicyRpEntityName": "app",
		"browserSecurityHeaders":     map[string]any{"k": "v"},
		"scopeMappings":              []any{map[string]any{"x": "y"}},
		"clientScopeMappings":        map[string]any{"c": []any{}},
		"defaultRole":                map[string]any{"name": "dr"},
	}}

	warnings := checkUnsupportedRealmFeatures(exp)

	expectedIssues := map[string]string{
		"authenticationFlows":    "531",
		"requiredActions":        "531",
		"browserFlow":            "531",
		"otpPolicy*":             "532",
		"webAuthnPolicy*":        "533",
		"browserSecurityHeaders": "534",
		"scopeMappings":          "535",
		"clientScopeMappings":    "535",
		"defaultRole":            "536",
	}

	foundFields := make(map[string]bool)
	for _, w := range warnings {
		if expectedIssue, ok := expectedIssues[w.Field]; ok {
			foundFields[w.Field] = true
			if !strings.Contains(w.IssueURL, expectedIssue) {
				t.Errorf("field %q: issueURL = %q, want it to contain issue %s", w.Field, w.IssueURL, expectedIssue)
			}
			if !strings.HasPrefix(w.IssueURL, "https://github.com/vriesdemichael/keycloak-operator/issues/") {
				t.Errorf("field %q: issueURL = %q, want it to be a full GitHub issue URL", w.Field, w.IssueURL)
			}
		}
	}

	for field := range expectedIssues {
		if !foundFields[field] {
			t.Errorf("expected warning for field %q, but none was found", field)
		}
	}
}
