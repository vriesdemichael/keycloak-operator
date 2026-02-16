package transform

import (
	"testing"
)

func TestTransformClient_PublicSPA(t *testing.T) {
	clientRaw := map[string]any{
		"clientId":                  "frontend-spa",
		"description":               "Single-page application",
		"publicClient":              true,
		"bearerOnly":                false,
		"protocol":                  "openid-connect",
		"standardFlowEnabled":       true,
		"implicitFlowEnabled":       false,
		"directAccessGrantsEnabled": false,
		"serviceAccountsEnabled":    false,
		"consentRequired":           false,
		"fullScopeAllowed":          true,
		"frontchannelLogout":        true,
		"redirectUris":              []any{"https://app.example.com/*"},
		"webOrigins":                []any{"https://app.example.com"},
		"baseUrl":                   "https://app.example.com",
		"rootUrl":                   "https://app.example.com",
		"defaultClientScopes":       []any{"profile", "email"},
		"optionalClientScopes":      []any{"offline_access"},
		"attributes": map[string]any{
			"pkce.code.challenge.method":  "S256",
			"post.logout.redirect.uris":   "https://app.example.com/logout",
			"access.token.lifespan":       "600",
			"client.session.idle.timeout": "1800",
		},
		"protocolMappers": []any{
			map[string]any{
				"name":           "groups",
				"protocol":       "openid-connect",
				"protocolMapper": "oidc-group-membership-mapper",
				"config":         map[string]any{"claim.name": "groups"},
			},
		},
	}
	opts := defaultOpts()
	values, secrets, warnings := TransformClient(clientRaw, "test-realm", opts)

	// Basic fields
	if values["clientId"] != "frontend-spa" {
		t.Errorf("clientId = %v", values["clientId"])
	}
	if values["publicClient"] != true {
		t.Errorf("publicClient = %v, want true", values["publicClient"])
	}
	if values["bearerOnly"] != false {
		t.Errorf("bearerOnly = %v, want false", values["bearerOnly"])
	}
	if values["protocol"] != "openid-connect" {
		t.Errorf("protocol = %v", values["protocol"])
	}
	if values["description"] != "Single-page application" {
		t.Errorf("description = %v", values["description"])
	}

	// Flows
	if values["standardFlowEnabled"] != true {
		t.Errorf("standardFlowEnabled = %v", values["standardFlowEnabled"])
	}
	if values["implicitFlowEnabled"] != false {
		t.Errorf("implicitFlowEnabled = %v", values["implicitFlowEnabled"])
	}
	if values["consentRequired"] != false {
		t.Errorf("consentRequired = %v", values["consentRequired"])
	}
	if values["frontchannelLogout"] != true {
		t.Errorf("frontchannelLogout = %v", values["frontchannelLogout"])
	}
	if values["fullScopeAllowed"] != true {
		t.Errorf("fullScopeAllowed = %v", values["fullScopeAllowed"])
	}

	// URIs
	redirectUris := values["redirectUris"].([]string)
	if len(redirectUris) != 1 || redirectUris[0] != "https://app.example.com/*" {
		t.Errorf("redirectUris = %v", redirectUris)
	}
	webOrigins := values["webOrigins"].([]string)
	if len(webOrigins) != 1 {
		t.Errorf("webOrigins len = %d", len(webOrigins))
	}

	// URLs
	if values["baseUrl"] != "https://app.example.com" {
		t.Errorf("baseUrl = %v", values["baseUrl"])
	}
	if values["rootUrl"] != "https://app.example.com" {
		t.Errorf("rootUrl = %v", values["rootUrl"])
	}

	// Post logout redirect URIs (from attributes)
	postLogout := values["postLogoutRedirectUris"].([]string)
	if len(postLogout) != 1 || postLogout[0] != "https://app.example.com/logout" {
		t.Errorf("postLogoutRedirectUris = %v", postLogout)
	}

	// Realm ref
	realmRef := values["realmRef"].(map[string]any)
	if realmRef["name"] != "test-realm" {
		t.Errorf("realmRef.name = %v", realmRef["name"])
	}
	if realmRef["namespace"] != "my-app" {
		t.Errorf("realmRef.namespace = %v", realmRef["namespace"])
	}

	// Settings (from attributes)
	settings := values["settings"].(map[string]any)
	if settings["pkceCodeChallengeMethod"] != "S256" {
		t.Errorf("pkceCodeChallengeMethod = %v", settings["pkceCodeChallengeMethod"])
	}
	if settings["accessTokenLifespan"] != 600 {
		t.Errorf("accessTokenLifespan = %v, want 600", settings["accessTokenLifespan"])
	}
	if settings["clientSessionIdleTimeout"] != 1800 {
		t.Errorf("clientSessionIdleTimeout = %v, want 1800", settings["clientSessionIdleTimeout"])
	}

	// Protocol mappers
	mappers := values["protocolMappers"].([]any)
	if len(mappers) != 1 {
		t.Errorf("expected 1 mapper, got %d", len(mappers))
	}

	// Client scopes
	dcs := values["defaultClientScopes"].([]string)
	if len(dcs) != 2 {
		t.Errorf("defaultClientScopes len = %d, want 2", len(dcs))
	}

	// Public client should have no secrets or manageSecret
	if len(secrets) != 0 {
		t.Errorf("expected 0 secrets for public client, got %d", len(secrets))
	}
	if _, ok := values["manageSecret"]; ok {
		t.Error("public client should not have manageSecret")
	}

	// No warnings expected for basic client
	if len(warnings) != 0 {
		t.Errorf("expected 0 warnings, got %d: %v", len(warnings), warnings)
	}
}

func TestTransformClient_ConfidentialWithSecret(t *testing.T) {
	clientRaw := map[string]any{
		"clientId":                "api-service",
		"publicClient":            false,
		"bearerOnly":              false,
		"serviceAccountsEnabled":  true,
		"secret":                  "my-client-secret",
		"clientAuthenticatorType": "client-secret",
	}
	opts := defaultOpts()
	values, secrets, _ := TransformClient(clientRaw, "test-realm", opts)

	// Should extract secret
	if len(secrets) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(secrets))
	}
	if secrets[0].Value != "my-client-secret" {
		t.Errorf("secret value = %q", secrets[0].Value)
	}
	if secrets[0].Key != "client-secret" {
		t.Errorf("secret key = %q, want client-secret", secrets[0].Key)
	}

	// ManageSecret should be false (default)
	if values["manageSecret"] != false {
		t.Errorf("manageSecret = %v, want false", values["manageSecret"])
	}

	// Should have clientSecret ref
	csRef, ok := values["clientSecret"].(map[string]any)
	if !ok {
		t.Fatal("clientSecret reference missing")
	}
	if csRef["name"] != "api-service-client-secret" {
		t.Errorf("clientSecret.name = %v", csRef["name"])
	}
}

func TestTransformClient_ConfidentialWithManageSecrets(t *testing.T) {
	clientRaw := map[string]any{
		"clientId":     "api-service",
		"publicClient": false,
		"bearerOnly":   false,
		"secret":       "my-secret",
	}
	opts := defaultOpts()
	opts.ManageSecrets = true

	values, secrets, _ := TransformClient(clientRaw, "test-realm", opts)

	// manageSecret should be true
	if values["manageSecret"] != true {
		t.Errorf("manageSecret = %v, want true", values["manageSecret"])
	}

	// secretRotation should be configured
	rotation, ok := values["secretRotation"].(map[string]any)
	if !ok {
		t.Fatal("secretRotation missing")
	}
	if rotation["enabled"] != false {
		t.Errorf("secretRotation.enabled = %v, want false", rotation["enabled"])
	}

	// clientSecret ref should NOT be present when manageSecrets is true
	if _, ok := values["clientSecret"]; ok {
		t.Error("clientSecret ref should not be present when manageSecrets is true")
	}

	// Secret should still be extracted for inventory purposes
	if len(secrets) != 1 {
		t.Errorf("expected 1 secret, got %d", len(secrets))
	}
}

func TestTransformClient_BearerOnly(t *testing.T) {
	clientRaw := map[string]any{
		"clientId":     "resource-server",
		"publicClient": false,
		"bearerOnly":   true,
	}
	opts := defaultOpts()
	values, secrets, _ := TransformClient(clientRaw, "test-realm", opts)

	if values["bearerOnly"] != true {
		t.Errorf("bearerOnly = %v, want true", values["bearerOnly"])
	}
	// Bearer-only clients should not have manageSecret or secret extraction
	if _, ok := values["manageSecret"]; ok {
		t.Error("bearer-only should not have manageSecret")
	}
	if len(secrets) != 0 {
		t.Errorf("expected 0 secrets for bearer-only, got %d", len(secrets))
	}
}

func TestTransformClient_AuthFlowOverrides(t *testing.T) {
	clientRaw := map[string]any{
		"clientId":     "custom-flow-client",
		"publicClient": true,
		"authenticationFlowBindingOverrides": map[string]any{
			"browser":      "my-browser-flow",
			"direct_grant": "my-direct-grant-flow",
		},
	}
	opts := defaultOpts()
	values, _, _ := TransformClient(clientRaw, "test-realm", opts)

	authFlow, ok := values["authenticationFlow"].(map[string]any)
	if !ok {
		t.Fatal("authenticationFlow missing")
	}
	if authFlow["browserFlow"] != "my-browser-flow" {
		t.Errorf("browserFlow = %v", authFlow["browserFlow"])
	}
	if authFlow["directGrantFlow"] != "my-direct-grant-flow" {
		t.Errorf("directGrantFlow = %v", authFlow["directGrantFlow"])
	}
}

func TestTransformClient_AuthorizationSettings(t *testing.T) {
	clientRaw := map[string]any{
		"clientId":                     "authz-client",
		"publicClient":                 false,
		"bearerOnly":                   false,
		"authorizationServicesEnabled": true,
		"secret":                       "authz-secret",
		"authorizationSettings": map[string]any{
			"policyEnforcementMode": "ENFORCING",
			"scopes": []any{
				map[string]any{"name": "read"},
			},
		},
	}
	opts := defaultOpts()
	values, _, _ := TransformClient(clientRaw, "test-realm", opts)

	if values["authorizationServicesEnabled"] != true {
		t.Errorf("authorizationServicesEnabled = %v", values["authorizationServicesEnabled"])
	}

	authz, ok := values["authorizationSettings"].(map[string]any)
	if !ok {
		t.Fatal("authorizationSettings missing")
	}
	if authz["policyEnforcementMode"] != "ENFORCING" {
		t.Errorf("policyEnforcementMode = %v", authz["policyEnforcementMode"])
	}
}

func TestTransformAllClients_SkipsInternal(t *testing.T) {
	exp := loadFixture(t, "maximal-realm.json")
	opts := defaultOpts()
	opts.SkipInternalClients = true

	result, _, _ := TransformAllClients(exp, opts)

	for name := range InternalClients {
		if _, ok := result[name]; ok {
			t.Errorf("internal client %q should be skipped", name)
		}
	}

	// Should have frontend-spa, api-service, authz-client
	if len(result) != 3 {
		t.Errorf("expected 3 custom clients, got %d", len(result))
	}
	if _, ok := result["frontend-spa"]; !ok {
		t.Error("missing frontend-spa")
	}
	if _, ok := result["api-service"]; !ok {
		t.Error("missing api-service")
	}
	if _, ok := result["authz-client"]; !ok {
		t.Error("missing authz-client")
	}
}

func TestTransformAllClients_IncludesInternal(t *testing.T) {
	exp := loadFixture(t, "minimal-realm.json")
	opts := defaultOpts()
	opts.SkipInternalClients = false

	result, secrets, _ := TransformAllClients(exp, opts)

	// Minimal has "account" + "my-app" + "backend-service"
	if len(result) != 3 {
		t.Errorf("expected 3 clients (including internal), got %d: %v", len(result), keysOf(result))
	}
	if _, ok := result["account"]; !ok {
		t.Error("expected account when SkipInternalClients=false")
	}
	if _, ok := result["my-app"]; !ok {
		t.Error("expected my-app")
	}
	if _, ok := result["backend-service"]; !ok {
		t.Error("expected backend-service")
	}

	// backend-service is confidential with a secret — verify extraction
	backendSecretFound := false
	for _, s := range secrets {
		if s.Name == "backend-service-client-secret" {
			backendSecretFound = true
			if s.Value != "my-backend-client-secret-value" {
				t.Errorf("backend-service secret value = %q, want my-backend-client-secret-value", s.Value)
			}
		}
	}
	if !backendSecretFound {
		t.Error("backend-service client secret not extracted")
	}
}

func TestTransformAllClients_RemovesDeprecatedFields(t *testing.T) {
	exp := loadFixture(t, "medium-realm.json")
	opts := defaultOpts()

	result, _, _ := TransformAllClients(exp, opts)

	// api-service in medium has surrogateAuthRequired and nodeReRegistrationTimeout
	apiService, ok := result["api-service"]
	if !ok {
		t.Fatal("api-service missing")
	}

	// These deprecated fields should not appear in output
	for _, deprecated := range []string{"surrogateAuthRequired", "nodeReRegistrationTimeout"} {
		if _, ok := apiService[deprecated]; ok {
			t.Errorf("deprecated field %q should be stripped", deprecated)
		}
	}
}

func TestTransformAllClients_MediumFixture(t *testing.T) {
	exp := loadFixture(t, "medium-realm.json")
	opts := defaultOpts()

	result, secrets, _ := TransformAllClients(exp, opts)

	// Should have webapp and api-service (account and admin-cli skipped)
	if len(result) != 2 {
		t.Errorf("expected 2 clients, got %d: %v", len(result), keysOf(result))
	}

	// api-service should extract a client secret
	clientSecretFound := false
	for _, s := range secrets {
		if s.Name == "api-service-client-secret" {
			clientSecretFound = true
			if s.Value != "api-service-client-secret-value" {
				t.Errorf("client secret value = %q", s.Value)
			}
		}
	}
	if !clientSecretFound {
		t.Error("api-service client secret not extracted")
	}
}

func TestTransformClientSettings(t *testing.T) {
	clientRaw := map[string]any{
		"attributes": map[string]any{
			"pkce.code.challenge.method":  "S256",
			"access.token.lifespan":       "300",
			"client.session.idle.timeout": "900",
			"client.session.max.lifespan": "3600",
		},
	}

	settings := transformClientSettings(clientRaw)

	if settings["pkceCodeChallengeMethod"] != "S256" {
		t.Errorf("pkceCodeChallengeMethod = %v", settings["pkceCodeChallengeMethod"])
	}
	if settings["accessTokenLifespan"] != 300 {
		t.Errorf("accessTokenLifespan = %v, want 300", settings["accessTokenLifespan"])
	}
	if settings["clientSessionIdleTimeout"] != 900 {
		t.Errorf("clientSessionIdleTimeout = %v, want 900", settings["clientSessionIdleTimeout"])
	}
	if settings["clientSessionMaxLifespan"] != 3600 {
		t.Errorf("clientSessionMaxLifespan = %v, want 3600", settings["clientSessionMaxLifespan"])
	}
}

func TestTransformClientSettings_Empty(t *testing.T) {
	clientRaw := map[string]any{}
	settings := transformClientSettings(clientRaw)
	if len(settings) != 0 {
		t.Errorf("expected empty settings, got %v", settings)
	}
}

func TestParseIntString(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"300", 300},
		{"0", 0},
		{"abc", 0},
		{"", 0},
	}
	for _, tt := range tests {
		got := parseIntString(tt.input)
		if got != tt.want {
			t.Errorf("parseIntString(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

// keysOf returns the keys of a map for debugging
func keysOf(m map[string]map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
