package transform

import (
	"path/filepath"
	"testing"

	"github.com/vriesdemichael/keycloak-operator/tools/migration-toolkit/internal/export"
)

func loadFixture(t *testing.T, name string) *export.RealmExport {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", name)
	exp, err := export.ParseFile(path)
	if err != nil {
		t.Fatalf("failed to load fixture %s: %v", name, err)
	}
	return exp
}

func defaultOpts() TransformOptions {
	return TransformOptions{
		OperatorNamespace:   "keycloak-system",
		RealmNamespace:      "my-app",
		SkipInternalClients: true,
		ManageSecrets:       false,
		SecretMode:          "plain",
	}
}

func TestTransformRealm_Minimal(t *testing.T) {
	exp := loadFixture(t, "minimal-realm.json")
	opts := defaultOpts()

	values, secrets, warnings := TransformRealm(exp, opts)

	// Required fields
	if values["realmName"] != "minimal-test" {
		t.Errorf("realmName = %v, want minimal-test", values["realmName"])
	}
	if values["displayName"] != "Minimal Test Realm" {
		t.Errorf("displayName = %v, want Minimal Test Realm", values["displayName"])
	}

	// Operator ref
	opRef, ok := values["operatorRef"].(map[string]any)
	if !ok {
		t.Fatal("operatorRef missing or not a map")
	}
	if opRef["namespace"] != "keycloak-system" {
		t.Errorf("operatorRef.namespace = %v, want keycloak-system", opRef["namespace"])
	}

	// No secrets or significant warnings for minimal
	if len(secrets) != 0 {
		t.Errorf("expected 0 secrets, got %d", len(secrets))
	}

	// Minimal has no SMTP, IdP, password policy, etc.
	if _, ok := values["smtpServer"]; ok {
		t.Error("minimal should not have smtpServer")
	}
	if _, ok := values["passwordPolicy"]; ok {
		t.Error("minimal should not have passwordPolicy")
	}
	if _, ok := values["identityProviders"]; ok {
		t.Error("minimal should not have identityProviders")
	}

	// Should not have unsupported warnings (no complex features)
	for _, w := range warnings {
		if w.Category == "unsupported" && w.Field != "users" {
			t.Logf("unexpected unsupported warning: %s - %s", w.Field, w.Message)
		}
	}
}

func TestTransformRealm_Medium(t *testing.T) {
	exp := loadFixture(t, "medium-realm.json")
	opts := defaultOpts()

	values, secrets, warnings := TransformRealm(exp, opts)

	// Required fields
	if values["realmName"] != "medium-test" {
		t.Errorf("realmName = %v, want medium-test", values["realmName"])
	}

	// Security settings
	security, ok := values["security"].(map[string]any)
	if !ok {
		t.Fatal("security missing or not a map")
	}
	if security["registrationAllowed"] != true {
		t.Errorf("security.registrationAllowed = %v, want true", security["registrationAllowed"])
	}
	if security["bruteForceProtected"] != true {
		t.Errorf("security.bruteForceProtected = %v, want true", security["bruteForceProtected"])
	}

	// Themes
	themes, ok := values["themes"].(map[string]any)
	if !ok {
		t.Fatal("themes missing or not a map")
	}
	if themes["login"] != "keycloak" {
		t.Errorf("themes.login = %v, want keycloak", themes["login"])
	}
	if themes["account"] != "keycloak.v3" {
		t.Errorf("themes.account = %v, want keycloak.v3", themes["account"])
	}

	// Localization
	localization, ok := values["localization"].(map[string]any)
	if !ok {
		t.Fatal("localization missing or not a map")
	}
	if localization["defaultLocale"] != "en" {
		t.Errorf("localization.defaultLocale = %v, want en", localization["defaultLocale"])
	}
	if localization["enabled"] != true {
		t.Errorf("localization.enabled = %v, want true", localization["enabled"])
	}
	supportedLocales, ok := localization["supportedLocales"].([]string)
	if !ok {
		t.Fatal("supportedLocales missing or not a string slice")
	}
	if len(supportedLocales) != 3 {
		t.Errorf("supportedLocales len = %d, want 3", len(supportedLocales))
	}

	// Token settings
	ts, ok := values["tokenSettings"].(map[string]any)
	if !ok {
		t.Fatal("tokenSettings missing")
	}
	if ts["accessTokenLifespan"] != 600 {
		t.Errorf("accessTokenLifespan = %v, want 600", ts["accessTokenLifespan"])
	}
	if ts["offlineSessionMaxLifespanEnabled"] != true {
		t.Errorf("offlineSessionMaxLifespanEnabled = %v, want true", ts["offlineSessionMaxLifespanEnabled"])
	}

	// SMTP
	smtp, ok := values["smtpServer"].(map[string]any)
	if !ok {
		t.Fatal("smtpServer missing")
	}
	if smtp["host"] != "smtp.example.com" {
		t.Errorf("smtp host = %v, want smtp.example.com", smtp["host"])
	}
	if smtp["starttls"] != true {
		t.Errorf("smtp starttls = %v, want true", smtp["starttls"])
	}
	if smtp["ssl"] != false {
		t.Errorf("smtp ssl = %v, want false", smtp["ssl"])
	}

	// SMTP password secret
	smtpSecretFound := false
	for _, s := range secrets {
		if s.SourceField == "smtpServer.password" {
			smtpSecretFound = true
			if s.Value != "super-secret-smtp-password" {
				t.Errorf("smtp secret value = %q, want super-secret-smtp-password", s.Value)
			}
		}
	}
	if !smtpSecretFound {
		t.Error("SMTP password secret not extracted")
	}

	// Password policy
	pp, ok := values["passwordPolicy"].(map[string]any)
	if !ok {
		t.Fatal("passwordPolicy missing")
	}
	if pp["hashIterations"] != 27500 {
		t.Errorf("hashIterations = %v, want 27500", pp["hashIterations"])
	}

	// Identity providers
	idps, ok := values["identityProviders"].([]any)
	if !ok {
		t.Fatal("identityProviders missing")
	}
	if len(idps) != 1 {
		t.Errorf("expected 1 identity provider, got %d", len(idps))
	}

	// IdP secret extracted
	idpSecretFound := false
	for _, s := range secrets {
		if s.SourceField == "identityProviders[alias=github].config.clientSecret" {
			idpSecretFound = true
			if s.Value != "github-client-secret-value" {
				t.Errorf("idp secret value = %q", s.Value)
			}
		}
	}
	if !idpSecretFound {
		t.Error("GitHub IdP client secret not extracted")
	}

	// Client scopes
	cs, ok := values["clientScopes"].([]any)
	if !ok {
		t.Fatal("clientScopes missing")
	}
	if len(cs) != 1 {
		t.Errorf("expected 1 client scope, got %d", len(cs))
	}

	// Roles
	roles, ok := values["roles"].(map[string]any)
	if !ok {
		t.Fatal("roles missing")
	}
	realmRoles, ok := roles["realmRoles"].([]any)
	if !ok {
		t.Fatal("realmRoles missing")
	}
	// Should skip built-in roles (offline_access, uma_authorization, default-roles-medium-test)
	if len(realmRoles) != 3 {
		t.Errorf("expected 3 custom realm roles, got %d", len(realmRoles))
	}

	// Groups
	groups, ok := values["groups"].([]any)
	if !ok {
		t.Fatal("groups missing")
	}
	if len(groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(groups))
	}

	// Events config
	ec, ok := values["eventsConfig"].(map[string]any)
	if !ok {
		t.Fatal("eventsConfig missing")
	}
	if ec["eventsEnabled"] != true {
		t.Errorf("eventsEnabled = %v, want true", ec["eventsEnabled"])
	}

	// Description (from displayNameHtml)
	if values["description"] != "<h1>Medium Test</h1>" {
		t.Errorf("description = %v, want <h1>Medium Test</h1>", values["description"])
	}

	// User warning
	userWarningFound := false
	for _, w := range warnings {
		if w.Field == "users" && w.Category == "info" {
			userWarningFound = true
		}
	}
	if !userWarningFound {
		t.Error("expected info warning about users")
	}
}

func TestTransformRealm_Maximal(t *testing.T) {
	exp := loadFixture(t, "maximal-realm.json")
	opts := defaultOpts()
	opts.ClientAuthorizationGrants = []string{"ns1", "ns2"}

	values, secrets, warnings := TransformRealm(exp, opts)

	// Realm name
	if values["realmName"] != "maximal-test" {
		t.Errorf("realmName = %v, want maximal-test", values["realmName"])
	}

	// Client authorization grants
	grants, ok := values["clientAuthorizationGrants"].([]string)
	if !ok {
		t.Fatal("clientAuthorizationGrants missing")
	}
	if len(grants) != 2 {
		t.Errorf("expected 2 grants, got %d", len(grants))
	}

	// Security — maximal has more brute force fields
	security, ok := values["security"].(map[string]any)
	if !ok {
		t.Fatal("security missing")
	}
	if security["rememberMe"] != true {
		t.Errorf("security.rememberMe = %v, want true", security["rememberMe"])
	}

	// Token settings — more fields
	ts, ok := values["tokenSettings"].(map[string]any)
	if !ok {
		t.Fatal("tokenSettings missing")
	}
	if ts["accessTokenLifespan"] != 300 {
		t.Errorf("accessTokenLifespan = %v, want 300", ts["accessTokenLifespan"])
	}
	if ts["clientSessionIdleTimeout"] != 1800 {
		t.Errorf("clientSessionIdleTimeout = %v, want 1800", ts["clientSessionIdleTimeout"])
	}

	// Two identity providers
	idps, ok := values["identityProviders"].([]any)
	if !ok {
		t.Fatal("identityProviders missing")
	}
	if len(idps) != 2 {
		t.Errorf("expected 2 identity providers, got %d", len(idps))
	}

	// 2 IdP secrets + SMTP secret = 3 realm-level secrets
	if len(secrets) < 3 {
		t.Errorf("expected at least 3 secrets, got %d", len(secrets))
	}

	// User federation
	uf, ok := values["userFederation"].([]any)
	if !ok {
		t.Fatal("userFederation missing")
	}
	if len(uf) != 1 {
		t.Errorf("expected 1 user federation provider, got %d", len(uf))
	}

	// Client profiles (unwrapped from Keycloak's {"profiles": [...]})
	cp, ok := values["clientProfiles"].([]any)
	if !ok {
		t.Fatal("clientProfiles missing")
	}
	if len(cp) != 1 {
		t.Errorf("expected 1 client profile, got %d", len(cp))
	}

	// Client policies (unwrapped)
	cpol, ok := values["clientPolicies"].([]any)
	if !ok {
		t.Fatal("clientPolicies missing")
	}
	if len(cpol) != 1 {
		t.Errorf("expected 1 client policy, got %d", len(cpol))
	}

	// Unsupported feature warnings — maximal has auth flows, OTP, webauthn, headers, scope mappings, default role
	unsupportedFields := map[string]bool{
		"authenticationFlows":    false,
		"requiredActions":        false,
		"otpPolicy*":             false,
		"webAuthnPolicy*":        false,
		"browserSecurityHeaders": false,
		"scopeMappings":          false,
		"defaultRole":            false,
	}
	for _, w := range warnings {
		if w.Category == "unsupported" {
			unsupportedFields[w.Field] = true
		}
	}
	for field, found := range unsupportedFields {
		if !found {
			t.Errorf("expected unsupported warning for %q", field)
		}
	}
}

func TestTransformRealm_OperatorRef(t *testing.T) {
	exp := loadFixture(t, "minimal-realm.json")
	opts := TransformOptions{
		OperatorNamespace: "custom-ns",
	}
	values, _, _ := TransformRealm(exp, opts)

	opRef, ok := values["operatorRef"].(map[string]any)
	if !ok {
		t.Fatal("operatorRef missing")
	}
	if opRef["namespace"] != "custom-ns" {
		t.Errorf("operatorRef.namespace = %v, want custom-ns", opRef["namespace"])
	}
}

func TestTransformSecurity(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm":                        "test",
		"registrationAllowed":          true,
		"bruteForceProtected":          true,
		"permanentLockout":             false,
		"maxFailureWaitSeconds":        float64(900),
		"minimumQuickLoginWaitSeconds": float64(60),
		"failureFactor":                float64(5),
	}}

	security := transformSecurity(exp)

	if security["registrationAllowed"] != true {
		t.Errorf("registrationAllowed = %v", security["registrationAllowed"])
	}
	if security["bruteForceProtected"] != true {
		t.Errorf("bruteForceProtected = %v", security["bruteForceProtected"])
	}
	if security["permanentLockout"] != false {
		t.Errorf("permanentLockout = %v", security["permanentLockout"])
	}
	if security["maxFailureWait"] != 900 {
		t.Errorf("maxFailureWait = %v, want 900", security["maxFailureWait"])
	}
	if security["failureFactor"] != 5 {
		t.Errorf("failureFactor = %v, want 5", security["failureFactor"])
	}
}

func TestTransformThemes(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm":        "test",
		"loginTheme":   "custom",
		"adminTheme":   "keycloak",
		"accountTheme": "keycloak.v3",
		"emailTheme":   "custom-email",
	}}

	themes := transformThemes(exp)
	if themes["login"] != "custom" {
		t.Errorf("login = %v, want custom", themes["login"])
	}
	if themes["admin"] != "keycloak" {
		t.Errorf("admin = %v, want keycloak", themes["admin"])
	}
	if themes["account"] != "keycloak.v3" {
		t.Errorf("account = %v, want keycloak.v3", themes["account"])
	}
	if themes["email"] != "custom-email" {
		t.Errorf("email = %v, want custom-email", themes["email"])
	}
}

func TestTransformThemes_Empty(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{"realm": "test"}}
	themes := transformThemes(exp)
	if len(themes) != 0 {
		t.Errorf("expected empty themes, got %v", themes)
	}
}

func TestTransformLocalization(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm":                       "test",
		"defaultLocale":               "de",
		"supportedLocales":            []any{"en", "de"},
		"internationalizationEnabled": true,
	}}

	loc := transformLocalization(exp)
	if loc["defaultLocale"] != "de" {
		t.Errorf("defaultLocale = %v, want de", loc["defaultLocale"])
	}
	if loc["enabled"] != true {
		t.Errorf("enabled = %v, want true", loc["enabled"])
	}
	locales := loc["supportedLocales"].([]string)
	if len(locales) != 2 {
		t.Errorf("supportedLocales len = %d, want 2", len(locales))
	}
}

func TestTransformTokenSettings(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm":                            "test",
		"accessTokenLifespan":              float64(300),
		"ssoSessionIdleTimeout":            float64(1800),
		"ssoSessionMaxLifespan":            float64(36000),
		"offlineSessionMaxLifespanEnabled": true,
	}}

	ts := transformTokenSettings(exp)
	if ts["accessTokenLifespan"] != 300 {
		t.Errorf("accessTokenLifespan = %v, want 300", ts["accessTokenLifespan"])
	}
	if ts["ssoSessionIdleTimeout"] != 1800 {
		t.Errorf("ssoSessionIdleTimeout = %v, want 1800", ts["ssoSessionIdleTimeout"])
	}
	if ts["offlineSessionMaxLifespanEnabled"] != true {
		t.Errorf("offlineSessionMaxLifespanEnabled = %v, want true", ts["offlineSessionMaxLifespanEnabled"])
	}
}

func TestTransformSMTP_WithPassword(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm": "test",
		"smtpServer": map[string]any{
			"host":     "smtp.example.com",
			"port":     "587",
			"from":     "noreply@example.com",
			"ssl":      "false",
			"starttls": "true",
			"auth":     "true",
			"password": "secret123",
		},
	}}

	smtp, secrets, _ := transformSMTP(exp, defaultOpts())
	if smtp == nil {
		t.Fatal("expected SMTP config, got nil")
	}
	if smtp["host"] != "smtp.example.com" {
		t.Errorf("host = %v", smtp["host"])
	}
	if smtp["ssl"] != false {
		t.Errorf("ssl = %v, want false", smtp["ssl"])
	}
	if smtp["starttls"] != true {
		t.Errorf("starttls = %v, want true", smtp["starttls"])
	}

	// Password should be extracted
	if len(secrets) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(secrets))
	}
	if secrets[0].Value != "secret123" {
		t.Errorf("secret value = %q, want secret123", secrets[0].Value)
	}

	// SMTP should reference the secret
	pwSecret, ok := smtp["passwordSecret"].(map[string]any)
	if !ok {
		t.Fatal("passwordSecret missing")
	}
	if pwSecret["key"] != "password" {
		t.Errorf("passwordSecret.key = %v, want password", pwSecret["key"])
	}
}

func TestTransformSMTP_Empty(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{"realm": "test"}}
	smtp, secrets, _ := transformSMTP(exp, defaultOpts())
	if smtp != nil {
		t.Errorf("expected nil SMTP for empty export, got %v", smtp)
	}
	if secrets != nil {
		t.Errorf("expected nil secrets for empty export, got %v", secrets)
	}
}

func TestTransformIdentityProviders(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm": "test",
		"identityProviders": []any{
			map[string]any{
				"alias":      "github",
				"providerId": "github",
				"enabled":    true,
				"config": map[string]any{
					"clientId":     "gh-id",
					"clientSecret": "gh-secret",
					"defaultScope": "user:email",
				},
			},
		},
	}}

	idps, secrets, _ := transformIdentityProviders(exp, defaultOpts())
	if len(idps) != 1 {
		t.Fatalf("expected 1 IdP, got %d", len(idps))
	}

	idp := idps[0].(map[string]any)
	if idp["alias"] != "github" {
		t.Errorf("alias = %v, want github", idp["alias"])
	}

	// clientSecret should be removed from config
	config := idp["config"].(map[string]any)
	if _, ok := config["clientSecret"]; ok {
		t.Error("clientSecret should not remain in config")
	}
	if config["defaultScope"] != "user:email" {
		t.Errorf("defaultScope = %v, want user:email", config["defaultScope"])
	}

	// Secret extracted
	if len(secrets) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(secrets))
	}
	if secrets[0].Value != "gh-secret" {
		t.Errorf("secret value = %q", secrets[0].Value)
	}

	// configSecrets should reference the secret
	configSecrets := idp["configSecrets"].(map[string]any)
	csRef := configSecrets["clientSecret"].(map[string]any)
	if csRef["key"] != "client-secret" {
		t.Errorf("configSecrets ref key = %v", csRef["key"])
	}
}

func TestTransformClientScopes(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm": "test",
		"clientScopes": []any{
			map[string]any{
				"name":        "my-scope",
				"description": "Test scope",
				"protocol":    "openid-connect",
				"attributes": map[string]any{
					"display.on.consent.screen": "true",
				},
				"protocolMappers": []any{
					map[string]any{
						"name":           "mapper1",
						"protocol":       "openid-connect",
						"protocolMapper": "oidc-audience-mapper",
						"config":         map[string]any{"key": "val"},
					},
				},
			},
		},
	}}

	scopes := transformClientScopes(exp)
	if len(scopes) != 1 {
		t.Fatalf("expected 1 scope, got %d", len(scopes))
	}
	scope := scopes[0].(map[string]any)
	if scope["name"] != "my-scope" {
		t.Errorf("name = %v, want my-scope", scope["name"])
	}
	mappers := scope["protocolMappers"].([]any)
	if len(mappers) != 1 {
		t.Errorf("expected 1 mapper, got %d", len(mappers))
	}
}

func TestTransformRealmRoles_SkipsBuiltIn(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm": "test",
		"roles": map[string]any{
			"realm": []any{
				map[string]any{"name": "offline_access"},
				map[string]any{"name": "uma_authorization"},
				map[string]any{"name": "default-roles-test"},
				map[string]any{"name": "custom-role", "description": "My role"},
			},
		},
	}}

	roles := transformRealmRoles(exp)
	if len(roles) != 1 {
		t.Fatalf("expected 1 custom role (built-ins skipped), got %d", len(roles))
	}
	role := roles[0].(map[string]any)
	if role["name"] != "custom-role" {
		t.Errorf("role name = %v, want custom-role", role["name"])
	}
}

func TestTransformRealmRoles_Composite(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm": "test",
		"roles": map[string]any{
			"realm": []any{
				map[string]any{
					"name":      "manager",
					"composite": true,
					"composites": map[string]any{
						"realm": []any{"role-a", "role-b"},
					},
				},
			},
		},
	}}

	roles := transformRealmRoles(exp)
	if len(roles) != 1 {
		t.Fatalf("expected 1 role, got %d", len(roles))
	}
	role := roles[0].(map[string]any)
	if role["composite"] != true {
		t.Errorf("composite = %v, want true", role["composite"])
	}
	compositeRoles := role["compositeRoles"].([]string)
	if len(compositeRoles) != 2 {
		t.Errorf("expected 2 composite roles, got %d", len(compositeRoles))
	}
}

func TestTransformGroups_Recursive(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm": "test",
		"groups": []any{
			map[string]any{
				"name":       "parent",
				"realmRoles": []any{"admin"},
				"subGroups": []any{
					map[string]any{
						"name":       "child",
						"realmRoles": []any{"user"},
						"subGroups": []any{
							map[string]any{
								"name": "grandchild",
							},
						},
					},
				},
			},
		},
	}}

	groups := transformGroups(exp)
	if len(groups) != 1 {
		t.Fatalf("expected 1 top-level group, got %d", len(groups))
	}
	parent := groups[0].(map[string]any)
	if parent["name"] != "parent" {
		t.Errorf("parent name = %v", parent["name"])
	}
	subs := parent["subGroups"].([]any)
	if len(subs) != 1 {
		t.Fatalf("expected 1 subgroup, got %d", len(subs))
	}
	child := subs[0].(map[string]any)
	childSubs := child["subGroups"].([]any)
	if len(childSubs) != 1 {
		t.Fatalf("expected 1 grandchild, got %d", len(childSubs))
	}
}

func TestTransformEventsConfig(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm":                     "test",
		"eventsEnabled":             true,
		"adminEventsEnabled":        true,
		"adminEventsDetailsEnabled": true,
		"eventsListeners":           []any{"jboss-logging"},
		"enabledEventTypes":         []any{"LOGIN", "LOGOUT"},
		"eventsExpiration":          float64(604800),
	}}

	ec := transformEventsConfig(exp)
	if ec["eventsEnabled"] != true {
		t.Errorf("eventsEnabled = %v", ec["eventsEnabled"])
	}
	if ec["adminEventsEnabled"] != true {
		t.Errorf("adminEventsEnabled = %v", ec["adminEventsEnabled"])
	}
	if ec["eventsExpiration"] != 604800 {
		t.Errorf("eventsExpiration = %v, want 604800", ec["eventsExpiration"])
	}
}

func TestTransformEventsConfig_Empty(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{"realm": "test"}}
	ec := transformEventsConfig(exp)
	if ec != nil {
		t.Errorf("expected nil for empty events config, got %v", ec)
	}
}

func TestTransformClientProfiles_WrappedFormat(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm": "test",
		"clientProfiles": map[string]any{
			"profiles": []any{
				map[string]any{"name": "profile1"},
			},
		},
	}}

	result := transformClientProfiles(exp)
	if len(result) != 1 {
		t.Errorf("expected 1 profile, got %d", len(result))
	}
}

func TestTransformClientPolicies_WrappedFormat(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm": "test",
		"clientPolicies": map[string]any{
			"policies": []any{
				map[string]any{"name": "policy1"},
			},
		},
	}}

	result := transformClientPolicies(exp)
	if len(result) != 1 {
		t.Errorf("expected 1 policy, got %d", len(result))
	}
}

func TestTransformStringArray(t *testing.T) {
	tests := []struct {
		name  string
		input []any
		want  int
	}{
		{"nil", nil, 0},
		{"strings", []any{"a", "b"}, 2},
		{"mixed", []any{"a", 42, "b"}, 2}, // non-strings skipped
		{"empty", []any{}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := transformStringArray(tt.input)
			if tt.want == 0 {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
			} else if len(result) != tt.want {
				t.Errorf("len = %d, want %d", len(result), tt.want)
			}
		})
	}
}

func TestHelperGetString(t *testing.T) {
	m := map[string]any{"key": "value", "num": 42}
	if getString(m, "key") != "value" {
		t.Errorf("getString(key) = %q, want value", getString(m, "key"))
	}
	if getString(m, "num") != "" {
		t.Errorf("getString(num) = %q, want empty", getString(m, "num"))
	}
	if getString(m, "missing") != "" {
		t.Errorf("getString(missing) = %q, want empty", getString(m, "missing"))
	}
}

func TestHelperGetBool(t *testing.T) {
	m := map[string]any{"yes": true, "no": false, "str": "true"}
	if getBool(m, "yes", false) != true {
		t.Error("getBool(yes) should be true")
	}
	if getBool(m, "no", true) != false {
		t.Error("getBool(no) should be false")
	}
	if getBool(m, "str", false) != false {
		t.Error("getBool(str) should return default for non-bool")
	}
	if getBool(m, "missing", true) != true {
		t.Error("getBool(missing) should return default")
	}
}

func TestHelperGetInt(t *testing.T) {
	m := map[string]any{"num": float64(42), "str": "hello"}
	if getInt(m, "num", 0) != 42 {
		t.Errorf("getInt(num) = %d, want 42", getInt(m, "num", 0))
	}
	if getInt(m, "str", 99) != 99 {
		t.Errorf("getInt(str) = %d, want 99", getInt(m, "str", 99))
	}
	if getInt(m, "missing", 7) != 7 {
		t.Errorf("getInt(missing) = %d, want 7", getInt(m, "missing", 7))
	}
}

func TestHelperGetArray(t *testing.T) {
	m := map[string]any{"arr": []any{"a"}, "str": "hello"}
	arr := getArray(m, "arr")
	if len(arr) != 1 {
		t.Errorf("getArray(arr) len = %d, want 1", len(arr))
	}
	if getArray(m, "str") != nil {
		t.Error("getArray(str) should return nil for non-array")
	}
	if getArray(m, "missing") != nil {
		t.Error("getArray(missing) should return nil")
	}
}
