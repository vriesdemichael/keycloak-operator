package transform

import (
	"testing"

	"github.com/vriesdemichael/keycloak-operator/tools/migration-toolkit/internal/export"
)

func TestTransformUserFederation_NoComponents(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{"realm": "test"}}
	result, secrets, warnings := TransformUserFederation(exp, defaultOpts())
	if result != nil {
		t.Errorf("expected nil result, got %v", result)
	}
	if secrets != nil {
		t.Errorf("expected nil secrets, got %v", secrets)
	}
	if warnings != nil {
		t.Errorf("expected nil warnings, got %v", warnings)
	}
}

func TestTransformUserFederation_NoUserStorageProviders(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm": "test",
		"components": map[string]any{
			"org.keycloak.other.Component": []any{},
		},
	}}
	result, _, _ := TransformUserFederation(exp, defaultOpts())
	if result != nil {
		t.Errorf("expected nil result, got %v", result)
	}
}

func TestTransformUserFederation_LDAPProvider(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm": "test",
		"components": map[string]any{
			"org.keycloak.storage.UserStorageProvider": []any{
				map[string]any{
					"name":       "corporate-ldap",
					"providerId": "ldap",
					"enabled":    true,
					"priority":   float64(0),
					"config": map[string]any{
						"connectionUrl":         []any{"ldap://ldap.example.com:389"},
						"bindDn":                []any{"cn=admin,dc=example,dc=com"},
						"bindCredential":        []any{"ldap-password"},
						"usersDn":               []any{"ou=People,dc=example,dc=com"},
						"vendor":                []any{"other"},
						"usernameLdapAttribute": []any{"uid"},
						"uuidLdapAttribute":     []any{"entryUUID"},
						"rdnLdapAttribute":      []any{"uid"},
						"userObjectClasses":     []any{"inetOrgPerson,organizationalPerson"},
						"editMode":              []any{"READ_ONLY"},
						"startTls":              []any{"false"},
						"trustEmail":            []any{"true"},
						"importEnabled":         []any{"true"},
						"fullSyncPeriod":        []any{"604800"},
						"changedSyncPeriod":     []any{"86400"},
					},
				},
			},
		},
	}}

	result, secrets, _ := TransformUserFederation(exp, defaultOpts())
	if len(result) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(result))
	}

	uf := result[0].(map[string]any)

	// Basic fields
	if uf["name"] != "corporate-ldap" {
		t.Errorf("name = %v", uf["name"])
	}
	if uf["providerId"] != "ldap" {
		t.Errorf("providerId = %v", uf["providerId"])
	}
	if uf["enabled"] != true {
		t.Errorf("enabled = %v", uf["enabled"])
	}
	if uf["priority"] != 0 {
		t.Errorf("priority = %v, want 0", uf["priority"])
	}

	// Connection
	if uf["connectionUrl"] != "ldap://ldap.example.com:389" {
		t.Errorf("connectionUrl = %v", uf["connectionUrl"])
	}
	if uf["bindDn"] != "cn=admin,dc=example,dc=com" {
		t.Errorf("bindDn = %v", uf["bindDn"])
	}
	if uf["usersDn"] != "ou=People,dc=example,dc=com" {
		t.Errorf("usersDn = %v", uf["usersDn"])
	}

	// Vendor
	if uf["vendor"] != "other" {
		t.Errorf("vendor = %v", uf["vendor"])
	}

	// Attribute mappings
	if uf["usernameLdapAttribute"] != "uid" {
		t.Errorf("usernameLdapAttribute = %v", uf["usernameLdapAttribute"])
	}
	if uf["uuidLdapAttribute"] != "entryUUID" {
		t.Errorf("uuidLdapAttribute = %v", uf["uuidLdapAttribute"])
	}

	// User object classes (split from comma-separated string)
	classes := uf["userObjectClasses"].([]string)
	if len(classes) != 2 {
		t.Errorf("userObjectClasses len = %d, want 2", len(classes))
	}

	// Edit mode
	if uf["editMode"] != "READ_ONLY" {
		t.Errorf("editMode = %v", uf["editMode"])
	}

	// Bool config
	if uf["startTls"] != false {
		t.Errorf("startTls = %v, want false", uf["startTls"])
	}
	if uf["trustEmail"] != true {
		t.Errorf("trustEmail = %v, want true", uf["trustEmail"])
	}

	// Sync settings
	sync := uf["syncSettings"].(map[string]any)
	if sync["importEnabled"] != true {
		t.Errorf("importEnabled = %v", sync["importEnabled"])
	}
	if sync["fullSyncPeriod"] != 604800 {
		t.Errorf("fullSyncPeriod = %v, want 604800", sync["fullSyncPeriod"])
	}
	if sync["changedUsersSyncPeriod"] != 86400 {
		t.Errorf("changedUsersSyncPeriod = %v, want 86400", sync["changedUsersSyncPeriod"])
	}

	// Bind credential secret
	if len(secrets) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(secrets))
	}
	if secrets[0].Value != "ldap-password" {
		t.Errorf("secret value = %q", secrets[0].Value)
	}
	if secrets[0].Key != "password" {
		t.Errorf("secret key = %q, want password", secrets[0].Key)
	}

	// bindCredentialSecret ref
	bindRef := uf["bindCredentialSecret"].(map[string]any)
	if bindRef["key"] != "password" {
		t.Errorf("bindCredentialSecret.key = %v", bindRef["key"])
	}
}

func TestTransformUserFederation_WithMappers(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm": "test",
		"components": map[string]any{
			"org.keycloak.storage.UserStorageProvider": []any{
				map[string]any{
					"name":       "ldap",
					"providerId": "ldap",
					"config": map[string]any{
						"connectionUrl": []any{"ldap://host"},
					},
					"subComponents": map[string]any{
						"org.keycloak.storage.ldap.mappers.LDAPStorageMapper": []any{
							map[string]any{
								"name":       "email",
								"providerId": "user-attribute-ldap-mapper",
								"config": map[string]any{
									"ldap.attribute":       []any{"mail"},
									"user.model.attribute": []any{"email"},
									"read.only":            []any{"true"},
								},
							},
							map[string]any{
								"name":       "first-name",
								"providerId": "user-attribute-ldap-mapper",
								"config": map[string]any{
									"ldap.attribute":       []any{"givenName"},
									"user.model.attribute": []any{"firstName"},
								},
							},
						},
					},
				},
			},
		},
	}}

	result, _, _ := TransformUserFederation(exp, defaultOpts())
	if len(result) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(result))
	}

	uf := result[0].(map[string]any)
	mappers := uf["mappers"].([]any)
	if len(mappers) != 2 {
		t.Fatalf("expected 2 mappers, got %d", len(mappers))
	}

	mapper1 := mappers[0].(map[string]any)
	if mapper1["name"] != "email" {
		t.Errorf("mapper name = %v, want email", mapper1["name"])
	}
	if mapper1["mapperType"] != "user-attribute-ldap-mapper" {
		t.Errorf("mapperType = %v", mapper1["mapperType"])
	}

	config := mapper1["config"].(map[string]any)
	if config["ldap.attribute"] != "mail" {
		t.Errorf("config[ldap.attribute] = %v, want mail", config["ldap.attribute"])
	}
}

func TestTransformUserFederation_WithKeytab(t *testing.T) {
	exp := &export.RealmExport{Raw: map[string]any{
		"realm": "test",
		"components": map[string]any{
			"org.keycloak.storage.UserStorageProvider": []any{
				map[string]any{
					"name":       "kerberos-ldap",
					"providerId": "ldap",
					"config": map[string]any{
						"connectionUrl":   []any{"ldap://host"},
						"kerberosRealm":   []any{"EXAMPLE.COM"},
						"serverPrincipal": []any{"HTTP/host@EXAMPLE.COM"},
						"keyTab":          []any{"/etc/keytab"},
					},
				},
			},
		},
	}}

	result, secrets, _ := TransformUserFederation(exp, defaultOpts())
	uf := result[0].(map[string]any)

	if uf["kerberosRealm"] != "EXAMPLE.COM" {
		t.Errorf("kerberosRealm = %v", uf["kerberosRealm"])
	}
	if uf["serverPrincipal"] != "HTTP/host@EXAMPLE.COM" {
		t.Errorf("serverPrincipal = %v", uf["serverPrincipal"])
	}

	// Keytab should be extracted as secret
	keytabFound := false
	for _, s := range secrets {
		if s.Key == "keytab" {
			keytabFound = true
			if s.Value != "/etc/keytab" {
				t.Errorf("keytab value = %q", s.Value)
			}
		}
	}
	if !keytabFound {
		t.Error("keytab secret not extracted")
	}

	// keytabSecret ref
	ktRef := uf["keytabSecret"].(map[string]any)
	if ktRef["key"] != "keytab" {
		t.Errorf("keytabSecret.key = %v", ktRef["key"])
	}
}

func TestTransformUserFederation_MaximalFixture(t *testing.T) {
	exp := loadFixture(t, "maximal-realm.json")
	result, secrets, _ := TransformUserFederation(exp, defaultOpts())

	if len(result) != 1 {
		t.Fatalf("expected 1 LDAP provider, got %d", len(result))
	}

	uf := result[0].(map[string]any)
	if uf["name"] != "corporate-ldap" {
		t.Errorf("name = %v", uf["name"])
	}

	// Should have 2 mappers
	mappers := uf["mappers"].([]any)
	if len(mappers) != 2 {
		t.Errorf("expected 2 mappers, got %d", len(mappers))
	}

	// Bind credential secret
	if len(secrets) != 1 {
		t.Errorf("expected 1 secret (bind credential), got %d", len(secrets))
	}
}

func TestGetProviderConfig_Flattening(t *testing.T) {
	provider := map[string]any{
		"config": map[string]any{
			"arrayValue":  []any{"value1"},
			"stringValue": "value2",
			"emptyArray":  []any{},
			"intArray":    []any{42},
		},
	}

	config := getProviderConfig(provider)

	if config["arrayValue"] != "value1" {
		t.Errorf("arrayValue = %v, want value1", config["arrayValue"])
	}
	if config["stringValue"] != "value2" {
		t.Errorf("stringValue = %v, want value2", config["stringValue"])
	}
	if _, ok := config["emptyArray"]; ok {
		t.Error("emptyArray should not be present (empty array)")
	}
	// intArray[0] is float64(42) when from JSON, but here it's int — not a string, so skipped
	if _, ok := config["intArray"]; ok {
		t.Error("intArray should not be present (non-string element)")
	}
}

func TestGetProviderConfig_Nil(t *testing.T) {
	provider := map[string]any{}
	config := getProviderConfig(provider)
	if config != nil {
		t.Errorf("expected nil config, got %v", config)
	}
}

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"corporate-ldap", "corporate-ldap"},
		{"My LDAP", "my-ldap"},
		{"Test_Server", "test-server"},
		{"UPPER", "upper"},
		{"special!@#chars", "specialchars"},
		{"spaces and dashes-ok", "spaces-and-dashes-ok"},
	}

	for _, tt := range tests {
		got := sanitizeName(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSplitTrimmed(t *testing.T) {
	result := splitTrimmed("a, b , c", ",")
	if len(result) != 3 {
		t.Fatalf("expected 3, got %d: %v", len(result), result)
	}
	if result[0] != "a" || result[1] != "b" || result[2] != "c" {
		t.Errorf("result = %v", result)
	}
}

func TestSplitTrimmed_Single(t *testing.T) {
	result := splitTrimmed("single", ",")
	if len(result) != 1 || result[0] != "single" {
		t.Errorf("result = %v", result)
	}
}

func TestGetConfigString(t *testing.T) {
	config := map[string]string{"key": "value"}
	if getConfigString(config, "key") != "value" {
		t.Error("expected value")
	}
	if getConfigString(config, "missing") != "" {
		t.Error("expected empty for missing key")
	}
	if getConfigString(nil, "key") != "" {
		t.Error("expected empty for nil config")
	}
}
