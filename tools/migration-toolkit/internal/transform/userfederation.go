package transform

import (
	"fmt"

	"github.com/vriesdemichael/keycloak-operator/tools/migration-toolkit/internal/export"
)

// TransformUserFederation converts Keycloak export components into
// structured userFederation Helm values.
//
// Keycloak stores user federation providers in the "components" map under
// the key "org.keycloak.storage.UserStorageProvider". Each provider has
// its config in a flat key-value format where values are single-element arrays.
func TransformUserFederation(exp *export.RealmExport, opts TransformOptions) ([]any, []SecretEntry, []Warning) {
	components := exp.Components()
	if components == nil {
		return nil, nil, nil
	}

	providers, ok := components["org.keycloak.storage.UserStorageProvider"].([]any)
	if !ok || len(providers) == 0 {
		return nil, nil, nil
	}

	var result []any
	var secrets []SecretEntry
	var warnings []Warning

	for _, providerRaw := range providers {
		provider, ok := providerRaw.(map[string]any)
		if !ok {
			continue
		}

		uf, ufSecrets, ufWarnings := transformSingleProvider(provider, exp.GetString("realm"), opts)
		if uf != nil {
			result = append(result, uf)
			secrets = append(secrets, ufSecrets...)
			warnings = append(warnings, ufWarnings...)
		}
	}

	if len(result) == 0 {
		return nil, secrets, warnings
	}
	return result, secrets, warnings
}

func transformSingleProvider(provider map[string]any, realmName string, opts TransformOptions) (map[string]any, []SecretEntry, []Warning) {
	config := getProviderConfig(provider)
	providerName := getString(provider, "name")
	providerId := getString(provider, "providerId")

	if providerId == "" {
		providerId = "ldap" // default
	}

	uf := map[string]any{
		"name":       providerName,
		"providerId": providerId,
	}

	var secrets []SecretEntry
	var warnings []Warning

	// Priority
	if v, ok := provider["priority"].(float64); ok {
		uf["priority"] = int(v)
	}

	// Enabled (stored in parentConfig or top-level)
	if _, ok := provider["enabled"]; ok {
		uf["enabled"] = getBool(provider, "enabled", true)
	}

	// Connection settings
	if v := getConfigString(config, "connectionUrl"); v != "" {
		uf["connectionUrl"] = v
	}
	if v := getConfigString(config, "bindDn"); v != "" {
		uf["bindDn"] = v
	}
	if v := getConfigString(config, "usersDn"); v != "" {
		uf["usersDn"] = v
	}

	// Bind credential — extract as secret
	if v := getConfigString(config, "bindCredential"); v != "" {
		secretName := fmt.Sprintf("%s-ldap-%s-bind", SanitizeK8sName(realmName), SanitizeK8sName(providerName))
		secrets = append(secrets, SecretEntry{
			Name:        secretName,
			Key:         "password",
			Value:       v,
			Description: fmt.Sprintf("LDAP bind credential for '%s'", providerName),
			SourceField: fmt.Sprintf("components[UserStorageProvider][name=%s].config.bindCredential", providerName),
		})
		uf["bindCredentialSecret"] = map[string]any{
			"name": secretName,
			"key":  "password",
		}
	}

	// Vendor
	if v := getConfigString(config, "vendor"); v != "" {
		uf["vendor"] = v
	}

	// LDAP attribute mappings
	attrFields := map[string]string{
		"usernameLdapAttribute": "usernameLdapAttribute",
		"uuidLdapAttribute":     "uuidLdapAttribute",
		"rdnLdapAttribute":      "rdnLdapAttribute",
	}
	for configKey, helmKey := range attrFields {
		if v := getConfigString(config, configKey); v != "" {
			uf[helmKey] = v
		}
	}

	// User object classes
	if v := getConfigString(config, "userObjectClasses"); v != "" {
		uf["userObjectClasses"] = splitTrimmed(v, ",")
	}

	// Boolean config fields
	boolConfigs := map[string]string{
		"startTls":                    "startTls",
		"trustEmail":                  "trustEmail",
		"allowKerberosAuthentication": "allowKerberosAuthentication",
	}
	for configKey, helmKey := range boolConfigs {
		if v := getConfigString(config, configKey); v != "" {
			uf[helmKey] = v == "true"
		}
	}

	// Edit mode
	if v := getConfigString(config, "editMode"); v != "" {
		uf["editMode"] = v
	}

	// Search scope
	if v := getConfigString(config, "searchScope"); v != "" {
		if intVal := parseIntString(v); intVal > 0 {
			uf["searchScope"] = intVal
		}
	}

	// Kerberos settings
	if v := getConfigString(config, "kerberosRealm"); v != "" {
		uf["kerberosRealm"] = v
	}
	if v := getConfigString(config, "serverPrincipal"); v != "" {
		uf["serverPrincipal"] = v
	}

	// Keytab — extract as secret
	if v := getConfigString(config, "keyTab"); v != "" {
		secretName := fmt.Sprintf("%s-ldap-%s-keytab", SanitizeK8sName(realmName), SanitizeK8sName(providerName))
		secrets = append(secrets, SecretEntry{
			Name:        secretName,
			Key:         "keytab",
			Value:       v,
			Description: fmt.Sprintf("Kerberos keytab for '%s'", providerName),
			SourceField: fmt.Sprintf("components[UserStorageProvider][name=%s].config.keyTab", providerName),
		})
		uf["keytabSecret"] = map[string]any{
			"name": secretName,
			"key":  "keytab",
		}
	}

	// Sync settings
	syncSettings := make(map[string]any)
	if v := getConfigString(config, "importEnabled"); v != "" {
		syncSettings["importEnabled"] = v == "true"
	}
	if v := getConfigString(config, "fullSyncPeriod"); v != "" {
		if intVal := parseIntString(v); intVal != 0 {
			syncSettings["fullSyncPeriod"] = intVal
		}
	}
	if v := getConfigString(config, "changedSyncPeriod"); v != "" {
		if intVal := parseIntString(v); intVal != 0 {
			syncSettings["changedUsersSyncPeriod"] = intVal
		}
	}
	if len(syncSettings) > 0 {
		uf["syncSettings"] = syncSettings
	}

	// LDAP mappers — from sub-components
	mappers := transformLDAPMappers(provider, realmName)
	if mappers != nil {
		uf["mappers"] = mappers
	}

	return uf, secrets, warnings
}

func transformLDAPMappers(provider map[string]any, realmName string) []any {
	// In Keycloak exports, mappers are in the components map under
	// "org.keycloak.storage.ldap.mappers.LDAPStorageMapper"
	// They reference their parent provider via parentId.
	// Since we process each provider individually, the caller should
	// pass the full components and filter by parentId.
	// For now, we look for subComponents on the provider itself.

	subComponents, ok := provider["subComponents"].(map[string]any)
	if !ok {
		return nil
	}

	ldapMappers, ok := subComponents["org.keycloak.storage.ldap.mappers.LDAPStorageMapper"].([]any)
	if !ok || len(ldapMappers) == 0 {
		return nil
	}

	var result []any
	for _, mapperRaw := range ldapMappers {
		mapper, ok := mapperRaw.(map[string]any)
		if !ok {
			continue
		}

		m := map[string]any{
			"name":       getString(mapper, "name"),
			"mapperType": getString(mapper, "providerId"),
		}

		if config := getProviderConfig(mapper); len(config) > 0 {
			flatConfig := make(map[string]any)
			for k, v := range config {
				flatConfig[k] = v
			}
			m["config"] = flatConfig
		}

		result = append(result, m)
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

// getProviderConfig extracts the flat config map from a Keycloak component.
// Keycloak stores config values as single-element string arrays, e.g.:
//
//	{"config": {"connectionUrl": ["ldap://host:389"]}}
//
// This function flattens them to simple strings.
func getProviderConfig(provider map[string]any) map[string]string {
	configRaw, ok := provider["config"].(map[string]any)
	if !ok {
		return nil
	}

	result := make(map[string]string)
	for k, v := range configRaw {
		switch val := v.(type) {
		case []any:
			if len(val) > 0 {
				if s, ok := val[0].(string); ok {
					result[k] = s
				}
			}
		case string:
			result[k] = val
		}
	}
	return result
}

func getConfigString(config map[string]string, key string) string {
	if config == nil {
		return ""
	}
	return config[key]
}

func splitTrimmed(s string, sep string) []string {
	var result []string
	for _, part := range splitString(s, sep) {
		trimmed := trimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func splitString(s string, sep string) []string {
	if sep == "" {
		return []string{s}
	}
	var result []string
	for {
		idx := indexOf(s, sep)
		if idx < 0 {
			result = append(result, s)
			break
		}
		result = append(result, s[:idx])
		s = s[idx+len(sep):]
	}
	return result
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
