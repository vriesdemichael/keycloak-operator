package transform

import (
	"fmt"

	"github.com/vriesdemichael/keycloak-operator/tools/migration-toolkit/internal/export"
)

// TransformRealm converts a Keycloak realm export into keycloak-realm Helm chart values.
func TransformRealm(exp *export.RealmExport, opts TransformOptions) (map[string]any, []SecretEntry, []Warning) {
	values := make(map[string]any)
	var secrets []SecretEntry
	var warnings []Warning

	// Required fields
	values["realmName"] = exp.GetString("realm")

	if v := exp.GetString("displayName"); v != "" {
		values["displayName"] = v
	}

	// Operator reference
	values["operatorRef"] = map[string]any{
		"namespace": opts.OperatorNamespace,
	}

	// Client authorization grants
	if len(opts.ClientAuthorizationGrants) > 0 {
		values["clientAuthorizationGrants"] = opts.ClientAuthorizationGrants
	}

	// Security settings
	security := transformSecurity(exp)
	if len(security) > 0 {
		values["security"] = security
	}

	// Themes
	themes := transformThemes(exp)
	if len(themes) > 0 {
		values["themes"] = themes
	}

	// Localization
	localization := transformLocalization(exp)
	if len(localization) > 0 {
		values["localization"] = localization
	}

	// Token settings
	tokenSettings := transformTokenSettings(exp)
	if len(tokenSettings) > 0 {
		values["tokenSettings"] = tokenSettings
	}

	// SMTP server
	smtp, smtpSecrets, smtpWarnings := transformSMTP(exp, opts)
	if smtp != nil {
		values["smtpServer"] = smtp
		secrets = append(secrets, smtpSecrets...)
		warnings = append(warnings, smtpWarnings...)
	}

	// Attributes
	if attrs := exp.GetMap("attributes"); attrs != nil && len(attrs) > 0 {
		values["attributes"] = attrs
	}

	// Description
	if v := exp.GetString("displayNameHtml"); v != "" {
		values["description"] = v
	}

	// Password policy
	if policyStr := exp.GetString("passwordPolicy"); policyStr != "" {
		policy, policyWarnings := ParsePasswordPolicy(policyStr)
		if policy != nil {
			values["passwordPolicy"] = policy
		}
		warnings = append(warnings, policyWarnings...)
	}

	// Identity providers
	idps, idpSecrets, idpWarnings := transformIdentityProviders(exp, opts)
	if idps != nil {
		values["identityProviders"] = idps
		secrets = append(secrets, idpSecrets...)
		warnings = append(warnings, idpWarnings...)
	}

	// Client scopes
	if scopes := transformClientScopes(exp); scopes != nil {
		values["clientScopes"] = scopes
	}

	// Default/optional client scopes
	if dcs := transformStringArray(exp.GetArray("defaultDefaultClientScopes")); dcs != nil {
		values["defaultClientScopes"] = dcs
	}
	if ocs := transformStringArray(exp.GetArray("defaultOptionalClientScopes")); ocs != nil {
		values["optionalClientScopes"] = ocs
	}

	// Roles
	realmRoles := transformRealmRoles(exp)
	if realmRoles != nil {
		values["roles"] = map[string]any{
			"realmRoles": realmRoles,
		}
	}

	// Groups
	groups := transformGroups(exp)
	if groups != nil {
		values["groups"] = groups
	}

	// Default groups
	if dg := transformStringArray(exp.GetArray("defaultGroups")); dg != nil {
		values["defaultGroups"] = dg
	}

	// User federation
	uf, ufSecrets, ufWarnings := TransformUserFederation(exp, opts)
	if uf != nil {
		values["userFederation"] = uf
		secrets = append(secrets, ufSecrets...)
		warnings = append(warnings, ufWarnings...)
	}

	// Events config
	eventsConfig := transformEventsConfig(exp)
	if eventsConfig != nil {
		values["eventsConfig"] = eventsConfig
	}

	// Client profiles & policies (pass through if present)
	// Keycloak exports these as {"profiles": [...]} / {"policies": [...]}, not arrays directly
	if exp.HasKey("clientProfiles") {
		if cp := transformClientProfiles(exp); cp != nil {
			values["clientProfiles"] = cp
		}
	}
	if exp.HasKey("clientPolicies") {
		if cpol := transformClientPolicies(exp); cpol != nil {
			values["clientPolicies"] = cpol
		}
	}

	// Unsupported features with issue references
	warnings = append(warnings, checkUnsupportedRealmFeatures(exp)...)

	return values, secrets, warnings
}

func transformSecurity(exp *export.RealmExport) map[string]any {
	s := make(map[string]any)

	boolFields := map[string]string{
		"registrationAllowed":         "registrationAllowed",
		"registrationEmailAsUsername": "registrationEmailAsUsername",
		"editUsernameAllowed":         "editUsernameAllowed",
		"resetPasswordAllowed":        "resetPasswordAllowed",
		"rememberMe":                  "rememberMe",
		"verifyEmail":                 "verifyEmail",
		"loginWithEmailAllowed":       "loginWithEmailAllowed",
		"duplicateEmailsAllowed":      "duplicateEmailsAllowed",
		"bruteForceProtected":         "bruteForceProtected",
		"permanentLockout":            "permanentLockout",
	}

	for exportKey, helmKey := range boolFields {
		if exp.HasKey(exportKey) {
			s[helmKey] = exp.GetBool(exportKey, false)
		}
	}

	intFields := map[string]string{
		"maxFailureWaitSeconds":        "maxFailureWait",
		"minimumQuickLoginWaitSeconds": "minimumQuickLoginWait",
		"waitIncrementSeconds":         "waitIncrement",
		"quickLoginCheckMilliSeconds":  "quickLoginCheckMillis",
		"maxDeltaTimeSeconds":          "maxDeltaTime",
		"failureFactor":                "failureFactor",
	}

	for exportKey, helmKey := range intFields {
		if exp.HasKey(exportKey) {
			s[helmKey] = exp.GetInt(exportKey, 0)
		}
	}

	return s
}

func transformThemes(exp *export.RealmExport) map[string]any {
	t := make(map[string]any)
	themeFields := map[string]string{
		"loginTheme":   "login",
		"adminTheme":   "admin",
		"accountTheme": "account",
		"emailTheme":   "email",
	}
	for exportKey, helmKey := range themeFields {
		if v := exp.GetString(exportKey); v != "" {
			t[helmKey] = v
		}
	}
	return t
}

func transformLocalization(exp *export.RealmExport) map[string]any {
	l := make(map[string]any)
	if v := exp.GetString("defaultLocale"); v != "" {
		l["defaultLocale"] = v
	}
	if arr := transformStringArray(exp.GetArray("supportedLocales")); arr != nil {
		l["supportedLocales"] = arr
	}
	if exp.HasKey("internationalizationEnabled") {
		l["enabled"] = exp.GetBool("internationalizationEnabled", false)
	}
	return l
}

func transformTokenSettings(exp *export.RealmExport) map[string]any {
	ts := make(map[string]any)
	intFields := map[string]string{
		"accessTokenLifespan":                "accessTokenLifespan",
		"accessTokenLifespanForImplicitFlow": "accessTokenLifespanForImplicitFlow",
		"ssoSessionIdleTimeout":              "ssoSessionIdleTimeout",
		"ssoSessionMaxLifespan":              "ssoSessionMaxLifespan",
		"offlineSessionIdleTimeout":          "offlineSessionIdleTimeout",
		"offlineSessionMaxLifespan":          "offlineSessionMaxLifespan",
		"clientSessionIdleTimeout":           "clientSessionIdleTimeout",
		"clientSessionMaxLifespan":           "clientSessionMaxLifespan",
	}
	for exportKey, helmKey := range intFields {
		if exp.HasKey(exportKey) {
			ts[helmKey] = exp.GetInt(exportKey, 0)
		}
	}
	if exp.HasKey("offlineSessionMaxLifespanEnabled") {
		ts["offlineSessionMaxLifespanEnabled"] = exp.GetBool("offlineSessionMaxLifespanEnabled", false)
	}
	return ts
}

func transformSMTP(exp *export.RealmExport, opts TransformOptions) (map[string]any, []SecretEntry, []Warning) {
	smtpRaw := exp.GetMap("smtpServer")
	if smtpRaw == nil || len(smtpRaw) == 0 {
		return nil, nil, nil
	}

	smtp := map[string]any{
		"enabled": true,
	}
	var secrets []SecretEntry
	var warnings []Warning

	// String fields
	stringFields := []string{"host", "from", "fromDisplayName", "replyTo", "envelopeFrom", "user"}
	for _, f := range stringFields {
		if v, ok := smtpRaw[f]; ok {
			if s, ok := v.(string); ok && s != "" {
				smtp[f] = s
			}
		}
	}

	// Port
	if v, ok := smtpRaw["port"]; ok {
		switch p := v.(type) {
		case string:
			smtp["port"] = p
		case float64:
			smtp["port"] = int(p)
		}
	}

	// Bool fields (Keycloak exports these as strings "true"/"false")
	boolStringFields := map[string]string{"ssl": "ssl", "starttls": "starttls", "auth": "auth"}
	for exportKey, helmKey := range boolStringFields {
		if v, ok := smtpRaw[exportKey]; ok {
			switch b := v.(type) {
			case string:
				smtp[helmKey] = b == "true"
			case bool:
				smtp[helmKey] = b
			}
		}
	}

	// Password — extract as secret
	if v, ok := smtpRaw["password"]; ok {
		if pw, ok := v.(string); ok && pw != "" {
			realmName := exp.GetString("realm")
			secretName := fmt.Sprintf("%s-smtp-password", SanitizeK8sName(realmName))
			secrets = append(secrets, SecretEntry{
				Name:        secretName,
				Key:         "password",
				Value:       pw,
				Description: "SMTP server password",
				SourceField: "smtpServer.password",
			})
			smtp["passwordSecret"] = map[string]any{
				"name": secretName,
				"key":  "password",
			}
		}
	}

	return smtp, secrets, warnings
}

func transformIdentityProviders(exp *export.RealmExport, opts TransformOptions) ([]any, []SecretEntry, []Warning) {
	arr := exp.GetArray("identityProviders")
	if arr == nil {
		return nil, nil, nil
	}

	var result []any
	var secrets []SecretEntry
	var warnings []Warning

	for _, item := range arr {
		idpRaw, ok := item.(map[string]any)
		if !ok {
			continue
		}

		idp := make(map[string]any)

		// Direct fields
		directFields := []string{"alias", "providerId", "displayName", "enabled", "trustEmail",
			"storeToken", "linkOnly", "firstBrokerLoginFlowAlias", "postBrokerLoginFlowAlias"}
		for _, f := range directFields {
			if v, ok := idpRaw[f]; ok {
				idp[f] = v
			}
		}

		// Config — extract secrets
		if configRaw, ok := idpRaw["config"].(map[string]any); ok {
			config := make(map[string]any)
			configSecrets := make(map[string]any)

			for k, v := range configRaw {
				if k == "clientSecret" {
					if secret, ok := v.(string); ok && secret != "" {
						alias := getString(idpRaw, "alias")
						realmName := exp.GetString("realm")
						secretName := fmt.Sprintf("%s-idp-%s-secret", SanitizeK8sName(realmName), SanitizeK8sName(alias))
						secrets = append(secrets, SecretEntry{
							Name:        secretName,
							Key:         "client-secret",
							Value:       secret,
							Description: fmt.Sprintf("Identity provider '%s' client secret", alias),
							SourceField: fmt.Sprintf("identityProviders[alias=%s].config.clientSecret", alias),
						})
						configSecrets["clientSecret"] = map[string]any{
							"name": secretName,
							"key":  "client-secret",
						}
					}
				} else {
					config[k] = v
				}
			}

			if len(config) > 0 {
				idp["config"] = config
			}
			if len(configSecrets) > 0 {
				idp["configSecrets"] = configSecrets
			}
		}

		result = append(result, idp)
	}

	return result, secrets, warnings
}

func transformClientScopes(exp *export.RealmExport) []any {
	arr := exp.GetArray("clientScopes")
	if arr == nil {
		return nil
	}

	var result []any
	for _, item := range arr {
		csRaw, ok := item.(map[string]any)
		if !ok {
			continue
		}

		cs := make(map[string]any)
		directFields := []string{"name", "description", "protocol"}
		for _, f := range directFields {
			if v, ok := csRaw[f]; ok {
				cs[f] = v
			}
		}

		if attrs, ok := csRaw["attributes"].(map[string]any); ok && len(attrs) > 0 {
			cs["attributes"] = attrs
		}

		if mappers := transformProtocolMappers(csRaw); mappers != nil {
			cs["protocolMappers"] = mappers
		}

		result = append(result, cs)
	}

	return result
}

func transformProtocolMappers(parent map[string]any) []any {
	arr, ok := parent["protocolMappers"].([]any)
	if !ok || len(arr) == 0 {
		return nil
	}

	var result []any
	for _, item := range arr {
		pmRaw, ok := item.(map[string]any)
		if !ok {
			continue
		}

		pm := make(map[string]any)
		for _, f := range []string{"name", "protocol", "protocolMapper"} {
			if v, ok := pmRaw[f]; ok {
				pm[f] = v
			}
		}
		if config, ok := pmRaw["config"].(map[string]any); ok && len(config) > 0 {
			pm["config"] = config
		}

		result = append(result, pm)
	}

	return result
}

func transformRealmRoles(exp *export.RealmExport) []any {
	rolesMap := exp.GetMap("roles")
	if rolesMap == nil {
		return nil
	}

	realmRoles, ok := rolesMap["realm"].([]any)
	if !ok || len(realmRoles) == 0 {
		return nil
	}

	var result []any
	for _, item := range realmRoles {
		roleRaw, ok := item.(map[string]any)
		if !ok {
			continue
		}

		// Skip default Keycloak roles
		name := getString(roleRaw, "name")
		if name == "offline_access" || name == "uma_authorization" || name == "default-roles-"+exp.GetString("realm") {
			continue
		}

		role := map[string]any{
			"name": name,
		}
		if desc := getString(roleRaw, "description"); desc != "" {
			role["description"] = desc
		}
		if composite, ok := roleRaw["composite"].(bool); ok && composite {
			role["composite"] = true
			// Extract composite role names
			if composites, ok := roleRaw["composites"].(map[string]any); ok {
				if realmComps, ok := composites["realm"].([]any); ok {
					role["compositeRoles"] = transformStringArray(realmComps)
				}
			}
		}
		if attrs, ok := roleRaw["attributes"].(map[string]any); ok && len(attrs) > 0 {
			role["attributes"] = attrs
		}

		result = append(result, role)
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

func transformGroups(exp *export.RealmExport) []any {
	arr := exp.GetArray("groups")
	if arr == nil {
		return nil
	}

	var result []any
	for _, item := range arr {
		groupRaw, ok := item.(map[string]any)
		if !ok {
			continue
		}
		group := transformGroup(groupRaw)
		result = append(result, group)
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

func transformGroup(groupRaw map[string]any) map[string]any {
	group := make(map[string]any)

	if name := getString(groupRaw, "name"); name != "" {
		group["name"] = name
	}
	if attrs, ok := groupRaw["attributes"].(map[string]any); ok && len(attrs) > 0 {
		group["attributes"] = attrs
	}
	if realmRoles := transformStringArray(getArray(groupRaw, "realmRoles")); realmRoles != nil {
		group["realmRoles"] = realmRoles
	}
	if clientRoles, ok := groupRaw["clientRoles"].(map[string]any); ok && len(clientRoles) > 0 {
		group["clientRoles"] = clientRoles
	}

	// Recursive subgroups
	if subGroups := getArray(groupRaw, "subGroups"); subGroups != nil {
		var subs []any
		for _, sg := range subGroups {
			if sgMap, ok := sg.(map[string]any); ok {
				subs = append(subs, transformGroup(sgMap))
			}
		}
		if len(subs) > 0 {
			group["subGroups"] = subs
		}
	}

	return group
}

func transformEventsConfig(exp *export.RealmExport) map[string]any {
	ec := make(map[string]any)
	hasContent := false

	if exp.HasKey("eventsEnabled") {
		ec["eventsEnabled"] = exp.GetBool("eventsEnabled", false)
		hasContent = true
	}
	if exp.HasKey("adminEventsEnabled") {
		ec["adminEventsEnabled"] = exp.GetBool("adminEventsEnabled", false)
		hasContent = true
	}
	if exp.HasKey("adminEventsDetailsEnabled") {
		ec["adminEventsDetailsEnabled"] = exp.GetBool("adminEventsDetailsEnabled", false)
		hasContent = true
	}
	if arr := transformStringArray(exp.GetArray("eventsListeners")); arr != nil {
		ec["eventsListeners"] = arr
		hasContent = true
	}
	if arr := transformStringArray(exp.GetArray("enabledEventTypes")); arr != nil {
		ec["enabledEventTypes"] = arr
		hasContent = true
	}
	if exp.HasKey("eventsExpiration") {
		ec["eventsExpiration"] = exp.GetInt("eventsExpiration", 0)
		hasContent = true
	}

	if !hasContent {
		return nil
	}
	return ec
}

func transformClientProfiles(exp *export.RealmExport) []any {
	// Keycloak exports clientProfiles as {"profiles": [...]}
	cpRaw := exp.GetMap("clientProfiles")
	if cpRaw != nil {
		if profiles, ok := cpRaw["profiles"].([]any); ok {
			return profiles
		}
	}
	// Fallback: maybe it's directly an array
	return exp.GetArray("clientProfiles")
}

func transformClientPolicies(exp *export.RealmExport) []any {
	// Keycloak exports clientPolicies as {"policies": [...]}
	cpRaw := exp.GetMap("clientPolicies")
	if cpRaw != nil {
		if policies, ok := cpRaw["policies"].([]any); ok {
			return policies
		}
	}
	return exp.GetArray("clientPolicies")
}

// Helper functions

func getString(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getBool(m map[string]any, key string, defaultVal bool) bool {
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return defaultVal
}

func getInt(m map[string]any, key string, defaultVal int) int {
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		}
	}
	return defaultVal
}

func getArray(m map[string]any, key string) []any {
	if v, ok := m[key]; ok {
		if arr, ok := v.([]any); ok {
			return arr
		}
	}
	return nil
}

func transformStringArray(arr []any) []string {
	if arr == nil {
		return nil
	}
	var result []string
	for _, item := range arr {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}
