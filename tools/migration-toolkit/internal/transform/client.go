package transform

import (
	"fmt"

	"github.com/vriesdemichael/keycloak-operator/tools/migration-toolkit/internal/export"
)

// TransformClient converts a single Keycloak client export into keycloak-client Helm chart values.
func TransformClient(clientRaw map[string]any, realmName string, opts TransformOptions) (map[string]any, []SecretEntry, []Warning) {
	values := make(map[string]any)
	var secrets []SecretEntry
	var warnings []Warning

	clientId := getString(clientRaw, "clientId")
	values["clientId"] = clientId

	// Description
	if v := getString(clientRaw, "description"); v != "" {
		values["description"] = v
	}

	// Realm reference
	values["realmRef"] = map[string]any{
		"name":      realmName,
		"namespace": opts.RealmNamespace,
	}

	// Client type
	values["publicClient"] = getBool(clientRaw, "publicClient", false)
	values["bearerOnly"] = getBool(clientRaw, "bearerOnly", false)
	if v := getString(clientRaw, "protocol"); v != "" {
		values["protocol"] = v
	}

	// URIs
	if uris := transformStringArray(getArray(clientRaw, "redirectUris")); uris != nil {
		values["redirectUris"] = uris
	}
	if origins := transformStringArray(getArray(clientRaw, "webOrigins")); origins != nil {
		values["webOrigins"] = origins
	}
	if postLogout := transformStringArray(getArray(clientRaw, "attributes.post.logout.redirect.uris")); postLogout != nil {
		values["postLogoutRedirectUris"] = postLogout
	}

	// Also check attributes for post logout redirect URIs
	if attrs, ok := clientRaw["attributes"].(map[string]any); ok {
		if v, ok := attrs["post.logout.redirect.uris"].(string); ok && v != "" {
			values["postLogoutRedirectUris"] = []string{v}
		}
	}

	// URLs
	if v := getString(clientRaw, "baseUrl"); v != "" {
		values["baseUrl"] = v
	}
	if v := getString(clientRaw, "rootUrl"); v != "" {
		values["rootUrl"] = v
	}
	if v := getString(clientRaw, "adminUrl"); v != "" {
		values["adminUrl"] = v
	}

	// Client authenticator type
	if v := getString(clientRaw, "clientAuthenticatorType"); v != "" {
		values["clientAuthenticatorType"] = v
	}

	// Flow settings
	flowFields := map[string]string{
		"standardFlowEnabled":       "standardFlowEnabled",
		"implicitFlowEnabled":       "implicitFlowEnabled",
		"directAccessGrantsEnabled": "directAccessGrantsEnabled",
		"serviceAccountsEnabled":    "serviceAccountsEnabled",
	}
	for exportKey, helmKey := range flowFields {
		if _, ok := clientRaw[exportKey]; ok {
			values[helmKey] = getBool(clientRaw, exportKey, false)
		}
	}

	// Consent
	if _, ok := clientRaw["consentRequired"]; ok {
		values["consentRequired"] = getBool(clientRaw, "consentRequired", false)
	}

	// Front-channel logout
	if _, ok := clientRaw["frontchannelLogout"]; ok {
		values["frontchannelLogout"] = getBool(clientRaw, "frontchannelLogout", false)
	}

	// Authorization services
	authzEnabled := getBool(clientRaw, "authorizationServicesEnabled", false)
	values["authorizationServicesEnabled"] = authzEnabled

	// Authorization settings
	if authzEnabled {
		if authzSettings, ok := clientRaw["authorizationSettings"].(map[string]any); ok {
			authz, authzWarnings := TransformAuthorizationSettings(authzSettings)
			if authz != nil {
				values["authorizationSettings"] = authz
			}
			warnings = append(warnings, authzWarnings...)
		}
	}

	// Display settings
	if _, ok := clientRaw["alwaysDisplayInConsole"]; ok {
		values["alwaysDisplayInConsole"] = getBool(clientRaw, "alwaysDisplayInConsole", false)
	}
	if _, ok := clientRaw["fullScopeAllowed"]; ok {
		values["fullScopeAllowed"] = getBool(clientRaw, "fullScopeAllowed", true)
	}

	// Settings (from attributes)
	settings := transformClientSettings(clientRaw)
	if len(settings) > 0 {
		values["settings"] = settings
	}

	// Default/optional client scopes
	if dcs := transformStringArray(getArray(clientRaw, "defaultClientScopes")); dcs != nil {
		values["defaultClientScopes"] = dcs
	}
	if ocs := transformStringArray(getArray(clientRaw, "optionalClientScopes")); ocs != nil {
		values["optionalClientScopes"] = ocs
	}

	// Protocol mappers
	if mappers := transformProtocolMappers(clientRaw); mappers != nil {
		values["protocolMappers"] = mappers
	}

	// Authentication flow overrides
	if overrides, ok := clientRaw["authenticationFlowBindingOverrides"].(map[string]any); ok {
		authFlow := make(map[string]any)
		flowMapping := map[string]string{
			"browser":      "browserFlow",
			"direct_grant": "directGrantFlow",
			"client_auth":  "clientAuthenticationFlow",
		}
		for exportKey, helmKey := range flowMapping {
			if v := getString(overrides, exportKey); v != "" {
				authFlow[helmKey] = v
			}
		}
		if len(authFlow) > 0 {
			values["authenticationFlow"] = authFlow
		}
	}

	// Secret management
	isPublic := getBool(clientRaw, "publicClient", false)
	isBearerOnly := getBool(clientRaw, "bearerOnly", false)

	if !isPublic && !isBearerOnly {
		if opts.ManageSecrets {
			values["manageSecret"] = true
			values["secretRotation"] = map[string]any{
				"enabled":        false,
				"rotationPeriod": "90d",
				"timezone":       "UTC",
			}
		} else {
			values["manageSecret"] = false
		}

		// Extract client secret
		if secret := getString(clientRaw, "secret"); secret != "" {
			secretName := fmt.Sprintf("%s-client-secret", clientId)
			secrets = append(secrets, SecretEntry{
				Name:        secretName,
				Key:         "client-secret",
				Value:       secret,
				Description: fmt.Sprintf("Client secret for '%s'", clientId),
				SourceField: fmt.Sprintf("clients[clientId=%s].secret", clientId),
			})

			if !opts.ManageSecrets {
				values["clientSecret"] = map[string]any{
					"name": secretName,
					"key":  "client-secret",
				}
			}
		}
	}

	return values, secrets, warnings
}

// TransformAllClients processes all clients from a realm export.
func TransformAllClients(exp *export.RealmExport, opts TransformOptions) (map[string]map[string]any, []SecretEntry, []Warning) {
	clients := exp.Clients()
	if clients == nil {
		return nil, nil, nil
	}

	result := make(map[string]map[string]any)
	var allSecrets []SecretEntry
	var allWarnings []Warning
	realmName := exp.GetString("realm")

	for _, clientRaw := range clients {
		clientId := getString(clientRaw, "clientId")
		if clientId == "" {
			continue
		}

		// Skip internal clients
		if opts.SkipInternalClients && InternalClients[clientId] {
			continue
		}

		// Skip deprecated fields (silently)
		cleanedClient := make(map[string]any)
		for k, v := range clientRaw {
			if !DeprecatedClientFields[k] {
				cleanedClient[k] = v
			}
		}

		values, secrets, warnings := TransformClient(cleanedClient, realmName, opts)
		result[clientId] = values
		allSecrets = append(allSecrets, secrets...)
		allWarnings = append(allWarnings, warnings...)
	}

	if len(result) == 0 {
		return nil, allSecrets, allWarnings
	}
	return result, allSecrets, allWarnings
}

func transformClientSettings(clientRaw map[string]any) map[string]any {
	settings := make(map[string]any)

	attrs, ok := clientRaw["attributes"].(map[string]any)
	if !ok {
		return settings
	}

	// PKCE
	if v := getString(attrs, "pkce.code.challenge.method"); v != "" {
		settings["pkceCodeChallengeMethod"] = v
	}

	// Token lifespan
	if v := getString(attrs, "access.token.lifespan"); v != "" {
		if intVal := parseIntString(v); intVal > 0 {
			settings["accessTokenLifespan"] = intVal
		}
	}

	// Session settings
	if v := getString(attrs, "client.session.idle.timeout"); v != "" {
		if intVal := parseIntString(v); intVal > 0 {
			settings["clientSessionIdleTimeout"] = intVal
		}
	}
	if v := getString(attrs, "client.session.max.lifespan"); v != "" {
		if intVal := parseIntString(v); intVal > 0 {
			settings["clientSessionMaxLifespan"] = intVal
		}
	}

	return settings
}

func parseIntString(s string) int {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err == nil {
		return n
	}
	return 0
}
