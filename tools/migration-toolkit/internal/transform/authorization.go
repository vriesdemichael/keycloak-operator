package transform

// TransformAuthorizationSettings converts Keycloak export authorizationSettings
// into the keycloak-client Helm chart's authorizationSettings structure.
func TransformAuthorizationSettings(settings map[string]any) (map[string]any, []Warning) {
	if settings == nil {
		return nil, nil
	}

	result := make(map[string]any)
	var warnings []Warning

	// Top-level settings
	if v := getString(settings, "policyEnforcementMode"); v != "" {
		result["policyEnforcementMode"] = v
	}
	if v := getString(settings, "decisionStrategy"); v != "" {
		result["decisionStrategy"] = v
	}
	if _, ok := settings["allowRemoteResourceManagement"]; ok {
		result["allowRemoteResourceManagement"] = getBool(settings, "allowRemoteResourceManagement", true)
	}

	// Scopes
	if scopes := transformAuthzScopes(settings); scopes != nil {
		result["scopes"] = scopes
	}

	// Resources
	if resources := transformAuthzResources(settings); resources != nil {
		result["resources"] = resources
	}

	// Policies
	policies, policyWarnings := transformAuthzPolicies(settings)
	if policies != nil {
		result["policies"] = policies
	}
	warnings = append(warnings, policyWarnings...)

	// Permissions
	if permissions := transformAuthzPermissions(settings); permissions != nil {
		result["permissions"] = permissions
	}

	if len(result) == 0 {
		return nil, warnings
	}
	return result, warnings
}

func transformAuthzScopes(settings map[string]any) []any {
	scopes, ok := settings["scopes"].([]any)
	if !ok || len(scopes) == 0 {
		return nil
	}

	var result []any
	for _, scopeRaw := range scopes {
		scope, ok := scopeRaw.(map[string]any)
		if !ok {
			continue
		}
		s := make(map[string]any)
		if v := getString(scope, "name"); v != "" {
			s["name"] = v
		}
		if v := getString(scope, "displayName"); v != "" {
			s["displayName"] = v
		}
		if v := getString(scope, "iconUri"); v != "" {
			s["iconUri"] = v
		}
		result = append(result, s)
	}
	return result
}

func transformAuthzResources(settings map[string]any) []any {
	resources, ok := settings["resources"].([]any)
	if !ok || len(resources) == 0 {
		return nil
	}

	var result []any
	for _, resRaw := range resources {
		res, ok := resRaw.(map[string]any)
		if !ok {
			continue
		}

		r := make(map[string]any)
		if v := getString(res, "name"); v != "" {
			// Skip the "Default Resource" created by Keycloak
			if v == "Default Resource" {
				continue
			}
			r["name"] = v
		}
		if v := getString(res, "displayName"); v != "" {
			r["displayName"] = v
		}
		if v := getString(res, "type"); v != "" {
			r["type"] = v
		}
		if uris := transformStringArray(getArray(res, "uris")); uris != nil {
			r["uris"] = uris
		}
		// Scopes in resources are objects with a "name" field — flatten to names
		if scopeArr := getArray(res, "scopes"); scopeArr != nil {
			var scopeNames []string
			for _, scopeRaw := range scopeArr {
				if scopeMap, ok := scopeRaw.(map[string]any); ok {
					if name := getString(scopeMap, "name"); name != "" {
						scopeNames = append(scopeNames, name)
					}
				}
			}
			if len(scopeNames) > 0 {
				r["scopes"] = scopeNames
			}
		}
		if _, ok := res["ownerManagedAccess"]; ok {
			r["ownerManagedAccess"] = getBool(res, "ownerManagedAccess", false)
		}
		if attrs, ok := res["attributes"].(map[string]any); ok && len(attrs) > 0 {
			r["attributes"] = attrs
		}

		result = append(result, r)
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

func transformAuthzPolicies(settings map[string]any) (map[string]any, []Warning) {
	policies, ok := settings["policies"].([]any)
	if !ok || len(policies) == 0 {
		return nil, nil
	}

	result := make(map[string]any)
	var warnings []Warning

	// Categorize policies by type
	var rolePolicies, userPolicies, groupPolicies, clientPolicies []any
	var timePolicies, regexPolicies, aggregatePolicies, jsPolicies []any

	for _, policyRaw := range policies {
		policy, ok := policyRaw.(map[string]any)
		if !ok {
			continue
		}

		policyType := getString(policy, "type")
		name := getString(policy, "name")

		// Skip Keycloak default policies
		if name == "Default Policy" || name == "Default Permission" {
			continue
		}

		switch policyType {
		case "role":
			rolePolicies = append(rolePolicies, transformRolePolicy(policy))
		case "user":
			userPolicies = append(userPolicies, transformUserPolicy(policy))
		case "group":
			groupPolicies = append(groupPolicies, transformGroupPolicy(policy))
		case "client":
			clientPolicies = append(clientPolicies, transformClientPolicy(policy))
		case "time":
			timePolicies = append(timePolicies, transformTimePolicy(policy))
		case "regex":
			regexPolicies = append(regexPolicies, transformRegexPolicy(policy))
		case "aggregate":
			aggregatePolicies = append(aggregatePolicies, transformAggregatePolicy(policy))
		case "js":
			jsPolicies = append(jsPolicies, transformJSPolicy(policy))
			result["allowJavaScriptPolicies"] = true
		case "resource", "scope":
			// These are permissions, not policies — handled separately
		default:
			warnings = append(warnings, Warning{
				Category: "unsupported",
				Field:    "authorizationSettings.policies",
				Message:  "Unknown policy type '" + policyType + "' for policy '" + name + "'",
			})
		}
	}

	if len(rolePolicies) > 0 {
		result["rolePolicies"] = rolePolicies
	}
	if len(userPolicies) > 0 {
		result["userPolicies"] = userPolicies
	}
	if len(groupPolicies) > 0 {
		result["groupPolicies"] = groupPolicies
	}
	if len(clientPolicies) > 0 {
		result["clientPolicies"] = clientPolicies
	}
	if len(timePolicies) > 0 {
		result["timePolicies"] = timePolicies
	}
	if len(regexPolicies) > 0 {
		result["regexPolicies"] = regexPolicies
	}
	if len(aggregatePolicies) > 0 {
		result["aggregatePolicies"] = aggregatePolicies
	}
	if len(jsPolicies) > 0 {
		result["javascriptPolicies"] = jsPolicies
	}

	if len(result) == 0 {
		return nil, warnings
	}
	return result, warnings
}

func transformRolePolicy(policy map[string]any) map[string]any {
	p := basePolicyFields(policy)

	// Roles from config
	if config, ok := policy["config"].(map[string]any); ok {
		if rolesJSON := getString(config, "roles"); rolesJSON != "" {
			// Keycloak stores roles as JSON string — we need to keep it for now
			// The actual parsing happens when the config is a proper structure
			p["fetchRoles"] = true
		}
	}

	// Roles from direct field (newer export format)
	if roles := getArray(policy, "roles"); roles != nil {
		var roleList []any
		for _, roleRaw := range roles {
			if roleMap, ok := roleRaw.(map[string]any); ok {
				r := make(map[string]any)
				if id := getString(roleMap, "id"); id != "" {
					r["name"] = id // Will need resolution — ID vs name
				}
				if _, ok := roleMap["required"]; ok {
					r["required"] = getBool(roleMap, "required", false)
				}
				roleList = append(roleList, r)
			}
		}
		if len(roleList) > 0 {
			p["roles"] = roleList
		}
	}

	return p
}

func transformUserPolicy(policy map[string]any) map[string]any {
	p := basePolicyFields(policy)
	if config, ok := policy["config"].(map[string]any); ok {
		if users := getString(config, "users"); users != "" {
			// Keycloak stores as JSON array string
			p["users"] = []string{users} // Placeholder — needs JSON parse
		}
	}
	if users := transformStringArray(getArray(policy, "users")); users != nil {
		p["users"] = users
	}
	return p
}

func transformGroupPolicy(policy map[string]any) map[string]any {
	p := basePolicyFields(policy)
	if config, ok := policy["config"].(map[string]any); ok {
		if groups := getString(config, "groups"); groups != "" {
			p["groups"] = []string{groups}
		}
		if claim := getString(config, "groupsClaim"); claim != "" {
			p["groupsClaim"] = claim
		}
	}
	if groups := transformStringArray(getArray(policy, "groups")); groups != nil {
		p["groups"] = groups
	}
	return p
}

func transformClientPolicy(policy map[string]any) map[string]any {
	p := basePolicyFields(policy)
	if config, ok := policy["config"].(map[string]any); ok {
		if clients := getString(config, "clients"); clients != "" {
			p["clients"] = []string{clients}
		}
	}
	if clients := transformStringArray(getArray(policy, "clients")); clients != nil {
		p["clients"] = clients
	}
	return p
}

func transformTimePolicy(policy map[string]any) map[string]any {
	p := basePolicyFields(policy)

	if config, ok := policy["config"].(map[string]any); ok {
		timeFields := []string{"notBefore", "notOnOrAfter", "dayMonth", "dayMonthEnd",
			"month", "monthEnd", "year", "yearEnd", "hour", "hourEnd", "minute", "minuteEnd"}
		for _, f := range timeFields {
			if v := getString(config, f); v != "" {
				if intVal := parseIntString(v); intVal > 0 {
					p[f] = intVal
				} else {
					p[f] = v
				}
			}
		}
	}

	return p
}

func transformRegexPolicy(policy map[string]any) map[string]any {
	p := basePolicyFields(policy)
	if config, ok := policy["config"].(map[string]any); ok {
		if v := getString(config, "targetClaim"); v != "" {
			p["targetClaim"] = v
		}
		if v := getString(config, "pattern"); v != "" {
			p["pattern"] = v
		}
	}
	return p
}

func transformAggregatePolicy(policy map[string]any) map[string]any {
	p := basePolicyFields(policy)
	if v := getString(policy, "decisionStrategy"); v != "" {
		p["decisionStrategy"] = v
	}
	if config, ok := policy["config"].(map[string]any); ok {
		if policies := getString(config, "applyPolicies"); policies != "" {
			p["policies"] = []string{policies}
		}
	}
	if policies := transformStringArray(getArray(policy, "policies")); policies != nil {
		p["policies"] = policies
	}
	return p
}

func transformJSPolicy(policy map[string]any) map[string]any {
	p := basePolicyFields(policy)
	if config, ok := policy["config"].(map[string]any); ok {
		if code := getString(config, "code"); code != "" {
			p["code"] = code
		}
	}
	return p
}

func basePolicyFields(policy map[string]any) map[string]any {
	p := make(map[string]any)
	if v := getString(policy, "name"); v != "" {
		p["name"] = v
	}
	if v := getString(policy, "description"); v != "" {
		p["description"] = v
	}
	if v := getString(policy, "logic"); v != "" && v != "POSITIVE" {
		p["logic"] = v
	}
	return p
}

func transformAuthzPermissions(settings map[string]any) map[string]any {
	policies, ok := settings["policies"].([]any)
	if !ok || len(policies) == 0 {
		return nil
	}

	result := make(map[string]any)
	var resourcePermissions, scopePermissions []any

	for _, policyRaw := range policies {
		policy, ok := policyRaw.(map[string]any)
		if !ok {
			continue
		}

		policyType := getString(policy, "type")
		name := getString(policy, "name")

		// Skip default permission
		if name == "Default Permission" {
			continue
		}

		switch policyType {
		case "resource":
			resourcePermissions = append(resourcePermissions, transformResourcePermission(policy))
		case "scope":
			scopePermissions = append(scopePermissions, transformScopePermission(policy))
		}
	}

	if len(resourcePermissions) > 0 {
		result["resourcePermissions"] = resourcePermissions
	}
	if len(scopePermissions) > 0 {
		result["scopePermissions"] = scopePermissions
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

func transformResourcePermission(policy map[string]any) map[string]any {
	p := make(map[string]any)
	if v := getString(policy, "name"); v != "" {
		p["name"] = v
	}
	if v := getString(policy, "description"); v != "" {
		p["description"] = v
	}
	if v := getString(policy, "decisionStrategy"); v != "" {
		p["decisionStrategy"] = v
	}
	if v := getString(policy, "resourceType"); v != "" {
		p["resourceType"] = v
	}

	if config, ok := policy["config"].(map[string]any); ok {
		if resources := getString(config, "resources"); resources != "" {
			p["resources"] = []string{resources}
		}
		if applyPolicies := getString(config, "applyPolicies"); applyPolicies != "" {
			p["policies"] = []string{applyPolicies}
		}
	}

	// Direct fields (newer export format)
	if resources := transformStringArray(getArray(policy, "resources")); resources != nil {
		p["resources"] = resources
	}
	if policies := transformStringArray(getArray(policy, "policies")); policies != nil {
		p["policies"] = policies
	}

	return p
}

func transformScopePermission(policy map[string]any) map[string]any {
	p := make(map[string]any)
	if v := getString(policy, "name"); v != "" {
		p["name"] = v
	}
	if v := getString(policy, "description"); v != "" {
		p["description"] = v
	}
	if v := getString(policy, "decisionStrategy"); v != "" {
		p["decisionStrategy"] = v
	}
	if v := getString(policy, "resourceType"); v != "" {
		p["resourceType"] = v
	}

	if config, ok := policy["config"].(map[string]any); ok {
		if scopes := getString(config, "scopes"); scopes != "" {
			p["scopes"] = []string{scopes}
		}
		if resources := getString(config, "resources"); resources != "" {
			p["resources"] = []string{resources}
		}
		if applyPolicies := getString(config, "applyPolicies"); applyPolicies != "" {
			p["policies"] = []string{applyPolicies}
		}
	}

	// Direct fields
	if scopes := transformStringArray(getArray(policy, "scopes")); scopes != nil {
		p["scopes"] = scopes
	}
	if resources := transformStringArray(getArray(policy, "resources")); resources != nil {
		p["resources"] = resources
	}
	if policies := transformStringArray(getArray(policy, "policies")); policies != nil {
		p["policies"] = policies
	}

	return p
}
