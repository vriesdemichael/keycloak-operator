package transform

import (
	"testing"
)

func TestTransformAuthorizationSettings_Nil(t *testing.T) {
	result, warnings := TransformAuthorizationSettings(nil)
	if result != nil {
		t.Errorf("expected nil result for nil input, got %v", result)
	}
	if warnings != nil {
		t.Errorf("expected nil warnings for nil input, got %v", warnings)
	}
}

func TestTransformAuthorizationSettings_Empty(t *testing.T) {
	result, warnings := TransformAuthorizationSettings(map[string]any{})
	if result != nil {
		t.Errorf("expected nil result for empty input, got %v", result)
	}
	if warnings != nil {
		t.Errorf("expected nil warnings for empty input, got %v", warnings)
	}
}

func TestTransformAuthorizationSettings_TopLevel(t *testing.T) {
	input := map[string]any{
		"policyEnforcementMode":         "ENFORCING",
		"decisionStrategy":              "UNANIMOUS",
		"allowRemoteResourceManagement": true,
	}

	result, warnings := TransformAuthorizationSettings(input)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got %v", warnings)
	}

	if v, ok := result["policyEnforcementMode"]; !ok || v != "ENFORCING" {
		t.Errorf("policyEnforcementMode = %v, want ENFORCING", v)
	}
	if v, ok := result["decisionStrategy"]; !ok || v != "UNANIMOUS" {
		t.Errorf("decisionStrategy = %v, want UNANIMOUS", v)
	}
	if v, ok := result["allowRemoteResourceManagement"]; !ok || v != true {
		t.Errorf("allowRemoteResourceManagement = %v, want true", v)
	}
}

func TestTransformAuthzScopes(t *testing.T) {
	settings := map[string]any{
		"scopes": []any{
			map[string]any{
				"name":        "read",
				"displayName": "Read Access",
				"iconUri":     "http://example.com/read.png",
			},
			map[string]any{
				"name": "write",
			},
		},
	}

	result := transformAuthzScopes(settings)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 scopes, got %d", len(result))
	}

	scope0, ok := result[0].(map[string]any)
	if !ok {
		t.Fatal("expected scope to be map[string]any")
	}
	if scope0["name"] != "read" {
		t.Errorf("scope[0].name = %v, want read", scope0["name"])
	}
	if scope0["displayName"] != "Read Access" {
		t.Errorf("scope[0].displayName = %v, want Read Access", scope0["displayName"])
	}
	if scope0["iconUri"] != "http://example.com/read.png" {
		t.Errorf("scope[0].iconUri = %v, want http://example.com/read.png", scope0["iconUri"])
	}

	scope1, ok := result[1].(map[string]any)
	if !ok {
		t.Fatal("expected scope to be map[string]any")
	}
	if scope1["name"] != "write" {
		t.Errorf("scope[1].name = %v, want write", scope1["name"])
	}
	if _, exists := scope1["displayName"]; exists {
		t.Errorf("scope[1] should not have displayName")
	}
	if _, exists := scope1["iconUri"]; exists {
		t.Errorf("scope[1] should not have iconUri")
	}
}

func TestTransformAuthzScopes_Empty(t *testing.T) {
	// nil settings (no scopes key)
	result := transformAuthzScopes(map[string]any{})
	if result != nil {
		t.Errorf("expected nil for missing scopes, got %v", result)
	}

	// empty scopes array
	result = transformAuthzScopes(map[string]any{"scopes": []any{}})
	if result != nil {
		t.Errorf("expected nil for empty scopes, got %v", result)
	}

	// scopes is not an array
	result = transformAuthzScopes(map[string]any{"scopes": "not-an-array"})
	if result != nil {
		t.Errorf("expected nil for non-array scopes, got %v", result)
	}
}

func TestTransformAuthzResources_Basic(t *testing.T) {
	settings := map[string]any{
		"resources": []any{
			map[string]any{
				"name": "my-resource",
				"type": "urn:resource:type",
				"uris": []any{"/api/*"},
				"scopes": []any{
					map[string]any{"name": "read"},
				},
				"displayName":        "My Resource",
				"ownerManagedAccess": true,
				"attributes": map[string]any{
					"key1": "val1",
				},
			},
		},
	}

	result := transformAuthzResources(settings)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(result))
	}

	res, ok := result[0].(map[string]any)
	if !ok {
		t.Fatal("expected resource to be map[string]any")
	}
	if res["name"] != "my-resource" {
		t.Errorf("name = %v, want my-resource", res["name"])
	}
	if res["type"] != "urn:resource:type" {
		t.Errorf("type = %v, want urn:resource:type", res["type"])
	}
	if res["displayName"] != "My Resource" {
		t.Errorf("displayName = %v, want My Resource", res["displayName"])
	}
	if res["ownerManagedAccess"] != true {
		t.Errorf("ownerManagedAccess = %v, want true", res["ownerManagedAccess"])
	}
	attrs, ok := res["attributes"].(map[string]any)
	if !ok {
		t.Fatal("expected attributes to be map[string]any")
	}
	if attrs["key1"] != "val1" {
		t.Errorf("attributes.key1 = %v, want val1", attrs["key1"])
	}

	uris, ok := res["uris"].([]string)
	if !ok {
		t.Fatal("expected uris to be []string")
	}
	if len(uris) != 1 || uris[0] != "/api/*" {
		t.Errorf("uris = %v, want [/api/*]", uris)
	}

	scopes, ok := res["scopes"].([]string)
	if !ok {
		t.Fatal("expected scopes to be []string")
	}
	if len(scopes) != 1 || scopes[0] != "read" {
		t.Errorf("scopes = %v, want [read]", scopes)
	}
}

func TestTransformAuthzResources_SkipsDefaultResource(t *testing.T) {
	settings := map[string]any{
		"resources": []any{
			map[string]any{
				"name": "Default Resource",
				"uris": []any{"/*"},
			},
			map[string]any{
				"name": "kept-resource",
			},
		},
	}

	result := transformAuthzResources(settings)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 resource (Default Resource skipped), got %d", len(result))
	}
	res := result[0].(map[string]any)
	if res["name"] != "kept-resource" {
		t.Errorf("name = %v, want kept-resource", res["name"])
	}
}

func TestTransformAuthzResources_ScopeFlattening(t *testing.T) {
	settings := map[string]any{
		"resources": []any{
			map[string]any{
				"name": "resource-with-scopes",
				"scopes": []any{
					map[string]any{"name": "read"},
					map[string]any{"name": "write"},
					map[string]any{"name": "delete"},
				},
			},
		},
	}

	result := transformAuthzResources(settings)
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	res := result[0].(map[string]any)
	scopes, ok := res["scopes"].([]string)
	if !ok {
		t.Fatal("expected scopes to be []string")
	}
	if len(scopes) != 3 {
		t.Fatalf("expected 3 scopes, got %d", len(scopes))
	}
	expected := []string{"read", "write", "delete"}
	for i, s := range scopes {
		if s != expected[i] {
			t.Errorf("scopes[%d] = %v, want %v", i, s, expected[i])
		}
	}
}

func TestTransformAuthzResources_AllDefaultsSkipped(t *testing.T) {
	settings := map[string]any{
		"resources": []any{
			map[string]any{
				"name": "Default Resource",
			},
		},
	}

	result := transformAuthzResources(settings)
	if result != nil {
		t.Errorf("expected nil result when all resources are default, got %v", result)
	}
}

func TestTransformAuthzPolicies_RolePolicy(t *testing.T) {
	settings := map[string]any{
		"policies": []any{
			map[string]any{
				"name":        "role-policy",
				"type":        "role",
				"description": "A role policy",
				"logic":       "POSITIVE",
				"roles": []any{
					map[string]any{
						"id":       "admin-role",
						"required": true,
					},
					map[string]any{
						"id": "user-role",
					},
				},
			},
		},
	}

	result, warnings := transformAuthzPolicies(settings)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got %v", warnings)
	}

	rolePolicies, ok := result["rolePolicies"].([]any)
	if !ok {
		t.Fatal("expected rolePolicies to be []any")
	}
	if len(rolePolicies) != 1 {
		t.Fatalf("expected 1 role policy, got %d", len(rolePolicies))
	}

	rp := rolePolicies[0].(map[string]any)
	if rp["name"] != "role-policy" {
		t.Errorf("name = %v, want role-policy", rp["name"])
	}
	if rp["description"] != "A role policy" {
		t.Errorf("description = %v, want A role policy", rp["description"])
	}
	// POSITIVE logic should be skipped
	if _, exists := rp["logic"]; exists {
		t.Errorf("POSITIVE logic should not be included, but found %v", rp["logic"])
	}

	roles, ok := rp["roles"].([]any)
	if !ok {
		t.Fatal("expected roles to be []any")
	}
	if len(roles) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(roles))
	}

	role0 := roles[0].(map[string]any)
	if role0["name"] != "admin-role" {
		t.Errorf("role[0].name = %v, want admin-role", role0["name"])
	}
	if role0["required"] != true {
		t.Errorf("role[0].required = %v, want true", role0["required"])
	}
}

func TestTransformAuthzPolicies_RolePolicy_FromConfig(t *testing.T) {
	settings := map[string]any{
		"policies": []any{
			map[string]any{
				"name": "config-role-policy",
				"type": "role",
				"config": map[string]any{
					"roles": `[{"id":"admin"}]`,
				},
			},
		},
	}

	result, _ := transformAuthzPolicies(settings)
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	rolePolicies := result["rolePolicies"].([]any)
	rp := rolePolicies[0].(map[string]any)
	if rp["fetchRoles"] != true {
		t.Errorf("fetchRoles = %v, want true", rp["fetchRoles"])
	}
}

func TestTransformAuthzPolicies_UserPolicy(t *testing.T) {
	settings := map[string]any{
		"policies": []any{
			map[string]any{
				"name":  "user-policy",
				"type":  "user",
				"users": []any{"user1", "user2"},
			},
		},
	}

	result, warnings := transformAuthzPolicies(settings)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got %v", warnings)
	}

	userPolicies, ok := result["userPolicies"].([]any)
	if !ok {
		t.Fatal("expected userPolicies to be []any")
	}
	if len(userPolicies) != 1 {
		t.Fatalf("expected 1 user policy, got %d", len(userPolicies))
	}

	up := userPolicies[0].(map[string]any)
	if up["name"] != "user-policy" {
		t.Errorf("name = %v, want user-policy", up["name"])
	}
	users, ok := up["users"].([]string)
	if !ok {
		t.Fatal("expected users to be []string")
	}
	if len(users) != 2 || users[0] != "user1" || users[1] != "user2" {
		t.Errorf("users = %v, want [user1 user2]", users)
	}
}

func TestTransformAuthzPolicies_UserPolicy_FromConfig(t *testing.T) {
	settings := map[string]any{
		"policies": []any{
			map[string]any{
				"name": "config-user-policy",
				"type": "user",
				"config": map[string]any{
					"users": `["uid-1","uid-2"]`,
				},
			},
		},
	}

	result, _ := transformAuthzPolicies(settings)
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	userPolicies := result["userPolicies"].([]any)
	up := userPolicies[0].(map[string]any)
	users, ok := up["users"].([]string)
	if !ok {
		t.Fatalf("expected users to be []string, got %T", up["users"])
	}
	if len(users) != 1 {
		t.Errorf("expected 1 user placeholder, got %d", len(users))
	}
}

func TestTransformAuthzPolicies_GroupPolicy(t *testing.T) {
	settings := map[string]any{
		"policies": []any{
			map[string]any{
				"name":   "group-policy",
				"type":   "group",
				"groups": []any{"group-a", "group-b"},
				"config": map[string]any{
					"groupsClaim": "groups-claim",
				},
			},
		},
	}

	result, warnings := transformAuthzPolicies(settings)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got %v", warnings)
	}

	groupPolicies, ok := result["groupPolicies"].([]any)
	if !ok {
		t.Fatal("expected groupPolicies to be []any")
	}

	gp := groupPolicies[0].(map[string]any)
	if gp["name"] != "group-policy" {
		t.Errorf("name = %v, want group-policy", gp["name"])
	}
	if gp["groupsClaim"] != "groups-claim" {
		t.Errorf("groupsClaim = %v, want groups-claim", gp["groupsClaim"])
	}
	groups, ok := gp["groups"].([]string)
	if !ok {
		t.Fatal("expected groups to be []string")
	}
	if len(groups) != 2 || groups[0] != "group-a" || groups[1] != "group-b" {
		t.Errorf("groups = %v, want [group-a group-b]", groups)
	}
}

func TestTransformAuthzPolicies_ClientPolicy(t *testing.T) {
	settings := map[string]any{
		"policies": []any{
			map[string]any{
				"name":    "client-policy",
				"type":    "client",
				"clients": []any{"client-a"},
			},
		},
	}

	result, warnings := transformAuthzPolicies(settings)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got %v", warnings)
	}

	clientPolicies, ok := result["clientPolicies"].([]any)
	if !ok {
		t.Fatal("expected clientPolicies to be []any")
	}

	cp := clientPolicies[0].(map[string]any)
	if cp["name"] != "client-policy" {
		t.Errorf("name = %v, want client-policy", cp["name"])
	}
	clients, ok := cp["clients"].([]string)
	if !ok {
		t.Fatal("expected clients to be []string")
	}
	if len(clients) != 1 || clients[0] != "client-a" {
		t.Errorf("clients = %v, want [client-a]", clients)
	}
}

func TestTransformAuthzPolicies_TimePolicy(t *testing.T) {
	settings := map[string]any{
		"policies": []any{
			map[string]any{
				"name": "time-policy",
				"type": "time",
				"config": map[string]any{
					"notBefore":    "Jan 1 2024",
					"notOnOrAfter": "Dec 31 2025",
					"dayMonth":     "15",
					"dayMonthEnd":  "28",
					"month":        "6",
					"monthEnd":     "12",
					"year":         "2024",
					"yearEnd":      "2025",
					"hour":         "9",
					"hourEnd":      "17",
					"minute":       "0",
					"minuteEnd":    "59",
				},
			},
		},
	}

	result, warnings := transformAuthzPolicies(settings)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got %v", warnings)
	}

	timePolicies, ok := result["timePolicies"].([]any)
	if !ok {
		t.Fatal("expected timePolicies to be []any")
	}

	tp := timePolicies[0].(map[string]any)
	if tp["name"] != "time-policy" {
		t.Errorf("name = %v, want time-policy", tp["name"])
	}
	// Non-numeric strings stay as strings
	if tp["notBefore"] != "Jan 1 2024" {
		t.Errorf("notBefore = %v, want Jan 1 2024", tp["notBefore"])
	}
	if tp["notOnOrAfter"] != "Dec 31 2025" {
		t.Errorf("notOnOrAfter = %v, want Dec 31 2025", tp["notOnOrAfter"])
	}
	// Numeric strings get parsed to int
	if tp["dayMonth"] != 15 {
		t.Errorf("dayMonth = %v, want 15", tp["dayMonth"])
	}
	if tp["dayMonthEnd"] != 28 {
		t.Errorf("dayMonthEnd = %v, want 28", tp["dayMonthEnd"])
	}
	if tp["month"] != 6 {
		t.Errorf("month = %v, want 6", tp["month"])
	}
	if tp["monthEnd"] != 12 {
		t.Errorf("monthEnd = %v, want 12", tp["monthEnd"])
	}
	if tp["year"] != 2024 {
		t.Errorf("year = %v, want 2024", tp["year"])
	}
	if tp["yearEnd"] != 2025 {
		t.Errorf("yearEnd = %v, want 2025", tp["yearEnd"])
	}
	if tp["hour"] != 9 {
		t.Errorf("hour = %v, want 9", tp["hour"])
	}
	if tp["hourEnd"] != 17 {
		t.Errorf("hourEnd = %v, want 17", tp["hourEnd"])
	}
}

func TestTransformAuthzPolicies_RegexPolicy(t *testing.T) {
	settings := map[string]any{
		"policies": []any{
			map[string]any{
				"name": "regex-policy",
				"type": "regex",
				"config": map[string]any{
					"targetClaim": "email",
					"pattern":     ".*@example\\.com$",
				},
			},
		},
	}

	result, warnings := transformAuthzPolicies(settings)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got %v", warnings)
	}

	regexPolicies, ok := result["regexPolicies"].([]any)
	if !ok {
		t.Fatal("expected regexPolicies to be []any")
	}

	rp := regexPolicies[0].(map[string]any)
	if rp["name"] != "regex-policy" {
		t.Errorf("name = %v, want regex-policy", rp["name"])
	}
	if rp["targetClaim"] != "email" {
		t.Errorf("targetClaim = %v, want email", rp["targetClaim"])
	}
	if rp["pattern"] != ".*@example\\.com$" {
		t.Errorf("pattern = %v, want .*@example\\.com$", rp["pattern"])
	}
}

func TestTransformAuthzPolicies_AggregatePolicy(t *testing.T) {
	settings := map[string]any{
		"policies": []any{
			map[string]any{
				"name":             "aggregate-policy",
				"type":             "aggregate",
				"decisionStrategy": "AFFIRMATIVE",
				"policies":         []any{"policy-a", "policy-b"},
			},
		},
	}

	result, warnings := transformAuthzPolicies(settings)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got %v", warnings)
	}

	aggregatePolicies, ok := result["aggregatePolicies"].([]any)
	if !ok {
		t.Fatal("expected aggregatePolicies to be []any")
	}

	ap := aggregatePolicies[0].(map[string]any)
	if ap["name"] != "aggregate-policy" {
		t.Errorf("name = %v, want aggregate-policy", ap["name"])
	}
	if ap["decisionStrategy"] != "AFFIRMATIVE" {
		t.Errorf("decisionStrategy = %v, want AFFIRMATIVE", ap["decisionStrategy"])
	}
	policies, ok := ap["policies"].([]string)
	if !ok {
		t.Fatal("expected policies to be []string")
	}
	if len(policies) != 2 || policies[0] != "policy-a" || policies[1] != "policy-b" {
		t.Errorf("policies = %v, want [policy-a policy-b]", policies)
	}
}

func TestTransformAuthzPolicies_JSPolicy(t *testing.T) {
	settings := map[string]any{
		"policies": []any{
			map[string]any{
				"name": "js-policy",
				"type": "js",
				"config": map[string]any{
					"code": "var context = $evaluation.getContext();",
				},
			},
		},
	}

	result, warnings := transformAuthzPolicies(settings)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got %v", warnings)
	}

	// allowJavaScriptPolicies flag should be set
	if v, ok := result["allowJavaScriptPolicies"]; !ok || v != true {
		t.Errorf("allowJavaScriptPolicies = %v, want true", v)
	}

	jsPolicies, ok := result["javascriptPolicies"].([]any)
	if !ok {
		t.Fatal("expected javascriptPolicies to be []any")
	}

	jp := jsPolicies[0].(map[string]any)
	if jp["name"] != "js-policy" {
		t.Errorf("name = %v, want js-policy", jp["name"])
	}
	if jp["code"] != "var context = $evaluation.getContext();" {
		t.Errorf("code = %v, want var context = $evaluation.getContext();", jp["code"])
	}
}

func TestTransformAuthzPolicies_SkipsDefaults(t *testing.T) {
	settings := map[string]any{
		"policies": []any{
			map[string]any{
				"name": "Default Policy",
				"type": "role",
			},
			map[string]any{
				"name": "Default Permission",
				"type": "resource",
			},
		},
	}

	result, warnings := transformAuthzPolicies(settings)
	if result != nil {
		t.Errorf("expected nil result when all policies are defaults, got %v", result)
	}
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got %v", warnings)
	}
}

func TestTransformAuthzPolicies_UnknownType(t *testing.T) {
	settings := map[string]any{
		"policies": []any{
			map[string]any{
				"name": "mysterious-policy",
				"type": "custom-unknown",
			},
		},
	}

	result, warnings := transformAuthzPolicies(settings)
	if result != nil {
		t.Errorf("expected nil result for unknown-only policies, got %v", result)
	}
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(warnings))
	}

	w := warnings[0]
	if w.Category != "unsupported" {
		t.Errorf("warning category = %v, want unsupported", w.Category)
	}
	if w.Field != "authorizationSettings.policies" {
		t.Errorf("warning field = %v, want authorizationSettings.policies", w.Field)
	}
	if w.Message == "" {
		t.Errorf("expected non-empty warning message")
	}
}

func TestTransformAuthzPolicies_SkipsPermissionTypes(t *testing.T) {
	settings := map[string]any{
		"policies": []any{
			map[string]any{
				"name": "resource-perm",
				"type": "resource",
			},
			map[string]any{
				"name": "scope-perm",
				"type": "scope",
			},
		},
	}

	result, warnings := transformAuthzPolicies(settings)
	if result != nil {
		t.Errorf("expected nil result for permission-only types, got %v", result)
	}
	if len(warnings) != 0 {
		t.Errorf("expected no warnings for permission types, got %v", warnings)
	}
}

func TestTransformAuthzPermissions_ResourceAndScope(t *testing.T) {
	settings := map[string]any{
		"policies": []any{
			map[string]any{
				"name":             "res-perm",
				"type":             "resource",
				"description":      "Resource permission",
				"decisionStrategy": "UNANIMOUS",
				"resourceType":     "urn:type",
				"resources":        []any{"resource-a"},
				"policies":         []any{"policy-1"},
			},
			map[string]any{
				"name":             "scope-perm",
				"type":             "scope",
				"description":      "Scope permission",
				"decisionStrategy": "AFFIRMATIVE",
				"scopes":           []any{"read", "write"},
				"resources":        []any{"resource-b"},
				"policies":         []any{"policy-2"},
			},
		},
	}

	result := transformAuthzPermissions(settings)
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// Resource permissions
	resPerms, ok := result["resourcePermissions"].([]any)
	if !ok {
		t.Fatal("expected resourcePermissions to be []any")
	}
	if len(resPerms) != 1 {
		t.Fatalf("expected 1 resource permission, got %d", len(resPerms))
	}

	rp := resPerms[0].(map[string]any)
	if rp["name"] != "res-perm" {
		t.Errorf("name = %v, want res-perm", rp["name"])
	}
	if rp["description"] != "Resource permission" {
		t.Errorf("description = %v, want Resource permission", rp["description"])
	}
	if rp["decisionStrategy"] != "UNANIMOUS" {
		t.Errorf("decisionStrategy = %v, want UNANIMOUS", rp["decisionStrategy"])
	}
	if rp["resourceType"] != "urn:type" {
		t.Errorf("resourceType = %v, want urn:type", rp["resourceType"])
	}
	resources, ok := rp["resources"].([]string)
	if !ok {
		t.Fatal("expected resources to be []string")
	}
	if len(resources) != 1 || resources[0] != "resource-a" {
		t.Errorf("resources = %v, want [resource-a]", resources)
	}
	policies, ok := rp["policies"].([]string)
	if !ok {
		t.Fatal("expected policies to be []string")
	}
	if len(policies) != 1 || policies[0] != "policy-1" {
		t.Errorf("policies = %v, want [policy-1]", policies)
	}

	// Scope permissions
	scopePerms, ok := result["scopePermissions"].([]any)
	if !ok {
		t.Fatal("expected scopePermissions to be []any")
	}
	if len(scopePerms) != 1 {
		t.Fatalf("expected 1 scope permission, got %d", len(scopePerms))
	}

	sp := scopePerms[0].(map[string]any)
	if sp["name"] != "scope-perm" {
		t.Errorf("name = %v, want scope-perm", sp["name"])
	}
	scopes, ok := sp["scopes"].([]string)
	if !ok {
		t.Fatal("expected scopes to be []string")
	}
	if len(scopes) != 2 || scopes[0] != "read" || scopes[1] != "write" {
		t.Errorf("scopes = %v, want [read write]", scopes)
	}
}

func TestTransformAuthzPermissions_SkipsDefaultPermission(t *testing.T) {
	settings := map[string]any{
		"policies": []any{
			map[string]any{
				"name": "Default Permission",
				"type": "resource",
			},
		},
	}

	result := transformAuthzPermissions(settings)
	if result != nil {
		t.Errorf("expected nil result when only Default Permission present, got %v", result)
	}
}

func TestTransformAuthzPermissions_FromConfig(t *testing.T) {
	settings := map[string]any{
		"policies": []any{
			map[string]any{
				"name": "config-res-perm",
				"type": "resource",
				"config": map[string]any{
					"resources":     `["res-1"]`,
					"applyPolicies": `["pol-1"]`,
				},
			},
			map[string]any{
				"name": "config-scope-perm",
				"type": "scope",
				"config": map[string]any{
					"scopes":        `["read"]`,
					"resources":     `["res-2"]`,
					"applyPolicies": `["pol-2"]`,
				},
			},
		},
	}

	result := transformAuthzPermissions(settings)
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	resPerms := result["resourcePermissions"].([]any)
	rp := resPerms[0].(map[string]any)
	resFromConfig, ok := rp["resources"].([]string)
	if !ok {
		t.Fatalf("expected resources from config to be []string, got %T", rp["resources"])
	}
	if len(resFromConfig) != 1 {
		t.Errorf("expected 1 resource from config, got %d", len(resFromConfig))
	}

	scopePerms := result["scopePermissions"].([]any)
	sp := scopePerms[0].(map[string]any)
	scopesFromConfig, ok := sp["scopes"].([]string)
	if !ok {
		t.Fatalf("expected scopes from config to be []string, got %T", sp["scopes"])
	}
	if len(scopesFromConfig) != 1 {
		t.Errorf("expected 1 scope from config, got %d", len(scopesFromConfig))
	}
}

func TestBasePolicyFields_SkipsPositiveLogic(t *testing.T) {
	// POSITIVE logic should be omitted
	policy := map[string]any{
		"name":        "test-policy",
		"description": "a description",
		"logic":       "POSITIVE",
	}
	result := basePolicyFields(policy)
	if result["name"] != "test-policy" {
		t.Errorf("name = %v, want test-policy", result["name"])
	}
	if result["description"] != "a description" {
		t.Errorf("description = %v, want a description", result["description"])
	}
	if _, exists := result["logic"]; exists {
		t.Errorf("POSITIVE logic should not be included")
	}

	// NEGATIVE logic should be preserved
	policy["logic"] = "NEGATIVE"
	result = basePolicyFields(policy)
	if result["logic"] != "NEGATIVE" {
		t.Errorf("logic = %v, want NEGATIVE", result["logic"])
	}
}

func TestBasePolicyFields_EmptyLogic(t *testing.T) {
	policy := map[string]any{
		"name": "no-logic-policy",
	}
	result := basePolicyFields(policy)
	if _, exists := result["logic"]; exists {
		t.Errorf("empty logic should not be included")
	}
}

func TestTransformAuthorizationSettings_Full(t *testing.T) {
	input := map[string]any{
		"policyEnforcementMode":         "ENFORCING",
		"decisionStrategy":              "UNANIMOUS",
		"allowRemoteResourceManagement": false,
		"scopes": []any{
			map[string]any{"name": "read"},
			map[string]any{"name": "write"},
		},
		"resources": []any{
			map[string]any{
				"name": "Default Resource",
				"uris": []any{"/*"},
			},
			map[string]any{
				"name": "api-resource",
				"type": "urn:api",
				"uris": []any{"/api/*"},
				"scopes": []any{
					map[string]any{"name": "read"},
				},
			},
		},
		"policies": []any{
			map[string]any{
				"name": "Default Policy",
				"type": "role",
			},
			map[string]any{
				"name": "Default Permission",
				"type": "resource",
			},
			map[string]any{
				"name":  "admin-role-policy",
				"type":  "role",
				"logic": "NEGATIVE",
				"roles": []any{
					map[string]any{"id": "admin"},
				},
			},
			map[string]any{
				"name": "api-resource-permission",
				"type": "resource",
				"config": map[string]any{
					"resources":     `["api-resource"]`,
					"applyPolicies": `["admin-role-policy"]`,
				},
			},
			map[string]any{
				"name":   "read-scope-permission",
				"type":   "scope",
				"scopes": []any{"read"},
			},
			map[string]any{
				"name": "unknown-type-policy",
				"type": "magic",
			},
		},
	}

	result, warnings := TransformAuthorizationSettings(input)
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// Top-level settings
	if result["policyEnforcementMode"] != "ENFORCING" {
		t.Errorf("policyEnforcementMode = %v, want ENFORCING", result["policyEnforcementMode"])
	}
	if result["decisionStrategy"] != "UNANIMOUS" {
		t.Errorf("decisionStrategy = %v, want UNANIMOUS", result["decisionStrategy"])
	}
	if result["allowRemoteResourceManagement"] != false {
		t.Errorf("allowRemoteResourceManagement = %v, want false", result["allowRemoteResourceManagement"])
	}

	// Scopes
	scopes, ok := result["scopes"].([]any)
	if !ok {
		t.Fatal("expected scopes to be []any")
	}
	if len(scopes) != 2 {
		t.Errorf("expected 2 scopes, got %d", len(scopes))
	}

	// Resources (Default Resource should be skipped)
	resources, ok := result["resources"].([]any)
	if !ok {
		t.Fatal("expected resources to be []any")
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource (Default Resource skipped), got %d", len(resources))
	}
	res := resources[0].(map[string]any)
	if res["name"] != "api-resource" {
		t.Errorf("resource name = %v, want api-resource", res["name"])
	}

	// Policies (Default Policy skipped, resource/scope types handled as permissions)
	policies, ok := result["policies"].(map[string]any)
	if !ok {
		t.Fatal("expected policies to be map[string]any")
	}
	rolePolicies, ok := policies["rolePolicies"].([]any)
	if !ok {
		t.Fatal("expected rolePolicies in policies")
	}
	if len(rolePolicies) != 1 {
		t.Errorf("expected 1 role policy, got %d", len(rolePolicies))
	}
	rp := rolePolicies[0].(map[string]any)
	if rp["logic"] != "NEGATIVE" {
		t.Errorf("role policy logic = %v, want NEGATIVE", rp["logic"])
	}

	// Permissions
	permissions, ok := result["permissions"].(map[string]any)
	if !ok {
		t.Fatal("expected permissions to be map[string]any")
	}
	resPerms, ok := permissions["resourcePermissions"].([]any)
	if !ok {
		t.Fatal("expected resourcePermissions in permissions")
	}
	if len(resPerms) != 1 {
		t.Errorf("expected 1 resource permission, got %d", len(resPerms))
	}
	scopePerms, ok := permissions["scopePermissions"].([]any)
	if !ok {
		t.Fatal("expected scopePermissions in permissions")
	}
	if len(scopePerms) != 1 {
		t.Errorf("expected 1 scope permission, got %d", len(scopePerms))
	}

	// Warnings
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning for unknown type, got %d", len(warnings))
	}
	if warnings[0].Category != "unsupported" {
		t.Errorf("warning category = %v, want unsupported", warnings[0].Category)
	}
}

func TestTransformAuthzPermissions_Empty(t *testing.T) {
	// No policies key
	result := transformAuthzPermissions(map[string]any{})
	if result != nil {
		t.Errorf("expected nil for missing policies, got %v", result)
	}

	// Empty policies
	result = transformAuthzPermissions(map[string]any{"policies": []any{}})
	if result != nil {
		t.Errorf("expected nil for empty policies, got %v", result)
	}

	// Only non-permission types
	result = transformAuthzPermissions(map[string]any{
		"policies": []any{
			map[string]any{"name": "role-pol", "type": "role"},
		},
	})
	if result != nil {
		t.Errorf("expected nil when no permission types present, got %v", result)
	}
}

func TestTransformAuthzPolicies_Empty(t *testing.T) {
	result, warnings := transformAuthzPolicies(map[string]any{})
	if result != nil {
		t.Errorf("expected nil for missing policies, got %v", result)
	}
	if warnings != nil {
		t.Errorf("expected nil warnings, got %v", warnings)
	}

	result, warnings = transformAuthzPolicies(map[string]any{"policies": []any{}})
	if result != nil {
		t.Errorf("expected nil for empty policies, got %v", result)
	}
	if warnings != nil {
		t.Errorf("expected nil warnings, got %v", warnings)
	}
}

func TestTransformAuthzResources_Empty(t *testing.T) {
	result := transformAuthzResources(map[string]any{})
	if result != nil {
		t.Errorf("expected nil for missing resources, got %v", result)
	}

	result = transformAuthzResources(map[string]any{"resources": []any{}})
	if result != nil {
		t.Errorf("expected nil for empty resources, got %v", result)
	}
}

func TestTransformTimePolicy_IntParsing(t *testing.T) {
	// Verify that parseIntString returns 0 for non-numeric strings (stored as string)
	// and positive ints for numeric strings (stored as int)
	policy := map[string]any{
		"name": "time-int-test",
		"config": map[string]any{
			"hour":      "8",
			"notBefore": "before-date",
			"minute":    "0",
		},
	}

	result := transformTimePolicy(policy)
	if result["hour"] != 8 {
		t.Errorf("hour = %v (type %T), want 8", result["hour"], result["hour"])
	}
	// "0" parses to int 0, which is not > 0, so stays as string
	if result["minute"] != "0" {
		t.Errorf("minute = %v (type %T), want '0' (string)", result["minute"], result["minute"])
	}
	// Non-numeric string stays as string
	if result["notBefore"] != "before-date" {
		t.Errorf("notBefore = %v, want before-date", result["notBefore"])
	}
}

func TestTransformGroupPolicy_FromConfig(t *testing.T) {
	policy := map[string]any{
		"name": "config-group-policy",
		"config": map[string]any{
			"groups":      `[{"id":"group-1"}]`,
			"groupsClaim": "my-groups",
		},
	}

	result := transformGroupPolicy(policy)
	if result["name"] != "config-group-policy" {
		t.Errorf("name = %v, want config-group-policy", result["name"])
	}
	if result["groupsClaim"] != "my-groups" {
		t.Errorf("groupsClaim = %v, want my-groups", result["groupsClaim"])
	}
	groups, ok := result["groups"].([]string)
	if !ok {
		t.Fatalf("expected groups to be []string, got %T", result["groups"])
	}
	if len(groups) != 1 {
		t.Errorf("expected 1 group placeholder, got %d", len(groups))
	}
}

func TestTransformClientPolicy_FromConfig(t *testing.T) {
	policy := map[string]any{
		"name": "config-client-policy",
		"config": map[string]any{
			"clients": `["client-1","client-2"]`,
		},
	}

	result := transformClientPolicy(policy)
	if result["name"] != "config-client-policy" {
		t.Errorf("name = %v, want config-client-policy", result["name"])
	}
	clients, ok := result["clients"].([]string)
	if !ok {
		t.Fatalf("expected clients to be []string, got %T", result["clients"])
	}
	if len(clients) != 1 {
		t.Errorf("expected 1 client placeholder, got %d", len(clients))
	}
}

func TestTransformAggregatePolicy_FromConfig(t *testing.T) {
	policy := map[string]any{
		"name":             "config-agg-policy",
		"decisionStrategy": "CONSENSUS",
		"config": map[string]any{
			"applyPolicies": `["pol-1","pol-2"]`,
		},
	}

	result := transformAggregatePolicy(policy)
	if result["name"] != "config-agg-policy" {
		t.Errorf("name = %v, want config-agg-policy", result["name"])
	}
	if result["decisionStrategy"] != "CONSENSUS" {
		t.Errorf("decisionStrategy = %v, want CONSENSUS", result["decisionStrategy"])
	}
	policies, ok := result["policies"].([]string)
	if !ok {
		t.Fatalf("expected policies to be []string, got %T", result["policies"])
	}
	if len(policies) != 1 {
		t.Errorf("expected 1 policy placeholder, got %d", len(policies))
	}
}

func TestTransformJSPolicy_EmptyCode(t *testing.T) {
	policy := map[string]any{
		"name":   "empty-js",
		"config": map[string]any{},
	}

	result := transformJSPolicy(policy)
	if result["name"] != "empty-js" {
		t.Errorf("name = %v, want empty-js", result["name"])
	}
	if _, exists := result["code"]; exists {
		t.Errorf("empty code should not be set")
	}
}

func TestTransformRegexPolicy_NoConfig(t *testing.T) {
	policy := map[string]any{
		"name": "no-config-regex",
	}

	result := transformRegexPolicy(policy)
	if result["name"] != "no-config-regex" {
		t.Errorf("name = %v, want no-config-regex", result["name"])
	}
	if _, exists := result["targetClaim"]; exists {
		t.Errorf("targetClaim should not be set without config")
	}
	if _, exists := result["pattern"]; exists {
		t.Errorf("pattern should not be set without config")
	}
}

func TestTransformAuthorizationSettings_OnlyAllowRemoteResourceManagement(t *testing.T) {
	// Verify allowRemoteResourceManagement false is preserved
	input := map[string]any{
		"allowRemoteResourceManagement": false,
	}

	result, _ := TransformAuthorizationSettings(input)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if v, ok := result["allowRemoteResourceManagement"]; !ok || v != false {
		t.Errorf("allowRemoteResourceManagement = %v, want false", v)
	}
}

func TestTransformAuthzResources_NonMapEntries(t *testing.T) {
	settings := map[string]any{
		"resources": []any{
			"not-a-map",
			42,
			map[string]any{"name": "valid"},
		},
	}

	result := transformAuthzResources(settings)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result) != 1 {
		t.Errorf("expected 1 resource (non-map entries skipped), got %d", len(result))
	}
}

func TestTransformAuthzScopes_NonMapEntries(t *testing.T) {
	settings := map[string]any{
		"scopes": []any{
			"not-a-map",
			map[string]any{"name": "valid-scope"},
		},
	}

	result := transformAuthzScopes(settings)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result) != 1 {
		t.Errorf("expected 1 scope (non-map entries skipped), got %d", len(result))
	}
}

func TestTransformAuthzPolicies_NonMapEntries(t *testing.T) {
	settings := map[string]any{
		"policies": []any{
			"not-a-map",
			map[string]any{
				"name": "valid-policy",
				"type": "role",
			},
		},
	}

	result, _ := transformAuthzPolicies(settings)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	rolePolicies := result["rolePolicies"].([]any)
	if len(rolePolicies) != 1 {
		t.Errorf("expected 1 role policy, got %d", len(rolePolicies))
	}
}
