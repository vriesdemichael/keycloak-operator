package transform

import (
	"testing"
)

func TestParsePasswordPolicy_Empty(t *testing.T) {
	result, warnings := ParsePasswordPolicy("")
	if result != nil {
		t.Errorf("expected nil result for empty string, got %v", result)
	}
	if warnings != nil {
		t.Errorf("expected nil warnings for empty string, got %v", warnings)
	}
}

func TestParsePasswordPolicy_SingleIntPolicy(t *testing.T) {
	result, warnings := ParsePasswordPolicy("length(8)")
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got %v", warnings)
	}
	if result["length"] != 8 {
		t.Errorf("length = %v, want 8", result["length"])
	}
}

func TestParsePasswordPolicy_SingleBoolPolicy(t *testing.T) {
	result, warnings := ParsePasswordPolicy("notUsername")
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got %v", warnings)
	}
	if result["notUsername"] != true {
		t.Errorf("notUsername = %v, want true", result["notUsername"])
	}
}

func TestParsePasswordPolicy_BoolPolicyWithParentheses(t *testing.T) {
	// Some versions export bool policies as "notUsername(1)"
	result, warnings := ParsePasswordPolicy("notUsername(1)")
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got %v", warnings)
	}
	if result["notUsername"] != true {
		t.Errorf("notUsername = %v, want true", result["notUsername"])
	}
}

func TestParsePasswordPolicy_RegexPattern(t *testing.T) {
	result, warnings := ParsePasswordPolicy("regexPattern(^[a-zA-Z0-9]+$)")
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got %v", warnings)
	}
	if result["regexPattern"] != "^[a-zA-Z0-9]+$" {
		t.Errorf("regexPattern = %v, want ^[a-zA-Z0-9]+$", result["regexPattern"])
	}
}

func TestParsePasswordPolicy_Complex(t *testing.T) {
	policy := "hashIterations(27500) and length(12) and upperCase(1) and lowerCase(1) and digits(1) and specialChars(1) and notUsername and notEmail and passwordHistory(5) and forceExpiredPasswordChange(90)"
	result, warnings := ParsePasswordPolicy(policy)

	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got %v", warnings)
	}

	expected := map[string]any{
		"hashIterations":             27500,
		"length":                     12,
		"upperCase":                  1,
		"lowerCase":                  1,
		"digits":                     1,
		"specialChars":               1,
		"notUsername":                true,
		"notEmail":                   true,
		"passwordHistory":            5,
		"forceExpiredPasswordChange": 90,
	}

	for k, want := range expected {
		got, ok := result[k]
		if !ok {
			t.Errorf("missing key %q", k)
			continue
		}
		if got != want {
			t.Errorf("%s = %v (%T), want %v (%T)", k, got, got, want, want)
		}
	}
}

func TestParsePasswordPolicy_UnknownPolicy(t *testing.T) {
	result, warnings := ParsePasswordPolicy("length(8) and customPolicy(42)")

	if result["length"] != 8 {
		t.Errorf("length = %v, want 8", result["length"])
	}

	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(warnings))
	}
	if warnings[0].Category != "unsupported" {
		t.Errorf("warning category = %q, want %q", warnings[0].Category, "unsupported")
	}
	if warnings[0].Field != "passwordPolicy" {
		t.Errorf("warning field = %q, want %q", warnings[0].Field, "passwordPolicy")
	}
}

func TestParsePasswordPolicy_UnknownBarePolicy(t *testing.T) {
	_, warnings := ParsePasswordPolicy("unknownPolicy")
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(warnings))
	}
	if warnings[0].Category != "unsupported" {
		t.Errorf("warning category = %q, want %q", warnings[0].Category, "unsupported")
	}
}

func TestParsePasswordPolicy_AllKnown(t *testing.T) {
	// Test each known policy individually to ensure complete coverage
	tests := []struct {
		input string
		key   string
		value any
	}{
		{"length(8)", "length", 8},
		{"upperCase(2)", "upperCase", 2},
		{"lowerCase(3)", "lowerCase", 3},
		{"digits(1)", "digits", 1},
		{"specialChars(1)", "specialChars", 1},
		{"hashIterations(210000)", "hashIterations", 210000},
		{"passwordHistory(5)", "passwordHistory", 5},
		{"forceExpiredPasswordChange(90)", "forceExpiredPasswordChange", 90},
		{"maxLength(64)", "maxLength", 64},
		{"notEmail", "notEmail", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, warnings := ParsePasswordPolicy(tt.input)
			if len(warnings) != 0 {
				t.Errorf("unexpected warnings: %v", warnings)
			}
			if result[tt.key] != tt.value {
				t.Errorf("%s = %v (%T), want %v (%T)", tt.key, result[tt.key], result[tt.key], tt.value, tt.value)
			}
		})
	}
}

func TestParsePasswordPolicy_MediumFixturePolicy(t *testing.T) {
	// Matches the medium-realm.json fixture
	policy := "hashIterations(27500) and length(12) and upperCase(1) and lowerCase(1) and digits(1) and notUsername"
	result, warnings := ParsePasswordPolicy(policy)

	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if result["hashIterations"] != 27500 {
		t.Errorf("hashIterations = %v, want 27500", result["hashIterations"])
	}
	if result["length"] != 12 {
		t.Errorf("length = %v, want 12", result["length"])
	}
	if result["notUsername"] != true {
		t.Errorf("notUsername = %v, want true", result["notUsername"])
	}
}
