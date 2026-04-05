// Package userimport provides user loading, credential resolution, and
// Partial Import execution for the keycloak-migrate import-users command.
package userimport

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// LoadResult holds the result of loading and validating a users.json file.
type LoadResult struct {
	Users     []map[string]any
	FileAge   time.Duration
	UserCount int
}

// LoadUsersFile reads users.json produced by keycloak-migrate transform,
// validates the contents, and enforces the maximum file age.
// Pass maxAge=0 to skip the age check.
func LoadUsersFile(path string, maxAge time.Duration) (*LoadResult, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot access %q: %w", path, err)
	}

	fileAge := time.Since(info.ModTime())

	if maxAge > 0 && fileAge > maxAge {
		return nil, fmt.Errorf(
			"%q is %.0f hours old (max: %.0f hours). Re-run 'keycloak-migrate transform' "+
				"or pass --max-age 0 to skip this check",
			path,
			fileAge.Hours(),
			maxAge.Hours(),
		)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %q: %w", path, err)
	}

	// Must be a JSON array
	var raw json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing %q: invalid JSON: %w", path, err)
	}
	if len(raw) == 0 || raw[0] != '[' {
		return nil, fmt.Errorf("%q must contain a JSON array (got object or scalar)", path)
	}

	var users []map[string]any
	if err := json.Unmarshal(data, &users); err != nil {
		return nil, fmt.Errorf("parsing %q as user array: %w", path, err)
	}

	// Validate each user has a non-empty username string
	for i, u := range users {
		v, ok := u["username"]
		if !ok {
			return nil, fmt.Errorf("user at index %d in %q is missing required field \"username\"", i, path)
		}
		s, isStr := v.(string)
		if !isStr || s == "" {
			return nil, fmt.Errorf("user at index %d in %q has an empty or non-string \"username\" field", i, path)
		}
	}

	return &LoadResult{
		Users:     users,
		FileAge:   fileAge,
		UserCount: len(users),
	}, nil
}
