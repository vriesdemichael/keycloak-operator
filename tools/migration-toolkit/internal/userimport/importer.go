package userimport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ImportMode controls how Keycloak handles users that already exist.
type ImportMode string

const (
	ImportModeSkip      ImportMode = "SKIP"
	ImportModeFail      ImportMode = "FAIL"
	ImportModeOverwrite ImportMode = "OVERWRITE"
)

// ImportOptions controls the import execution.
type ImportOptions struct {
	Target    *ResolvedTarget
	Users     []map[string]any
	Mode      ImportMode
	BatchSize int
	DryRun    bool
}

// ImportResult summarises what happened across all batches.
type ImportResult struct {
	TotalUsers   int
	Added        int
	Skipped      int
	Errors       int
	Batches      int
	ErrorDetails []string
}

// ImportUsers executes the Partial Import for all users in batches.
func ImportUsers(ctx context.Context, opts ImportOptions) (*ImportResult, error) {
	result := &ImportResult{TotalUsers: len(opts.Users)}

	if opts.BatchSize <= 0 {
		opts.BatchSize = 500
	}

	batches := chunk(opts.Users, opts.BatchSize)
	result.Batches = len(batches)

	if opts.DryRun {
		fmt.Printf("Dry run: would import %d users in %d batches of up to %d\n",
			result.TotalUsers, result.Batches, opts.BatchSize)
		fmt.Printf("  Server:    %s\n", opts.Target.ServerURL)
		fmt.Printf("  Realm:     %s\n", opts.Target.Realm)
		fmt.Printf("  Mode:      %s\n", opts.Mode)
		fmt.Printf("  Username:  %s\n", opts.Target.Username)
		return result, nil
	}

	token, expiry, err := authenticate(ctx, opts.Target)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	for i, batch := range batches {
		fmt.Printf("Importing batch %d/%d (%d users)...\n", i+1, len(batches), len(batch))

		// Refresh token if within 30s of expiry
		if time.Until(expiry) < 30*time.Second {
			token, expiry, err = authenticate(ctx, opts.Target)
			if err != nil {
				return nil, fmt.Errorf("token refresh failed before batch %d: %w", i+1, err)
			}
		}

		batchResult, err := importBatch(ctx, opts.Target, token, batch, opts.Mode)
		if err != nil {
			return nil, fmt.Errorf("batch %d/%d failed: %w", i+1, len(batches), err)
		}

		result.Added += batchResult.Added
		result.Skipped += batchResult.Skipped
		result.Errors += batchResult.Errors
		result.ErrorDetails = append(result.ErrorDetails, batchResult.ErrorDetails...)

		if batchResult.Errors > 0 {
			return result, fmt.Errorf(
				"batch %d/%d had %d error(s):\n%s",
				i+1, len(batches), batchResult.Errors,
				strings.Join(batchResult.ErrorDetails, "\n"),
			)
		}
	}

	return result, nil
}

// authenticate obtains an admin access token from Keycloak using the password grant.
// Returns the token string and its expiry time.
func authenticate(ctx context.Context, target *ResolvedTarget) (string, time.Time, error) {
	tokenURL := fmt.Sprintf("%s/realms/master/protocol/openid-connect/token", target.ServerURL)

	form := url.Values{}
	form.Set("client_id", "admin-cli")
	form.Set("grant_type", "password")
	form.Set("username", target.Username)
	form.Set("password", target.Password)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("building token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("token request returned %d: %s", resp.StatusCode, body)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", time.Time{}, fmt.Errorf("parsing token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", time.Time{}, fmt.Errorf("token response missing access_token")
	}

	expiry := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	return tokenResp.AccessToken, expiry, nil
}

type batchResult struct {
	Added        int
	Skipped      int
	Errors       int
	ErrorDetails []string
}

func importBatch(ctx context.Context, target *ResolvedTarget, token string, users []map[string]any, mode ImportMode) (*batchResult, error) {
	importURL := fmt.Sprintf("%s/admin/realms/%s/partialImport",
		target.ServerURL, url.PathEscape(target.Realm))

	payload := map[string]any{
		"users":             users,
		"ifResourceExists": string(mode),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshalling payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, importURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building import request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("import request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("HTTP 403 Forbidden — ensure the admin user has realm management permissions for realm %q", target.Realm)
	}
	if resp.StatusCode == http.StatusConflict {
		// FAIL mode returns 409 on first conflict — extract details
		return nil, fmt.Errorf("HTTP 409 Conflict (mode=FAIL): %s", respBody)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("partial import returned %d: %s", resp.StatusCode, respBody)
	}

	// Parse the Keycloak Partial Import response
	var importResp struct {
		Added   int `json:"added"`
		Skipped int `json:"skipped"`
		Errors  int `json:"errors"`
		Results []struct {
			Action      string `json:"action"`
			ResourceType string `json:"resourceType"`
			ResourceName string `json:"resourceName"`
			ID          string `json:"id"`
		} `json:"results"`
	}
	if err := json.Unmarshal(respBody, &importResp); err != nil {
		return nil, fmt.Errorf("parsing import response: %w — body: %s", err, respBody)
	}

	result := &batchResult{
		Added:   importResp.Added,
		Skipped: importResp.Skipped,
		Errors:  importResp.Errors,
	}

	// Collect error details for reporting
	for _, r := range importResp.Results {
		if r.Action == "ERROR" || r.Action == "FAILED" {
			result.ErrorDetails = append(result.ErrorDetails,
				fmt.Sprintf("  %s %q: %s", r.ResourceType, r.ResourceName, r.Action))
		}
	}

	return result, nil
}

// chunk splits a slice of users into sub-slices of at most size n.
func chunk(users []map[string]any, n int) [][]map[string]any {
	if len(users) == 0 {
		return nil
	}
	var chunks [][]map[string]any
	for i := 0; i < len(users); i += n {
		end := i + n
		if end > len(users) {
			end = len(users)
		}
		chunks = append(chunks, users[i:end])
	}
	return chunks
}
