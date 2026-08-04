package fetchmeta

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"risk-check/internal/types"
)

// apiBaseURL is overridden in tests to point at an httptest.Server.
var apiBaseURL = "https://api.github.com"

// GetGitHubRepoData fetches repository data from GitHub.
func GetGitHubRepoData(owner, repo string) (*types.GitHubRepo, error) {
	url := fmt.Sprintf("%s/repos/%s/%s", apiBaseURL, owner, repo)

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: unexpected status %s", url, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var data types.GitHubRepo
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	return &data, nil
}
