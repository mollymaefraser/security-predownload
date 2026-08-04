package fetchmeta

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"risk-check/internal/githubauth"
	"risk-check/internal/types"
)

// apiBaseURL is overridden in tests to point at an httptest.Server.
var apiBaseURL = "https://api.github.com"

// GetGitHubRepoData fetches repository data from GitHub. Set GITHUB_TOKEN
// to raise the rate limit from 60 to 5,000 requests/hour.
func GetGitHubRepoData(owner, repo string) (*types.GitHubRepo, error) {
	url := fmt.Sprintf("%s/repos/%s/%s", apiBaseURL, owner, repo)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	githubauth.SetAuthHeader(req)

	resp, err := http.DefaultClient.Do(req)
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
