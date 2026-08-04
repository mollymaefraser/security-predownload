package fetchmeta

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"risk-check/internal/types"
)

// GetGitHubRepoData fetches repository data from GitHub
func GetGitHubRepoData(owner, repo string) (*types.GitHubRepo, error) {
	// construct the GitHub API URL for the repository
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo)
	fmt.Println(url)

	// make the HTTP GET request to the GitHub API
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// decode into struct
	var data types.GitHubRepo
	err = json.Unmarshal(body, &data)
	if err != nil {
		return nil, err
	}

	return &data, nil
}
