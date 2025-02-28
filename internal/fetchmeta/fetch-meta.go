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
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo)
	fmt.Println(url)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Decode into struct
	var data types.GitHubRepo
	err = json.Unmarshal(body, &data)
	if err != nil {
		return nil, err
	}

	return &data, nil
}
