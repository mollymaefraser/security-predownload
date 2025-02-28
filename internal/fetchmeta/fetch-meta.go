package fetchmeta

import (
	"encoding/json"
	"fmt"
	"net/http"

	"risk-check/internal/types"
)

const githubAPI = "https://api.github.com/repos/"

func GetGitHubRepoData(owner, repo string) (*types.GitHubRepo, error) {
	url := fmt.Sprintf("%s%s/%s", githubAPI, owner, repo)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var repoData types.GitHubRepo
	err = json.NewDecoder(resp.Body).Decode(&repoData)
	if err != nil {
		return nil, err
	}

	return &repoData, nil
}
