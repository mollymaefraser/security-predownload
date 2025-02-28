package types

type GitHubRepo struct {
	StargazersCount int    `json:"stargazers_count"`
	ForksCount      int    `json:"forks_count"`
	PushedAt        string `json:"pushed_at"`
}
