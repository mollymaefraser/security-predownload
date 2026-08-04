package types

import (
	"encoding/json"
	"testing"
)

func TestGitHubRepo_UnmarshalsGitHubAPIFieldNames(t *testing.T) {
	// test that the GitHubRepo struct correctly unmarshals JSON with GitHub API field names into the struct fields.
	raw := `{"stargazers_count": 123, "forks_count": 45, "pushed_at": "2026-07-01T00:00:00Z", "unrelated_field": true}`

	// unmarshal the raw JSON into a GitHubRepo struct and check that the fields are correctly populated.
	var repo GitHubRepo
	if err := json.Unmarshal([]byte(raw), &repo); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// check that the fields are correctly populated.
	want := GitHubRepo{StargazersCount: 123, ForksCount: 45, PushedAt: "2026-07-01T00:00:00Z"}
	if repo != want {
		t.Errorf("got %+v, want %+v", repo, want)
	}
}
