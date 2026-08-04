package githubauth

import (
	"net/http"
	"testing"
)

func TestSetAuthHeader_WithToken(t *testing.T) {
	// set fake env var for GITHUB_TOKEN and check that SetAuthHeader adds the correct Authorization header to the request.
	t.Setenv("GITHUB_TOKEN", "test-token-123")

	// create a new HTTP request and call SetAuthHeader on it.
	req, _ := http.NewRequest(http.MethodGet, "https://api.github.com/repos/owner/repo", nil)
	SetAuthHeader(req)

	// check that the Authorization header was set correctly.
	if got := req.Header.Get("Authorization"); got != "Bearer test-token-123" {
		t.Errorf("got Authorization header %q, want %q", got, "Bearer test-token-123")
	}
}

func TestSetAuthHeader_WithoutToken(t *testing.T) {
	// clear GITHUB_TOKEN and check that SetAuthHeader does not add an Authorization header to the request.
	t.Setenv("GITHUB_TOKEN", "")

	// create a new HTTP request and call SetAuthHeader on it.
	req, _ := http.NewRequest(http.MethodGet, "https://api.github.com/repos/owner/repo", nil)
	SetAuthHeader(req)

	// check that the Authorization header was not set.
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("expected no Authorization header, got %q", got)
	}
}
