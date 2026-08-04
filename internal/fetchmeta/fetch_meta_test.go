package fetchmeta

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func withTestServer(t *testing.T, handler http.HandlerFunc) {
	// create a test server with the provided handler and ensure it is closed after the test.
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	original := apiBaseURL
	apiBaseURL = server.URL
	t.Cleanup(func() { apiBaseURL = original })
}

func TestGetGitHubRepoData_Success(t *testing.T) {
	// a successful request should return the expected GitHubRepo data.
	withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/owner/repo" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Write([]byte(`{"stargazers_count": 42, "forks_count": 7, "pushed_at": "2026-01-01T00:00:00Z"}`))
	})

	// call GetGitHubRepoData and check that it returns the expected data.
	data, err := GetGitHubRepoData("owner", "repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.StargazersCount != 42 || data.ForksCount != 7 || data.PushedAt != "2026-01-01T00:00:00Z" {
		t.Errorf("unexpected data: %+v", data)
	}
}

func TestGetGitHubRepoData_NotFound(t *testing.T) {
	// a 404 response should result in an error.
	withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "Not Found"}`))
	})

	// A 404 body still unmarshals cleanly into GitHubRepo (zero-value
	// fields), so without a status check this would silently look like a
	// 0-star repo instead of erroring.
	if _, err := GetGitHubRepoData("owner", "does-not-exist"); err == nil {
		t.Error("expected an error for a 404 response, got nil")
	}
}

func TestGetGitHubRepoData_MalformedJSON(t *testing.T) {
	// a malformed JSON response should result in an error.
	withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not json`))
	})

	// a malformed JSON body still unmarshals cleanly into GitHubRepo (zero-value
	// fields), so without a status check this would silently look like a
	// 0-star repo instead of erroring.
	if _, err := GetGitHubRepoData("owner", "repo"); err == nil {
		t.Error("expected an error for malformed JSON, got nil")
	}
}
