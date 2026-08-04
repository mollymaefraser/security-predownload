// Package githubauth adds GitHub API authentication to outgoing requests.
package githubauth

import (
	"net/http"
	"os"
)

// SetAuthHeader adds a GitHub API Authorization header to req if the
// GITHUB_TOKEN environment variable is set. Without it, GitHub's REST API
// caps unauthenticated requests at 60/hour per IP; with it, 5,000/hour.
func SetAuthHeader(req *http.Request) {
	// if GITHUB_TOKEN is set, add an Authorization header to the request.
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}
