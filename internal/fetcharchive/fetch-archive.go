package fetcharchive

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"risk-check/internal/githubauth"
)

// maxArchiveBytes caps how much we'll write to disk for a single download,
// so a malicious or oversized repo can't exhaust local storage before the
// archive ever reaches the sandbox. Var (not const) so tests can shrink it.
var maxArchiveBytes int64 = 200 * 1024 * 1024 // 200MB

// apiBaseURL is overridden in tests to point at an httptest.Server.
var apiBaseURL = "https://api.github.com"

// Download fetches a GitHub repository's default-branch source as a tarball
// into a fresh temp directory. It returns the archive path and a cleanup
// function that removes the temp directory; callers should defer cleanup().
// If the download fails, cleanup is called before returning, to keep things safe.
// Set GITHUB_TOKEN to raise the rate limit from 60 to 5,000 requests/hour.
func Download(owner, repo string) (path string, cleanup func(), err error) {
	// Make temp dir
	dir, err := os.MkdirTemp("", "security-predownload-*")
	if err != nil {
		return "", nil, fmt.Errorf("creating temp dir: %w", err)
	}

	// create cleanup that removes temp dir
	cleanup = func() { os.RemoveAll(dir) }

	// download the tarball from GitHub
	url := fmt.Sprintf("%s/repos/%s/%s/tarball", apiBaseURL, owner, repo)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("building request for %s: %w", url, err)
	}
	githubauth.SetAuthHeader(req)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("downloading %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		cleanup()
		return "", nil, fmt.Errorf("downloading %s: unexpected status %s", url, resp.Status)
	}

	// Bail out before writing anything to disk if the server told us the
	// size up front. Not authoritative (absent on chunked responses, and a
	// server could lie), so the LimitReader below still enforces the real cap.
	if resp.ContentLength > maxArchiveBytes {
		cleanup()
		return "", nil, fmt.Errorf("archive size %d exceeds %d byte limit", resp.ContentLength, maxArchiveBytes)
	}

	archivePath := filepath.Join(dir, "archive.tar.gz")
	// create archive file
	f, err := os.Create(archivePath)
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("creating archive file: %w", err)
	}
	defer f.Close()

	// limit the number of bytes we write to disk, so a malicious or oversized
	// repo can't exhaust local storage before the archive ever reaches the sandbox.
	limited := io.LimitReader(resp.Body, maxArchiveBytes+1) // check in advance of size
	n, err := io.Copy(f, limited)
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("writing archive: %w", err)
	}
	if n > maxArchiveBytes {
		cleanup()
		return "", nil, fmt.Errorf("archive exceeds %d byte limit", maxArchiveBytes)
	}

	return archivePath, cleanup, nil
}
