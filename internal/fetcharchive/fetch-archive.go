package fetcharchive

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// maxArchiveBytes caps how much we'll write to disk for a single download,
// so a malicious or oversized repo can't exhaust local storage before the
// archive ever reaches the sandbox (this has been the cause of many incidents).
const maxArchiveBytes = 200 * 1024 * 1024 // 200MB

// Download fetches a GitHub repository's default-branch source as a tarball
// into a fresh temp directory. It returns the archive path and a cleanup
// function that removes the temp directory; callers should defer cleanup().
// If the download fails, cleanup is called before returning, to keep things safe.
func Download(owner, repo string) (path string, cleanup func(), err error) {
	// Make temp dir
	dir, err := os.MkdirTemp("", "security-predownload-*")
	if err != nil {
		return "", nil, fmt.Errorf("creating temp dir: %w", err)
	}

	// create cleanup that removes temp dir
	cleanup = func() { os.RemoveAll(dir) }

	// download the tarball from GitHub
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/tarball", owner, repo)
	resp, err := http.Get(url)
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("downloading %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		cleanup()
		return "", nil, fmt.Errorf("downloading %s: unexpected status %s", url, resp.Status)
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
	limited := io.LimitReader(resp.Body, maxArchiveBytes+1)
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
