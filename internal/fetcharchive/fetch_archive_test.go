package fetcharchive

import (
	"net/http"
	"net/http/httptest"
	"os"
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

func TestDownload_Success(t *testing.T) {
	// a successful download should return the path to the downloaded file and a cleanup function that removes it.
	const body = "fake tarball contents"
	withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/owner/repo/tarball" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Write([]byte(body))
	})

	// call Download and check that it returns the expected contents and that the cleanup function removes the file.
	path, cleanup, err := Download("owner", "repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cleanup()

	// read the downloaded file and check its contents
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading downloaded archive: %v", err)
	}
	if string(got) != body {
		t.Errorf("got %q, want %q", got, body)
	}

	// call the cleanup function and check that the file was removed
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected cleanup to remove %s, stat err: %v", path, err)
	}
}

func TestDownload_SendsBearerTokenWhenSet(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "test-token-123")

	var gotAuth string
	withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Write([]byte("fake tarball contents"))
	})

	_, cleanup, err := Download("owner", "repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cleanup()

	if gotAuth != "Bearer test-token-123" {
		t.Errorf("got Authorization header %q, want %q", gotAuth, "Bearer test-token-123")
	}
}

func TestDownload_NonOKStatusCleansUpAndErrors(t *testing.T) {
	// a non-200 response should result in an error and the cleanup function should remove any partially downloaded file.
	withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	// cleanup is nil on the error path — Download itself calls it before
	// returning, so the test must not call it again.
	_, cleanup, err := Download("owner", "does-not-exist")
	if err == nil {
		t.Fatal("expected an error for a 404 response, got nil")
	}
	if cleanup != nil {
		t.Error("expected a nil cleanup func on the error path")
	}
}

func TestDownload_ExceedsSizeLimit(t *testing.T) {
	// a download that exceeds the maxArchiveBytes limit should return an error and the cleanup function should be nil.
	original := maxArchiveBytes
	maxArchiveBytes = 10
	t.Cleanup(func() { maxArchiveBytes = original })

	withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 100))
	})

	// cleanup is nil on the error path — Download itself calls it before
	// returning, so the test must not call it again.
	_, cleanup, err := Download("owner", "huge-repo")
	if err == nil {
		cleanup()
		t.Fatal("expected an error for an oversized archive, got nil")
	}
	if cleanup != nil {
		t.Error("expected a nil cleanup func on the error path")
	}
}
