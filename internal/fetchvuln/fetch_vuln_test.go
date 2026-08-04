package fetchvuln

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func withTestServer(t *testing.T, handler http.HandlerFunc) {
	// create a test server with the provided handler and ensure it is closed after the test.
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	original := osvAPI
	osvAPI = server.URL
	t.Cleanup(func() { osvAPI = original })
}

func TestCheckVulnerabilities_CountsVulns(t *testing.T) {
	// a response with two vulnerabilities should return a count of 2.
	withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"vulns": [{"id": "GHSA-1"}, {"id": "GHSA-2"}]}`))
	})

	// call CheckVulnerabilities and check that it returns the expected count.
	count, err := CheckVulnerabilities("some-package")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 2 {
		t.Errorf("got %d, want 2", count)
	}
}

func TestCheckVulnerabilities_NoVulnsField(t *testing.T) {
	// a response with no "vulns" field should return a count of 0.
	withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	})

	// call CheckVulnerabilities and check that it returns the expected count.
	count, err := CheckVulnerabilities("some-package")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("got %d, want 0", count)
	}
}

// A package name containing a double quote used to be spliced directly into
// a hand-built JSON string, producing invalid JSON (or, with a crafted name,
// letting the caller inject extra JSON fields into the request). Confirms
// the request body is now built via json.Marshal instead.
func TestCheckVulnerabilities_PackageNameWithQuoteIsSentSafely(t *testing.T) {
	// a package name containing a double quote should be sent safely in the request body.
	malicious := `evil"}, "extra": {"field`

	// capture the request body sent to the test server and check that it is valid JSON and contains the expected package name.
	var gotBody []byte
	withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		var err error
		gotBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("reading request body: %v", err)
		}
		w.Write([]byte(`{"vulns": []}`))
	})

	// call CheckVulnerabilities with the malicious package name and check that it does not return an error.
	if _, err := CheckVulnerabilities(malicious); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// unmarshal the request body and check that it contains the expected package name.
	var decoded osvQuery
	if err := json.Unmarshal(gotBody, &decoded); err != nil {
		t.Fatalf("request body is not valid JSON: %v\nbody: %s", err, gotBody)
	}
	if decoded.Package.Name != malicious {
		t.Errorf("package name got mangled: got %q, want %q", decoded.Package.Name, malicious)
	}
}
