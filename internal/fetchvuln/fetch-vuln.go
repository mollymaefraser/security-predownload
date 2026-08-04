package fetchvuln

import (
	"bytes"
	"encoding/json"
	"net/http"
)

// osvAPI is overridden in tests to point at an httptest.Server.
var osvAPI = "https://api.osv.dev/v1/query"

type osvQuery struct {
	Package osvPackage `json:"package"`
}

type osvPackage struct {
	Name string `json:"name"`
}

// CheckVulnerabilities looks up known vulnerabilities for packageName
// against the OSV.dev database and returns how many were found.
func CheckVulnerabilities(packageName string) (int, error) {
	body, err := json.Marshal(osvQuery{Package: osvPackage{Name: packageName}})
	if err != nil {
		return 0, err
	}

	resp, err := http.Post(osvAPI, "application/json", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	// decode the JSON response into a map
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, err
	}

	// Ensure "vulns" exists before type assertion
	vulns, ok := result["vulns"]
	if !ok || vulns == nil {
		return 0, nil
	}

	// type assert the vulns to a slice of interfaces
	vulnList, ok := vulns.([]interface{})
	if !ok {
		return 0, nil
	}

	return len(vulnList), nil
}
