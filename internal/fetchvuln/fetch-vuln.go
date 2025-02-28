package fetchvuln

import (
	"encoding/json"
	"net/http"
	"strings"
)

const osvAPI = "https://api.osv.dev/v1/query"

func CheckVulnerabilities(packageName string) (int, error) {
	data := `{"package": {"name": "` + packageName + `"}}`
	resp, err := http.Post(osvAPI, "application/json", strings.NewReader(data))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return 0, err
	}

	// Ensure "vulns" exists before type assertion
	vulns, ok := result["vulns"]
	if !ok || vulns == nil {
		return 0, nil
	}

	vulnList, ok := vulns.([]interface{})
	if !ok {
		return 0, nil
	}

	return len(vulnList), nil
}
