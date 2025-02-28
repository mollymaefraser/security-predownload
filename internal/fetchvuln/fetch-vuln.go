package fetchvuln

import (
	"encoding/json"
	"net/http"
	"strings"
)

const osvAPI = "https://api.osv.dev/v1/query"

func checkVulnerabilities(packageName string) (int, error) {
	data := `{"package": {"name": "` + packageName + `"}}`
	resp, err := http.Post(osvAPI, "application/json", strings.NewReader(data))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	vulnCount := len(result["vulns"].([]interface{}))

	return vulnCount, nil
}
