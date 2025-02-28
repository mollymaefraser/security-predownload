package assessrisk

import (
	"fmt"
	"risk-check/internal/fetchmeta"
	"risk-check/internal/fetchvuln"
)

func AssessRisk(packageName string) {
	repoData, err := fetchmeta.GetGitHubRepoData("owner", packageName)
	if err != nil {
		fmt.Println("There was an error")
	}

	vulnCount, err := fetchvuln.CheckVulnerabilities(packageName)
	if err != nil {
		fmt.Println("There was an error")
	}

	score := 100

	if repoData.StargazersCount < 50 {
		score -= 20
	}
	if vulnCount > 0 {
		score -= vulnCount * 10
	}

	fmt.Printf("Risk Score for %s: %d/100\n", packageName, score)
}
