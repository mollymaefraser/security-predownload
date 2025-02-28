package assessrisk

import (
	"fmt"
	"risk-check/internal/fetchmeta"
)

// AssessRisk evaluates the risk score and provides reasons
func AssessRisk(owner, packageName string) {
	fmt.Printf("Assessing risk for package: %s\n\n", packageName)

	// Try to fetch the GitHub data
	data, err := fetchmeta.GetGitHubRepoData(owner, packageName)
	if err != nil {
		fmt.Println("⚠️ Error searching GitHub:", err)
		return
	}

	// Continue with the risk assessment
	vulnCount := 0 // Simulate vulnerability check (you can integrate it as needed)
	score := 100
	reasons := []string{}

	// Deduct points for vulnerabilities
	if vulnCount > 0 {
		deduction := vulnCount * 10
		reasons = append(reasons, fmt.Sprintf("-%d: Found %d vulnerabilities", deduction, vulnCount))
		score -= deduction
	}

	// Deduct points for popularity (stars)
	if data.StargazersCount < 100 {
		deduction := 20
		reasons = append(reasons, fmt.Sprintf("-%d: Low popularity (%d stars)", deduction, data.StargazersCount))
		score -= deduction
	}

	if score < 100 {
		// Print risk breakdown
		fmt.Println("📊 **Risk Breakdown**")
		for _, reason := range reasons {
			fmt.Println(reason)
		}
	}

	// Print final risk score
	fmt.Printf("\n🔎 Final Risk Score for %s: **%d/100**\n", packageName, score)
}
