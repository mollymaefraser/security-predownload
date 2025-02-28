package assessrisk

import (
	"fmt"
	"errors"
	"github.com/mollymaefraser/security-predownload/internal/fetchmeta"
	"github.com/mollymaefraser/security-predownload/internal/fetchvuln"
)

func assessRisk(packageName string) {
	repoData := fetchmeta.getGitHubRepoData("owner", packageName)
	vulnCount := fetchvuln.checkVulnerabilities(packageName)

	}
	
	if(repoData.StargazersCount < 50) {
		score -= 20
	}
	if(vulnCount > 0) {
		score -= vulnCount * 10
	}

	fmt.Printf("Risk Score for %s: %d/100\n", packageName, score)
}