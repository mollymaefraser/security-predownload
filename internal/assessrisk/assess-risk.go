package assessrisk

import (
	"context"
	"fmt"
	"strings"

	"risk-check/internal/fetcharchive"
	"risk-check/internal/fetchmeta"
	"risk-check/internal/vulnscan"
)

const (
	scaDeductionPerHit = 5
	maxVulnDeduction   = 40 // caps the scan's contribution so a large dependency tree can't zero out the score on its own
)

var sastSeverityDeduction = map[string]int{
	"CRITICAL": 15,
	"HIGH":     10,
	"MEDIUM":   5,
	"LOW":      2,
}

// AssessRisk evaluates the risk score and prints a breakdown. Unless
// skipScan is set, it downloads the package source and runs it through the
// sandboxed vulnscan scan (internal/vulnscan) as part of the score.
func AssessRisk(ctx context.Context, owner, packageName string, skipScan bool) {
	fmt.Printf("Assessing risk for package: %s\n\n", packageName)

	// get the github metadata for the repo
	data, err := fetchmeta.GetGitHubRepoData(owner, packageName)
	if err != nil {
		fmt.Println("⚠️ Error searching GitHub:", err)
		return
	}

	// start with a perfect score and deduct for each risk factor
	score := 100
	var reasons []string

	if deduction, reason := popularityDeduction(data.StargazersCount); deduction > 0 {
		reasons = append(reasons, reason)
		score -= deduction
	}

	// Deduct for skipped scan (cant say its 100% safe if we didnt scan it!)
	if skipScan {
		reasons = append(reasons, "Skipped sandboxed vulnerability scan (--no-scan)")
	} else {
		// run the sandboxed scan and deduct for any findings
		deduction, scanReasons := runScan(ctx, owner, packageName)
		reasons = append(reasons, scanReasons...)
		score -= deduction
	}

	if score < 0 {
		score = 0
	}

	// print the breakdown of reasons for deductions
	if len(reasons) > 0 {
		fmt.Println("📊 **Risk Breakdown**")
		for _, reason := range reasons {
			fmt.Println(reason)
		}
	}

	fmt.Printf("\n🔎 Final Risk Score for %s: **%d/100**\n", packageName, score)
}

// popularityDeduction scores a repo's star count. Returns a zero deduction
// and empty reason when the repo clears the popularity bar.
func popularityDeduction(stars int) (int, string) {
	const threshold = 100
	const deduction = 20
	if stars >= threshold {
		return 0, ""
	}
	return deduction, fmt.Sprintf("-%d: Low popularity (%d stars)", deduction, stars)
}

// runScan downloads the package source and runs the sandboxed vulnscan
// scan, returning the score deduction and the reasons to display for it.
// Failures here (no Docker, download error) degrade to a warning rather
// than aborting the whole assessment, since the metadata-based score is
// still meaningful on its own.
func runScan(ctx context.Context, owner, packageName string) (int, []string) {
	// download the package source for scanning
	archivePath, cleanup, err := fetcharchive.Download(owner, packageName)
	if err != nil {
		return 0, []string{fmt.Sprintf("⚠️ Could not download source for scanning: %v", err)}
	}
	defer cleanup()

	// run the sandboxed scan
	report, err := vulnscan.Scan(ctx, archivePath)
	if err != nil {
		return 0, []string{fmt.Sprintf("⚠️ Sandboxed scan did not run (%v) — score reflects GitHub metadata only", err)}
	}

	return scoreForReport(report)
}

// scoreForReport turns a vulnscan report into a score deduction and the
// human-readable reasons behind it. Pulled out of runScan so the scoring
// math can be unit tested against fabricated reports without Docker.
func scoreForReport(report *vulnscan.Report) (int, []string) {
	var reasons []string
	raw := 0

	// Deduct for SCA findings (vulnerable dependencies)
	if n := len(report.ScaFindings); n > 0 {
		d := n * scaDeductionPerHit
		reasons = append(reasons, fmt.Sprintf("-%d: %d vulnerable dependencies found (SCA)", d, n))
		raw += d
	}

	// Deduct for SAST findings (vulnerable code)
	bySeverity := map[string]int{}
	for _, f := range report.SastFindings {
		bySeverity[strings.ToUpper(f.Severity)]++
	}

	// Deduct for each severity level, if any findings exist
	for _, severity := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		count := bySeverity[severity]
		if count == 0 {
			continue
		}
		d := sastSeverityDeduction[severity] * count
		reasons = append(reasons, fmt.Sprintf("-%d: %d %s severity SAST finding(s)", d, count, severity))
		raw += d
	}

	// Cap the total deduction to avoid a large dependency tree zeroing out the score
	applied := raw
	if applied > maxVulnDeduction {
		reasons = append(reasons, fmt.Sprintf("(vulnerability deduction capped at -%d, raw total was -%d)", maxVulnDeduction, raw))
		applied = maxVulnDeduction
	}

	return applied, reasons
}
