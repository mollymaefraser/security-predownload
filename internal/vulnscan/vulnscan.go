// Package vulnscan runs mollymaefraser/vulnscan (SCA + SAST for a source
// archive) inside the sandbox in internal/sandbox and parses its report.
package vulnscan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"risk-check/internal/sandbox"
)

const image = "vulnscan-sandbox:latest"

// Report mirrors vulnscan's --json output (src/report.rs: JsonReport).
type Report struct {
	ScaFindings  []ScaHit      `json:"sca_findings"`
	SastFindings []SastFinding `json:"sast_findings"`
}

// ScaHit mirrors vulnscan's JsonScaHit: a dependency with known
// vulnerabilities, found via a lockfile and checked against OSV.dev.
type ScaHit struct {
	Package          string   `json:"package"`
	Version          string   `json:"version"`
	Ecosystem        string   `json:"ecosystem"`
	SourceFile       string   `json:"source_file"`
	VulnerabilityIDs []string `json:"vulnerability_ids"`
	Summaries        []string `json:"summaries"`
}

// SastFinding mirrors vulnscan's JsonSastFinding: a source-level pattern
// match (dangerous call, hardcoded secret, etc).
type SastFinding struct {
	File        string  `json:"file"`
	Line        int     `json:"line"`
	RuleID      string  `json:"rule_id"`
	Severity    string  `json:"severity"`
	CWE         *string `json:"cwe"`
	Description string  `json:"description"`
	Snippet     string  `json:"snippet"`
}

// Scan builds the vulnscan sandbox image if needed, then runs two isolated
// passes against archivePath and merges their findings:
//
//   - SAST pass: --network none. It only reads the extracted archive
//     contents, so it never gets network access.
//   - SCA pass: network allowed, since vulnscan checks each dependency it
//     finds against OSV.dev.
func Scan(ctx context.Context, archivePath string) (*Report, error) {
	// check if sandbox is available before trying to build the image, since building
	// the image requires sandbox to be available (docker daemon running, etc)
	if err := sandbox.Available(ctx); err != nil {
		return nil, fmt.Errorf("sandbox unavailable: %w", err)
	}

	// build vulnscan image if needed
	dockerfile, buildContext := dockerBuildInputs()
	if err := sandbox.EnsureImage(ctx, image, dockerfile, buildContext); err != nil {
		return nil, err
	}

	// vulnscan runs inside the sandbox as a fixed non-root user, so it needs
	// read access to the archive dir and write access to the output dir
	// regardless of which host user owns them.
	archiveDir := filepath.Dir(archivePath)
	archiveName := filepath.Base(archivePath)

	// the container runs as a fixed non-root user (internal/sandbox); it
	// needs read access to the archive dir and write access to the output
	// dir regardless of which host user owns them.
	if err := os.Chmod(archiveDir, 0o755); err != nil {
		return nil, fmt.Errorf("preparing archive dir permissions: %w", err)
	}

	// vulnscan writes its JSON report to a temp dir, which we delete after reading it back out. The container runs as a fixed non-root user (internal/sandbox),
	// so we need to make sure the temp dir is world-writable.
	outDir, err := os.MkdirTemp("", "vulnscan-out-*")
	if err != nil {
		return nil, fmt.Errorf("creating output dir: %w", err)
	}
	defer os.RemoveAll(outDir)
	if err := os.Chmod(outDir, 0o777); err != nil {
		return nil, fmt.Errorf("preparing output dir permissions: %w", err)
	}

	// run the two passes in sequence, since they both write to the same output dir
	// and vulnscan doesn't support concurrent runs in the same dir.
	sastReport, err := runPass(ctx, archiveDir, archiveName, outDir, "sast.json", "--no-sca", false)
	if err != nil {
		return nil, fmt.Errorf("SAST pass: %w", err)
	}

	// SCA pass needs network access to check dependencies against OSV.dev, so we allow it here.
	scaReport, err := runPass(ctx, archiveDir, archiveName, outDir, "sca.json", "--no-sast", true)
	if err != nil {
		return nil, fmt.Errorf("SCA pass: %w", err)
	}

	return &Report{
		ScaFindings:  scaReport.ScaFindings,
		SastFindings: sastReport.SastFindings,
	}, nil
}

func runPass(ctx context.Context, archiveDir, archiveName, outDir, outName, skipFlag string, network bool) (*Report, error) {
	// run vulnscan inside the sandbox, mounting the archive dir read-only and the output dir read-write
	_, err := sandbox.Run(ctx, sandbox.RunOpts{
		Image: image,
		Command: []string{
			"/scan/" + archiveName,
			"--json", "/out/" + outName,
			skipFlag,
		},
		Mounts: []sandbox.Mount{
			{HostPath: archiveDir, ContainerPath: "/scan", ReadOnly: true},
			{HostPath: outDir, ContainerPath: "/out", ReadOnly: false},
		},
		Network: network,
	})
	if err != nil {
		return nil, err
	}

	// read the JSON report back out of the output dir and parse it
	data, err := os.ReadFile(filepath.Join(outDir, outName))
	if err != nil {
		return nil, fmt.Errorf("reading report: %w", err)
	}

	// parse the JSON report into a Report struct
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parsing report: %w", err)
	}
	return &report, nil
}

// dockerBuildInputs locates docker/vulnscan.Dockerfile relative to this
// source file, so Scan works regardless of the caller's working directory
// as long as the repo checkout is intact.
func dockerBuildInputs() (dockerfile, buildContext string) {
	// runtime.Caller(0) returns the full path to this source file, so we can
	// locate the repo root and the docker dir relative to it.
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
	dockerDir := filepath.Join(repoRoot, "docker")
	return filepath.Join(dockerDir, "vulnscan.Dockerfile"), dockerDir
}
