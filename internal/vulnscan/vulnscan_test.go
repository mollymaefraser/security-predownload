package vulnscan

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestMergeReports_TakesFindingsFromOwningPass(t *testing.T) {
	// a SAST report with SAST findings and an SCA report with SCA findings should merge into a report containing both types of findings.
	sastReport := &Report{
		SastFindings: []SastFinding{{File: "app.py", RuleID: "PY-OS-SYSTEM"}},
	}
	scaReport := &Report{
		ScaFindings: []ScaHit{{Package: "django", Version: "1.4"}},
	}

	got := mergeReports(sastReport, scaReport)

	// check that the merged report contains both types of findings.
	if len(got.SastFindings) != 1 || got.SastFindings[0].RuleID != "PY-OS-SYSTEM" {
		t.Errorf("SAST findings not carried over correctly: %+v", got.SastFindings)
	}
	if len(got.ScaFindings) != 1 || got.ScaFindings[0].Package != "django" {
		t.Errorf("SCA findings not carried over correctly: %+v", got.ScaFindings)
	}
}

func TestMergeReports_IgnoresOtherPassCrossContamination(t *testing.T) {
	// Neither pass should populate the other's finding type in practice
	// (--no-sca / --no-sast), but if one did, merge should still only take
	// SAST findings from the SAST-pass report and SCA findings from the
	// SCA-pass report.
	sastReport := &Report{
		SastFindings: []SastFinding{{RuleID: "real-sast-finding"}},
		ScaFindings:  []ScaHit{{Package: "should-be-ignored"}},
	}
	scaReport := &Report{
		ScaFindings:  []ScaHit{{Package: "real-sca-finding"}},
		SastFindings: []SastFinding{{RuleID: "should-be-ignored"}},
	}

	// merge the reports and check that only the correct findings are present in the merged report.
	got := mergeReports(sastReport, scaReport)

	// check that the merged report contains only the SAST findings from the SAST report and only the SCA findings from the SCA report.
	if len(got.SastFindings) != 1 || got.SastFindings[0].RuleID != "real-sast-finding" {
		t.Errorf("expected only the SAST pass's SAST findings, got %+v", got.SastFindings)
	}
	if len(got.ScaFindings) != 1 || got.ScaFindings[0].Package != "real-sca-finding" {
		t.Errorf("expected only the SCA pass's SCA findings, got %+v", got.ScaFindings)
	}
}

func TestDockerBuildInputs_PointsAtRepoDockerfile(t *testing.T) {
	// dockerBuildInputs should return the path to the vulnscan.Dockerfile in the repo and the build context directory.
	dockerfile, buildContext := dockerBuildInputs()

	// check that the dockerfile is named vulnscan.Dockerfile and that the build context is the docker directory, and that the dockerfile is inside the build context.
	if filepath.Base(dockerfile) != "vulnscan.Dockerfile" {
		t.Errorf("unexpected dockerfile: %s", dockerfile)
	}
	if filepath.Base(buildContext) != "docker" {
		t.Errorf("unexpected build context: %s", buildContext)
	}
	if !strings.HasPrefix(dockerfile, buildContext) {
		t.Errorf("dockerfile %s should live inside build context %s", dockerfile, buildContext)
	}
}
