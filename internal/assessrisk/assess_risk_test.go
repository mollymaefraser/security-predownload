package assessrisk

import (
	"testing"

	"risk-check/internal/vulnscan"
)

func TestPopularityDeduction(t *testing.T) {
	// test that the popularity deduction is applied for low star counts and not applied for high star counts.
	cases := []struct {
		stars        int
		wantDeducted bool
	}{
		{stars: 5, wantDeducted: true},
		{stars: 99, wantDeducted: true},
		{stars: 100, wantDeducted: false},
		{stars: 10000, wantDeducted: false},
	}
	// run the test cases
	for _, tc := range cases {
		deduction, reason := popularityDeduction(tc.stars)
		if tc.wantDeducted && deduction <= 0 {
			t.Errorf("stars=%d: expected a deduction, got %d", tc.stars, deduction)
		}
		if !tc.wantDeducted && (deduction != 0 || reason != "") {
			t.Errorf("stars=%d: expected no deduction, got %d (%q)", tc.stars, deduction, reason)
		}
	}
}

func TestScoreForReport_NoFindings(t *testing.T) {
	// a report with no findings should not deduct any points and should not produce any reasons.
	deduction, reasons := scoreForReport(&vulnscan.Report{})
	if deduction != 0 {
		t.Errorf("expected 0 deduction for a clean report, got %d", deduction)
	}
	if len(reasons) != 0 {
		t.Errorf("expected no reasons for a clean report, got %v", reasons)
	}
}

func TestScoreForReport_ScaFindings(t *testing.T) {
	// a report with SCA findings should deduct points for each finding and produce a reason.
	report := &vulnscan.Report{
		ScaFindings: []vulnscan.ScaHit{
			{Package: "django"}, {Package: "requests"},
		},
	}
	// each SCA finding should deduct 5 points, so with 2 findings we expect a deduction of 10.
	deduction, reasons := scoreForReport(report)
	if want := 2 * scaDeductionPerHit; deduction != want {
		t.Errorf("got deduction %d, want %d", deduction, want)
	}
	if len(reasons) != 1 {
		t.Errorf("expected exactly one SCA reason, got %v", reasons)
	}
}

func TestScoreForReport_SastSeverityWeighting(t *testing.T) {
	// a report with SAST findings of various severities should deduct points according to the severity weighting.
	report := &vulnscan.Report{
		SastFindings: []vulnscan.SastFinding{
			{Severity: "CRITICAL"},
			{Severity: "high"}, // lowercase from vulnscan should still be recognized
			{Severity: "LOW"},
		},
	}
	// the expected deduction is the sum of the deductions for each severity level present in the report.
	deduction, _ := scoreForReport(report)
	want := sastSeverityDeduction["CRITICAL"] + sastSeverityDeduction["HIGH"] + sastSeverityDeduction["LOW"]
	if deduction != want {
		t.Errorf("got deduction %d, want %d", deduction, want)
	}
}

func TestScoreForReport_UnknownSeverityIgnored(t *testing.T) {
	// a report with an unrecognized severity should not affect the score or produce any reasons.
	report := &vulnscan.Report{
		SastFindings: []vulnscan.SastFinding{{Severity: "NOT_A_REAL_SEVERITY"}},
	}
	// the expected deduction is 0 and there should be no reasons for an unrecognized severity.
	deduction, reasons := scoreForReport(report)
	if deduction != 0 {
		t.Errorf("expected unknown severities to not affect score, got deduction %d", deduction)
	}
	if len(reasons) != 0 {
		t.Errorf("expected no reasons for an unrecognized severity, got %v", reasons)
	}
}

func TestScoreForReport_DeductionIsCapped(t *testing.T) {
	// 10 SCA hits alone would be 10*5=50, comfortably over maxVulnDeduction.
	hits := make([]vulnscan.ScaHit, 10)
	report := &vulnscan.Report{ScaFindings: hits}

	// the expected deduction should be capped at maxVulnDeduction, and a reason should note that the cap was applied.
	deduction, reasons := scoreForReport(report)
	if deduction != maxVulnDeduction {
		t.Errorf("got deduction %d, want capped value %d", deduction, maxVulnDeduction)
	}

	// check that the reasons include a note about the cap being applied
	foundCapNote := false
	for _, r := range reasons {
		if r == "(vulnerability deduction capped at -40, raw total was -50)" {
			foundCapNote = true
		}
	}
	if !foundCapNote {
		t.Errorf("expected a reason noting the cap was applied, got %v", reasons)
	}
}
