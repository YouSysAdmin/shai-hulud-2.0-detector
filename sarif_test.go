package main

import "testing"

func TestGenerateSarif_Basic(t *testing.T) {
	summary := ScanSummary{
		TotalDependencies: 2,
		AffectedCount:     1,
		CleanCount:        1,
		Results: []ScanResult{
			{
				Package:  "badpkg",
				Version:  "1.0.0",
				Severity: SeverityCritical,
				IsDirect: true,
				Location: "package.json",
			},
		},
		SecurityFindings: []SecurityFinding{
			{
				Type:        "suspicious-script",
				Severity:    SeverityHigh,
				Title:       "Suspicious npm script",
				Description: "curl | bash detected",
				Location:    "package.json",
			},
		},
		DBVersion:     "test",
		DBLastUpdated: "2024-01-01T00:00:00Z",
	}

	sarif := generateSarif(summary)

	if sarif.Version != "2.1.0" {
		t.Fatalf("expected SARIF 2.1.0, got %s", sarif.Version)
	}

	if len(sarif.Runs) != 1 {
		t.Fatalf("expected one run")
	}

	run := sarif.Runs[0]
	if len(run.Tool.Driver.Rules) == 0 {
		t.Fatalf("expected rules")
	}

	if len(run.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(run.Results))
	}
}
