package main

import (
	"strings"
	"testing"
)

func TestParseMasterPackagesFromCSVReader_Basic(t *testing.T) {
	csvData := `package,version,status,date
lodash,1.0.0,compromised,2024-01-01
left-pad,0.0.1,compromised,2024-01-02
`

	masterPackages = MasterPackages{}
	affectedPackageNames = nil

	if err := parseMasterPackagesFromCSVReader(strings.NewReader(csvData)); err != nil {
		t.Fatalf("parseMasterPackagesFromCSVReader returned error: %v", err)
	}

	if len(masterPackages.Packages) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(masterPackages.Packages))
	}

	if !isAffected("lodash") || !isAffected("left-pad") {
		t.Fatalf("expected both packages to be marked as affected")
	}

	severity := getPackageSeverity("lodash")
	if severity != SeverityCritical {
		t.Fatalf("expected SeverityCritical, got %v", severity)
	}
}
