package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func formatTextReport(summary ScanSummary) string {
	var lines []string
	hasIssues := summary.AffectedCount > 0 || len(summary.SecurityFindings) > 0

	var crit, high, med, low []SecurityFinding
	for _, f := range summary.SecurityFindings {
		switch f.Severity {
		case SeverityCritical:
			crit = append(crit, f)
		case SeverityHigh:
			high = append(high, f)
		case SeverityMedium:
			med = append(med, f)
		case SeverityLow:
			low = append(low, f)
		}
	}

	lines = append(lines, "")
	lines = append(lines, strings.Repeat("=", 70))
	lines = append(lines, "  SHAI-HULUD 2.0 SUPPLY CHAIN ATTACK DETECTOR (Go CLI)")
	lines = append(lines, strings.Repeat("=", 70))
	lines = append(lines, "")

	if !hasIssues {
		lines = append(lines, "  STATUS: CLEAN")
		lines = append(lines, "  No compromised packages or security issues detected.")
	} else {
		parts := []string{}
		if summary.AffectedCount > 0 {
			parts = append(parts, fmt.Sprintf("%d compromised package(s)", summary.AffectedCount))
		}
		if len(summary.SecurityFindings) > 0 {
			parts = append(parts, fmt.Sprintf("%d security finding(s)", len(summary.SecurityFindings)))
		}
		lines = append(lines, "  STATUS: AFFECTED - "+strings.Join(parts, ", "))
	}

	if summary.AffectedCount > 0 {
		lines = append(lines, "")
		lines = append(lines, strings.Repeat("-", 70))
		lines = append(lines, "  COMPROMISED PACKAGES:")
		lines = append(lines, strings.Repeat("-", 70))

		for _, r := range summary.Results {
			badge := fmt.Sprintf("[%s]", strings.ToUpper(string(r.Severity)))
			if r.Severity == SeverityCritical {
				badge = "[CRITICAL]"
			}
			typ := "(transitive)"
			if r.IsDirect {
				typ = "(direct)"
			}
			lines = append(lines, fmt.Sprintf("  %s %s@%s %s", badge, r.Package, r.Version, typ))
			lines = append(lines, fmt.Sprintf("         Location: %s", r.Location))
		}
	}

	if len(summary.SecurityFindings) > 0 {
		lines = append(lines, "")
		lines = append(lines, strings.Repeat("-", 70))
		lines = append(lines, "  SECURITY FINDINGS:")
		lines = append(lines, strings.Repeat("-", 70))

		printGroup := func(label string, items []SecurityFinding) {
			if len(items) == 0 {
				return
			}
			lines = append(lines, "")
			lines = append(lines, fmt.Sprintf("  %s (%d):", label, len(items)))
			for _, f := range items {
				lines = append(lines, fmt.Sprintf("    [%s] %s", strings.ToUpper(string(f.Severity)), f.Title))
				lines = append(lines, fmt.Sprintf("           Type: %s", f.Type))
				lines = append(lines, fmt.Sprintf("           Location: %s", f.Location))
				if f.Evidence != "" {
					ev := f.Evidence
					if len(ev) > 80 {
						ev = ev[:77] + "..."
					}
					lines = append(lines, fmt.Sprintf("           Evidence: %s", ev))
				}
				lines = append(lines, fmt.Sprintf("           %s", f.Description))
			}
		}

		printGroup("CRITICAL", crit)
		printGroup("HIGH", high)
		printGroup("MEDIUM", med)
		printGroup("LOW", low)
	}

	lines = append(lines, "")
	lines = append(lines, strings.Repeat("-", 70))
	lines = append(lines, fmt.Sprintf("  Files scanned: %d", len(summary.ScannedFiles)))
	lines = append(lines, fmt.Sprintf("  Compromised packages: %d", summary.AffectedCount))
	lines = append(lines, fmt.Sprintf("  Security findings: %d", len(summary.SecurityFindings)))
	lines = append(lines, fmt.Sprintf("  Scan time: %dms", summary.ScanTimeMS))
	lines = append(lines, fmt.Sprintf("  Database version: %s", summary.DBVersion))
	lines = append(lines, fmt.Sprintf("  Last updated: %s", summary.DBLastUpdated))
	lines = append(lines, strings.Repeat("=", 70))
	lines = append(lines, "")

	if hasIssues {
		lines = append(lines, "  IMMEDIATE ACTIONS REQUIRED:")
		lines = append(lines, "  1. Do NOT run npm install until packages are updated")
		lines = append(lines, "  2. Rotate all credentials (npm, GitHub, AWS, etc.)")
		lines = append(lines, "  3. Check for unauthorized GitHub self-hosted runners named \"SHA1HULUD\"")
		lines = append(lines, "  4. Audit GitHub repos for \"Shai-Hulud: The Second Coming\" description")
		lines = append(lines, "  5. Check for actionsSecrets.json files containing stolen credentials")
		lines = append(lines, "  6. Review package.json scripts for suspicious preinstall/postinstall hooks")
		lines = append(lines, "")
		lines = append(lines, "  For more information:")
		lines = append(lines, "  https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains")
		lines = append(lines, "")
	}

	return strings.Join(lines, "\n")
}

func main() {
	var (
		dir          string
		format       string
		failOnAny    bool
		failOnCrit   bool
		failOnHigh   bool
		sarifOutPath string
	)
	flag.StringVar(&dir, "dir", ".", "Directory to scan")
	flag.StringVar(&format, "format", "text", "Output format: text|json|sarif")
	flag.BoolVar(&failOnAny, "fail-on-any", false, "Exit non-zero if any issues are found")
	flag.BoolVar(&failOnCrit, "fail-on-critical", false, "Exit non-zero if any critical issues are found")
	flag.BoolVar(&failOnHigh, "fail-on-high", false, "Exit non-zero if any high/critical issues are found")
	flag.StringVar(&sarifOutPath, "sarif-out", "shai-hulud-results.sarif", "Path to write SARIF report (for format=sarif)")
	flag.Parse()

	if err := loadMasterPackagesFromCSV(koiCSVURL); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load master packages DB: %v\n", err)
		os.Exit(1)
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to resolve dir: %v\n", err)
		os.Exit(1)
	}
	info, err := os.Stat(absDir)
	if err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "Directory does not exist or not a dir: %s\n", absDir)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("Shai-Hulud 2.0 Detector (Go CLI)")
	fmt.Println("===============================")
	fmt.Printf("Database version: %s\n", masterPackages.Version)
	fmt.Printf("Last updated: %s\n", masterPackages.LastUpdated)
	fmt.Printf("Total known affected packages: %d\n", len(masterPackages.Packages))
	fmt.Println()
	fmt.Printf("Scanning directory: %s\n", absDir)

	summary := runScan(absDir, true)

	switch strings.ToLower(format) {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(summary); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write JSON: %v\n", err)
			os.Exit(1)
		}
	case "sarif":
		sarif := generateSarif(summary)
		data, err := json.MarshalIndent(sarif, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to marshal SARIF: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(sarifOutPath, data, fs.ModePerm); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write SARIF file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("SARIF report written to: %s\n", sarifOutPath)
	default:
		fmt.Println(formatTextReport(summary))
	}

	hasIssues := summary.AffectedCount > 0 || len(summary.SecurityFindings) > 0

	criticalSec := 0
	highOrAboveSec := 0
	for _, f := range summary.SecurityFindings {
		switch f.Severity {
		case SeverityCritical:
			criticalSec++
			highOrAboveSec++
		case SeverityHigh:
			highOrAboveSec++
		}
	}
	criticalPkgs := 0
	highOrAbovePkgs := 0
	for _, r := range summary.Results {
		switch r.Severity {
		case SeverityCritical:
			criticalPkgs++
			highOrAbovePkgs++
		case SeverityHigh:
			highOrAbovePkgs++
		}
	}

	exitCode := 0
	var failReason string

	switch {
	case failOnAny && hasIssues:
		failReason = fmt.Sprintf("%d compromised package(s), %d security finding(s)", summary.AffectedCount, len(summary.SecurityFindings))
	case failOnCrit:
		totalCrit := criticalPkgs + criticalSec
		if totalCrit > 0 {
			failReason = fmt.Sprintf("%d critical severity issue(s) detected", totalCrit)
		}
	case failOnHigh:
		totalHigh := highOrAbovePkgs + highOrAboveSec
		if totalHigh > 0 {
			failReason = fmt.Sprintf("%d high/critical severity issue(s) detected", totalHigh)
		}
	}

	if failReason != "" {
		fmt.Fprintf(os.Stderr, "Shai-Hulud 2.0 indicators detected: %s\n", failReason)
		exitCode = 1
	} else if hasIssues {
		fmt.Fprintf(os.Stderr, "Shai-Hulud 2.0: Issues found (%d package(s), %d finding(s)) but not failing due to flags\n",
			summary.AffectedCount, len(summary.SecurityFindings))
	} else {
		fmt.Println("Scan complete. No compromised packages or security issues detected.")
	}

	os.Exit(exitCode)
}
