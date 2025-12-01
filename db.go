package main

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const koiCSVURL = "https://docs.google.com/spreadsheets/d/16aw6s7mWoGU7vxBciTEZSaR5HaohlBTfVirvI-PypJc/export?format=csv&gid=1289659284"

var (
	masterPackages       MasterPackages
	affectedPackageNames map[string]Severity

	koiCachePath = "/tmp/shai-hulud-koi-compromised-packages.csv"
	koiCacheTTL  = 24 * time.Hour
)

func parseMasterPackagesFromCSVReader(src io.Reader) error {
	r := csv.NewReader(src)
	r.FieldsPerRecord = -1

	records, err := r.ReadAll()
	if err != nil {
		return err
	}
	if len(records) == 0 {
		return fmt.Errorf("empty CSV")
	}

	pkgs := make([]MasterPackage, 0, len(records)-1)

	for i, rec := range records {
		// Skip header row
		if i == 0 {
			continue
		}
		if len(rec) == 0 {
			continue
		}

		name := strings.TrimSpace(rec[0])
		if name == "" || strings.EqualFold(name, "package") {
			continue
		}

		pkgs = append(pkgs, MasterPackage{
			Name:     name,
			Severity: SeverityCritical,
		})
	}

	masterPackages = MasterPackages{
		Version:     "koi-csv-live",
		LastUpdated: time.Now().UTC().Format(time.RFC3339),
		Packages:    pkgs,
	}

	affectedPackageNames = make(map[string]Severity, len(masterPackages.Packages))
	for _, p := range masterPackages.Packages {
		sev := p.Severity
		if sev == "" {
			sev = SeverityCritical
		}
		affectedPackageNames[p.Name] = sev
	}

	return nil
}

func loadMasterPackagesFromCSV(url string) error {
	// Try cached file in /tmp first
	if info, err := os.Stat(koiCachePath); err == nil {
		if time.Since(info.ModTime()) <= koiCacheTTL {
			if f, err := os.Open(koiCachePath); err == nil {
				defer f.Close()
				if err := parseMasterPackagesFromCSVReader(f); err == nil {
					return nil
				}
			}
		}
	}

	// Fallback to live download
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch CSV: %s", resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Best-effort write to cache; ignore write error
	_ = os.WriteFile(koiCachePath, data, 0o600)

	return parseMasterPackagesFromCSVReader(bytes.NewReader(data))
}

func isAffected(pkg string) bool {
	_, ok := affectedPackageNames[pkg]
	return ok
}

func getPackageSeverity(pkg string) Severity {
	if s, ok := affectedPackageNames[pkg]; ok {
		return s
	}
	return SeverityCritical
}
