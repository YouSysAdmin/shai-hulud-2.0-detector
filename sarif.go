package main

import (
	"fmt"
)

func sanitizeName(s string) string {
	res := make([]rune, 0, len(s))
	for _, r := range s {
		if (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '_' {
			res = append(res, r)
		} else {
			res = append(res, '_')
		}
	}
	return string(res)
}

func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

func generateSarif(summary ScanSummary) SarifResult {
	var rules []SarifRule
	var results []SarifResultIt
	ruleMap := make(map[string]string)
	ruleIndex := 0

	addRule := func(key, name, short, full, level string) string {
		if id, ok := ruleMap[key]; ok {
			return id
		}
		ruleIndex++
		id := fmt.Sprintf("SHAI-HULUD-%04d", ruleIndex)
		ruleMap[key] = id
		rules = append(rules, SarifRule{
			ID:   id,
			Name: name,
			ShortDescription: SarifText{
				Text: short,
			},
			FullDescription: SarifText{
				Text: full,
			},
			HelpURI: "https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains",
			DefaultConfiguration: SarifDefaultConfig{
				Level: level,
			},
		})
		return id
	}

	for _, r := range summary.Results {
		level := "warning"
		if r.Severity == SeverityCritical {
			level = "error"
		}
		key := "pkg:" + r.Package
		ruleID := addRule(
			key,
			fmt.Sprintf("CompromisedPackage_%s", sanitizeName(r.Package)),
			fmt.Sprintf("Compromised package: %s", r.Package),
			fmt.Sprintf(`The package "%s" has been identified as compromised in the Shai-Hulud 2.0 supply chain attack. This package may contain malicious code that steals credentials and exfiltrates sensitive data.`, r.Package),
			level,
		)
		results = append(results, SarifResultIt{
			RuleID: ruleID,
			Level:  level,
			Message: SarifText{
				Text: fmt.Sprintf(`Compromised package "%s@%s" detected. This package is part of the Shai-Hulud 2.0 supply chain attack.`, r.Package, r.Version),
			},
			Location: []SarifLocationRef{
				{
					PhysicalLocation: SarifPhysicalLocation{
						ArtifactLocation: SarifArtifactLocation{
							URI: r.Location,
						},
					},
				},
			},
		})
	}

	typePrefix := map[string]string{
		"suspicious-script":    "SCRIPT",
		"trufflehog-activity":  "TRUFFLEHOG",
		"shai-hulud-repo":      "REPO",
		"secrets-exfiltration": "EXFIL",
		"malicious-runner":     "RUNNER",
		"compromised-package":  "PKG",
	}
	for _, f := range summary.SecurityFindings {
		prefix := "SEC"
		if p, ok := typePrefix[f.Type]; ok {
			prefix = p
		}
		level := "note"
		switch f.Severity {
		case SeverityCritical:
			level = "error"
		case SeverityHigh:
			level = "warning"
		case SeverityMedium, SeverityLow:
			level = "note"
		}
		key := f.Type + ":" + f.Title
		if _, ok := ruleMap[key]; !ok {
			ruleIndex++
			id := fmt.Sprintf("SHAI-%s-%04d", prefix, ruleIndex)
			ruleMap[key] = id
			rules = append(rules, SarifRule{
				ID:   id,
				Name: truncateString(sanitizeName(f.Title), 64),
				ShortDescription: SarifText{
					Text: f.Title,
				},
				FullDescription: SarifText{
					Text: f.Description,
				},
				HelpURI: "https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains",
				DefaultConfiguration: SarifDefaultConfig{
					Level: level,
				},
			})
		}
		ruleID := ruleMap[key]
		msg := f.Title + ": " + f.Description
		if f.Evidence != "" {
			msg += "\n\nEvidence: " + f.Evidence
		}
		loc := SarifPhysicalLocation{
			ArtifactLocation: SarifArtifactLocation{
				URI: f.Location,
			},
		}
		if f.Line > 0 {
			loc.Region = &SarifRegion{StartLine: f.Line}
		}
		results = append(results, SarifResultIt{
			RuleID: ruleID,
			Level:  level,
			Message: SarifText{
				Text: msg,
			},
			Location: []SarifLocationRef{
				{PhysicalLocation: loc},
			},
		})
	}

	return SarifResult{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SarifRun{
			{
				Tool: SarifTool{
					Driver: SarifDriver{
						Name:           "shai-hulud-detector-go",
						Version:        "1.0.0",
						InformationURI: "https://github.com/gensecaihq/Shai-Hulud-2.0-Detector",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}
}
