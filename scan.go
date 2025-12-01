package main

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	suspiciousScriptPatterns = []struct {
		re          *regexp.Regexp
		description string
	}{
		{regexp.MustCompile(`(?i)setup_bun\.js`), "Shai-Hulud malicious setup script"},
		{regexp.MustCompile(`(?i)bun_environment\.js`), "Shai-Hulud environment script"},
		{regexp.MustCompile(`(?i)\bcurl\s+[^|]*\|\s*(ba)?sh`), "Curl piped to shell execution"},
		{regexp.MustCompile(`(?i)\bwget\s+[^|]*\|\s*(ba)?sh`), "Wget piped to shell execution"},
		{regexp.MustCompile(`(?i)\beval\s*\(`), "Eval execution (potential code injection)"},
		{regexp.MustCompile("(?i)\\beval\\s+['\"$`]"), "Eval with dynamic content"},
		{regexp.MustCompile(`(?i)base64\s+(--)?d(ecode)?`), "Base64 decode execution"},
		{regexp.MustCompile(`(?i)\$\(curl`), "Command substitution with curl"},
		{regexp.MustCompile(`(?i)\$\(wget`), "Command substitution with wget"},
		{regexp.MustCompile(`(?i)node\s+-e\s+['"].*?(http|eval|Buffer\.from)`), "Inline Node.js code execution"},
		{regexp.MustCompile(`(?i)npx\s+--yes\s+[^@\s]+@`), "NPX auto-install of versioned package"},
	}

	trufflehogPatterns = []struct {
		re          *regexp.Regexp
		description string
	}{
		{regexp.MustCompile(`(?i)trufflehog`), "TruffleHog reference detected"},
		{regexp.MustCompile(`(?i)trufflesecurity`), "TruffleSecurity reference"},
		{regexp.MustCompile(`(?i)credential[_-]?scan`), "Credential scanning pattern"},
		{regexp.MustCompile(`(?i)secret[_-]?scan`), "Secret scanning pattern"},
		{regexp.MustCompile(`--json\s+--no-update`), "TruffleHog CLI pattern"},
		{regexp.MustCompile(`github\.com/trufflesecurity/trufflehog`), "TruffleHog GitHub download"},
		{regexp.MustCompile(`releases\/download.*trufflehog`), "TruffleHog binary download"},
	}

	shaiHuludRepoPatterns = []struct {
		re          *regexp.Regexp
		description string
	}{
		{regexp.MustCompile(`(?i)shai[-_]?hulud`), "Shai-Hulud repository name"},
		{regexp.MustCompile(`(?i)the\s+second\s+coming`), "Shai-Hulud campaign description"},
		{regexp.MustCompile(`(?i)sha1hulud`), "SHA1HULUD variant"},
	}

	maliciousRunnerPatterns = []struct {
		re          *regexp.Regexp
		description string
	}{
		{regexp.MustCompile(`(?i)runs-on:\s*['"]?SHA1HULUD`), "SHA1HULUD malicious runner"},
		{regexp.MustCompile(`(?i)runs-on:\s*['"]?self-hosted.*SHA1HULUD`), "Self-hosted SHA1HULUD runner"},
		{regexp.MustCompile(`(?i)runner[_-]?name.*SHA1HULUD`), "SHA1HULUD runner reference"},
		{regexp.MustCompile(`(?i)labels:.*SHA1HULUD`), "SHA1HULUD runner label"},
	}

	maliciousWorkflowPatterns = []struct {
		re          *regexp.Regexp
		description string
	}{
		{regexp.MustCompile(`(?i)formatter_.*\.yml$`), "Shai-Hulud formatter workflow (formatter_*.yml)"},
		{regexp.MustCompile(`(?i)discussion\.ya?ml$`), "Shai-Hulud discussion workflow"},
	}

	webhookExfilPatterns = []struct {
		re          *regexp.Regexp
		description string
	}{
		{regexp.MustCompile(`webhook\.site`), "Webhook.site exfiltration endpoint"},
		{regexp.MustCompile(`bb8ca5f6-4175-45d2-b042-fc9ebb8170b7`), "Known malicious webhook UUID"},
		{regexp.MustCompile(`(?i)exfiltrat`), "Exfiltration reference"},
	}

	maliciousDomainPatterns = []struct {
		re          *regexp.Regexp
		description string
		label       string
	}{
		{regexp.MustCompile(`packages\.storeartifact\.com`), "Shai-Hulud malicious package hosting domain", "packages.storeartifact.com"},
		{regexp.MustCompile(`hulud`), "Reference to Shai-Hulud infrastructure/domain", "hulud"},
	}

	affectedNamespaces = []string{
		"@zapier",
		"@posthog",
		"@asyncapi",
		"@postman",
		"@ensdomains",
		"@ens",
		"@voiceflow",
		"@browserbase",
		"@ctrl",
		"@crowdstrike",
		"@art-ws",
		"@ngx",
		"@nativescript-community",
		"@oku-ui",
	}

	excludedPathPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)shai-hulud.*detector`),
		regexp.MustCompile(`/src/scanner\.(ts|js)$`),
		regexp.MustCompile(`/src/types\.(ts|js)$`),
		regexp.MustCompile(`/src/index\.(ts|js)$`),
		regexp.MustCompile(`/dist/index\.js$`),
		regexp.MustCompile(`/dist/.*\.d\.ts$`),
	}
)

func parsePackageJSON(path string) (*PackageJSON, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p PackageJSON
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func parsePackageLock(path string) (*PackageLock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var l PackageLock
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, err
	}
	return &l, nil
}

func parseYarnLock(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	pkgs := make(map[string]string)
	current := ""

	for _, line := range lines {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") && strings.Contains(line, "@") {
			line = strings.TrimSpace(line)
			if i := strings.Index(line, "@"); i >= 0 {
				line = strings.TrimPrefix(line, "\"")
				line = strings.TrimSuffix(line, "\":")
				if strings.HasPrefix(line, "@") {
					parts := strings.SplitN(line, "@", 3)
					if len(parts) >= 3 {
						current = parts[0] + "@" + parts[1]
					}
				} else {
					parts := strings.SplitN(line, "@", 2)
					current = parts[0]
				}
			}
		} else if strings.TrimSpace(line) != "" && current != "" &&
			strings.HasPrefix(strings.TrimSpace(line), "version") {
			parts := strings.Split(line, "\"")
			if len(parts) >= 2 {
				pkgs[current] = parts[1]
			}
		}
	}
	return pkgs, nil
}

func findLockfiles(root string) []string {
	var res []string
	possible := map[string]bool{
		"package-lock.json":   true,
		"yarn.lock":           true,
		"pnpm-lock.yaml":      true,
		"npm-shrinkwrap.json": true,
	}
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > 5 {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			full := filepath.Join(dir, e.Name())
			if e.Type().IsRegular() {
				if possible[e.Name()] {
					res = append(res, full)
				}
			} else if e.IsDir() {
				if e.Name() == "node_modules" || strings.HasPrefix(e.Name(), ".") {
					continue
				}
				walk(full, depth+1)
			}
		}
	}
	walk(root, 0)
	return res
}

func findPackageJSONFiles(root string) []string {
	var res []string
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > 5 {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			full := filepath.Join(dir, e.Name())
			if e.Type().IsRegular() && e.Name() == "package.json" {
				res = append(res, full)
			} else if e.IsDir() {
				if e.Name() == "node_modules" || strings.HasPrefix(e.Name(), ".") {
					continue
				}
				walk(full, depth+1)
			}
		}
	}
	walk(root, 0)
	return res
}

func isExcludedPath(p string) bool {
	norm := filepath.ToSlash(p)
	for _, re := range excludedPathPatterns {
		if re.MatchString(norm) {
			return true
		}
	}
	return false
}

func isDetectorSourceCode(content string) bool {
	markers := []string{
		"SHAI-HULUD 2.0 SUPPLY CHAIN ATTACK DETECTOR",
		"gensecaihq/Shai-Hulud-2.0-Detector",
		"SUSPICIOUS PATTERNS FOR ADVANCED DETECTION",
		"checkTrufflehogActivity",
		"checkMaliciousRunners",
	}
	count := 0
	for _, m := range markers {
		if strings.Contains(content, m) {
			count++
		}
	}
	return count >= 2
}

func collectDependencies(p *PackageJSON) map[string]string {
	deps := make(map[string]string)

	for k, v := range p.Dependencies {
		deps[k] = v
	}
	for k, v := range p.DevDependencies {
		if _, exists := deps[k]; !exists {
			deps[k] = v
		}
	}
	for k, v := range p.PeerDependencies {
		if _, exists := deps[k]; !exists {
			deps[k] = v
		}
	}
	for k, v := range p.OptionalDependencies {
		if _, exists := deps[k]; !exists {
			deps[k] = v
		}
	}

	return deps
}

func checkSuspiciousScripts(root string, pkgFiles []string) []SecurityFinding {
	var findings []SecurityFinding

	for _, pkgPath := range pkgFiles {
		p, err := parsePackageJSON(pkgPath)
		if err != nil {
			continue
		}
		if len(p.Scripts) == 0 {
			continue
		}

		for name, script := range p.Scripts {
			// First, check generic suspicious script patterns
			matchedSuspicious := false
			for _, pat := range suspiciousScriptPatterns {
				if pat.re.MatchString(script) {
					findings = append(findings, SecurityFinding{
						Type:        "suspicious-script",
						Severity:    SeverityHigh,
						Title:       "Suspicious npm script: " + name,
						Description: pat.description,
						Location:    pkgPath,
						Evidence:    script,
					})
					matchedSuspicious = true
					break
				}
			}

			// Additionally, treat known malicious domains in scripts as critical findings
			for _, dpat := range maliciousDomainPatterns {
				if dpat.re.MatchString(script) {
					findings = append(findings, SecurityFinding{
						Type:        "malicious-domain",
						Severity:    SeverityCritical,
						Title:       "Malicious domain reference found: " + dpat.label,
						Description: dpat.description,
						Location:    pkgPath,
						Evidence:    script,
					})
					break
				}
			}

			_ = matchedSuspicious // keep variable in case we extend logic later
		}
	}

	return findings
}

func checkAffectedNamespacesInDeps(pkgFiles []string) []SecurityFinding {
	var findings []SecurityFinding

	for _, pkgPath := range pkgFiles {
		p, err := parsePackageJSON(pkgPath)
		if err != nil {
			continue
		}
		deps := collectDependencies(p)
		if len(deps) == 0 {
			continue
		}

		for _, ns := range affectedNamespaces {
			for depName, depVer := range deps {
				if strings.HasPrefix(depName, ns+"/") {
					findings = append(findings, SecurityFinding{
						Type:        "affected-namespace",
						Severity:    SeverityHigh,
						Title:       "Dependency in affected namespace: " + depName,
						Description: "Dependency belongs to a namespace known to be targeted in the Shai-Hulud 2.0 campaign.",
						Location:    pkgPath,
						Evidence:    depName + "@" + depVer,
					})
				}
			}
		}
	}

	return findings
}

func walkTextFiles(root string, maxSize int64, fn func(path string, info fs.DirEntry, content string)) {
	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == "node_modules" || strings.HasPrefix(name, ".") || name == "dist" || name == "build" {
				return filepath.SkipDir
			}
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}
		if maxSize > 0 && info.Size() > maxSize {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		content := string(data)
		if isDetectorSourceCode(content) {
			return nil
		}

		fn(path, d, content)
		return nil
	})
}

func checkTrufflehogActivity(root string) []SecurityFinding {
	var findings []SecurityFinding

	walkTextFiles(root, 512*1024, func(path string, _ fs.DirEntry, content string) {
		for _, pat := range trufflehogPatterns {
			if pat.re.MatchString(content) {
				findings = append(findings, SecurityFinding{
					Type:        "trufflehog-activity",
					Severity:    SeverityMedium,
					Title:       "Potential TruffleHog usage",
					Description: pat.description,
					Location:    path,
				})
				break
			}
		}
	})

	return findings
}

func checkSecretsExfiltration(root string) []SecurityFinding {
	var findings []SecurityFinding

	walkTextFiles(root, 512*1024, func(path string, _ fs.DirEntry, content string) {
		for _, pat := range webhookExfilPatterns {
			if pat.re.MatchString(content) {
				findings = append(findings, SecurityFinding{
					Type:        "secrets-exfiltration",
					Severity:    SeverityCritical,
					Title:       "Potential secrets exfiltration endpoint",
					Description: pat.description,
					Location:    path,
				})
				break
			}
		}
	})

	return findings
}

func checkMaliciousDomains(root string) []SecurityFinding {
	var findings []SecurityFinding

	walkTextFiles(root, 512*1024, func(path string, _ fs.DirEntry, content string) {
		for _, pat := range maliciousDomainPatterns {
			if pat.re.MatchString(content) {
				findings = append(findings, SecurityFinding{
					Type:        "malicious-domain",
					Severity:    SeverityCritical,
					Title:       "Malicious domain reference found: " + pat.label,
					Description: pat.description,
					Location:    path,
				})
				break
			}
		}
	})

	return findings
}

func checkMaliciousRunners(root string) []SecurityFinding {
	var findings []SecurityFinding
	workflows := filepath.Join(root, ".github", "workflows")

	walkTextFiles(workflows, 256*1024, func(path string, _ fs.DirEntry, content string) {
		for _, pat := range maliciousRunnerPatterns {
			if pat.re.MatchString(content) {
				findings = append(findings, SecurityFinding{
					Type:        "malicious-runner",
					Severity:    SeverityCritical,
					Title:       "Potential malicious GitHub Actions runner configuration",
					Description: pat.description,
					Location:    path,
				})
				break
			}
		}
	})

	return findings
}

func checkShaiHuludRepos(root string) []SecurityFinding {
	var findings []SecurityFinding

	walkTextFiles(root, 256*1024, func(path string, _ fs.DirEntry, content string) {
		for _, pat := range shaiHuludRepoPatterns {
			if pat.re.MatchString(content) {
				findings = append(findings, SecurityFinding{
					Type:        "shai-hulud-repo",
					Severity:    SeverityMedium,
					Title:       "Reference to Shai-Hulud campaign repository",
					Description: pat.description,
					Location:    path,
				})
				break
			}
		}
	})

	return findings
}

func checkMaliciousWorkflowFiles(root string) []SecurityFinding {
	var findings []SecurityFinding
	workflowsDir := filepath.Join(root, ".github", "workflows")

	filepath.WalkDir(workflowsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}

		nameLower := strings.ToLower(d.Name())
		matched := false

		if strings.Contains(nameLower, "hulud") || strings.Contains(nameLower, "shai") {
			matched = true
		} else {
			data, err := os.ReadFile(path)
			if err == nil {
				contentLower := strings.ToLower(string(data))
				if strings.Contains(contentLower, "shai-hulud") ||
					strings.Contains(contentLower, "sha1hulud") ||
					strings.Contains(contentLower, "gensecaihq/shai-hulud-2.0-detector") {
					matched = true
				}
			}
		}

		if matched {
			findings = append(findings, SecurityFinding{
				Type:        "malicious-workflow-file",
				Severity:    SeverityCritical,
				Title:       "Malicious workflow file found: " + d.Name(),
				Description: "Workflow file matches Shai-Hulud indicators in name or content.",
				Location:    path,
			})
		}

		return nil
	})

	return findings
}

func runScan(root string, includeTransitive bool) ScanSummary {
	start := time.Now()

	var (
		results         []ScanResult
		securityFinding []SecurityFinding
		scannedFiles    []string
	)

	pkgFiles := findPackageJSONFiles(root)
	lockFiles := findLockfiles(root)

	scannedFiles = append(scannedFiles, pkgFiles...)
	scannedFiles = append(scannedFiles, lockFiles...)

	seenDirect := make(map[string]bool)

	for _, pkgPath := range pkgFiles {
		p, err := parsePackageJSON(pkgPath)
		if err != nil {
			continue
		}
		deps := collectDependencies(p)

		for name, ver := range deps {
			if !isAffected(name) {
				continue
			}
			key := name + "@" + ver + "|" + pkgPath
			if seenDirect[key] {
				continue
			}
			seenDirect[key] = true

			results = append(results, ScanResult{
				Package:  name,
				Version:  ver,
				Severity: getPackageSeverity(name),
				IsDirect: true,
				Location: pkgPath,
			})
		}
	}

	if includeTransitive {
		for _, lockPath := range lockFiles {
			if strings.HasSuffix(lockPath, "package-lock.json") || strings.HasSuffix(lockPath, "npm-shrinkwrap.json") {
				lock, err := parsePackageLock(lockPath)
				if err != nil {
					continue
				}

				for name := range lock.Dependencies {
					if !isAffected(name) {
						continue
					}
					results = append(results, ScanResult{
						Package:  name,
						Version:  "",
						Severity: getPackageSeverity(name),
						IsDirect: false,
						Location: lockPath,
					})
				}
				for name := range lock.Packages {
					if !isAffected(name) {
						continue
					}
					results = append(results, ScanResult{
						Package:  name,
						Version:  "",
						Severity: getPackageSeverity(name),
						IsDirect: false,
						Location: lockPath,
					})
				}
			} else if strings.HasSuffix(lockPath, "yarn.lock") {
				pkgs, err := parseYarnLock(lockPath)
				if err != nil {
					continue
				}
				for key, ver := range pkgs {
					name := key
					if strings.HasPrefix(name, "@") {
						parts := strings.SplitN(name, "@", 3)
						if len(parts) >= 3 {
							name = parts[0] + "/" + parts[1]
						}
					} else {
						parts := strings.SplitN(name, "@", 2)
						if len(parts) == 2 {
							name = parts[0]
						}
					}
					if !isAffected(name) {
						continue
					}
					results = append(results, ScanResult{
						Package:  name,
						Version:  ver,
						Severity: getPackageSeverity(name),
						IsDirect: false,
						Location: lockPath,
					})
				}
			}
		}
	}

	securityFinding = append(securityFinding, checkSuspiciousScripts(root, pkgFiles)...)
	securityFinding = append(securityFinding, checkAffectedNamespacesInDeps(pkgFiles)...)
	securityFinding = append(securityFinding, checkTrufflehogActivity(root)...)
	securityFinding = append(securityFinding, checkSecretsExfiltration(root)...)
	securityFinding = append(securityFinding, checkMaliciousDomains(root)...)
	securityFinding = append(securityFinding, checkMaliciousRunners(root)...)
	securityFinding = append(securityFinding, checkShaiHuludRepos(root)...)
	securityFinding = append(securityFinding, checkMaliciousWorkflowFiles(root)...)

	totalDeps := 0
	for _, pkgPath := range pkgFiles {
		p, err := parsePackageJSON(pkgPath)
		if err != nil {
			continue
		}
		totalDeps += len(collectDependencies(p))
	}

	affectedCount := len(results)
	cleanCount := 0
	if totalDeps > affectedCount {
		cleanCount = totalDeps - affectedCount
	}

	summary := ScanSummary{
		TotalDependencies: totalDeps,
		AffectedCount:     affectedCount,
		CleanCount:        cleanCount,
		Results:           results,
		SecurityFindings:  securityFinding,
		ScannedFiles:      scannedFiles,
		ScanTimeMS:        time.Since(start).Milliseconds(),
		DBVersion:         masterPackages.Version,
		DBLastUpdated:     masterPackages.LastUpdated,
	}

	return summary
}
