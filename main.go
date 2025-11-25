package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

//go:embed db.json
var embeddedDB []byte

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

type MasterPackage struct {
	Name     string   `json:"name"`
	Severity Severity `json:"severity"`
}

type MasterPackages struct {
	Version     string          `json:"version"`
	LastUpdated string          `json:"lastUpdated"`
	Packages    []MasterPackage `json:"packages"`
	AttackInfo  any             `json:"attackInfo,omitempty"`
	Indicators  any             `json:"indicators,omitempty"`
}

type PackageJSON struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	Scripts              map[string]string `json:"scripts"`
}

type PackageLockV2Entry struct {
	Version      string                         `json:"version"`
	Dependencies map[string]*PackageLockV2Entry `json:"dependencies,omitempty"`
}

type PackageLock struct {
	Packages     map[string]*PackageLockV2Entry `json:"packages,omitempty"`
	Dependencies map[string]*PackageLockV2Entry `json:"dependencies,omitempty"`
}

type ScanResult struct {
	Package  string   `json:"package"`
	Version  string   `json:"version"`
	Severity Severity `json:"severity"`
	IsDirect bool     `json:"isDirect"`
	Location string   `json:"location"`
}

type SecurityFinding struct {
	Type        string   `json:"type"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Location    string   `json:"location"`
	Evidence    string   `json:"evidence,omitempty"`
	Line        int      `json:"line,omitempty"`
}

type ScanSummary struct {
	TotalDependencies int               `json:"totalDependencies"`
	AffectedCount     int               `json:"affectedCount"`
	CleanCount        int               `json:"cleanCount"`
	Results           []ScanResult      `json:"results"`
	SecurityFindings  []SecurityFinding `json:"securityFindings"`
	ScannedFiles      []string          `json:"scannedFiles"`
	ScanTimeMS        int64             `json:"scanTime"`
	DBVersion         string            `json:"dbVersion"`
	DBLastUpdated     string            `json:"dbLastUpdated"`
}

type SarifResult struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SarifRun `json:"runs"`
}

type SarifRun struct {
	Tool    SarifTool       `json:"tool"`
	Results []SarifResultIt `json:"results"`
}

type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

type SarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SarifRule `json:"rules"`
}

type SarifRule struct {
	ID                   string             `json:"id"`
	Name                 string             `json:"name"`
	ShortDescription     SarifText          `json:"shortDescription"`
	FullDescription      SarifText          `json:"fullDescription"`
	HelpURI              string             `json:"helpUri"`
	DefaultConfiguration SarifDefaultConfig `json:"defaultConfiguration"`
}

type SarifText struct {
	Text string `json:"text"`
}

type SarifDefaultConfig struct {
	Level string `json:"level"`
}

type SarifResultIt struct {
	RuleID   string             `json:"ruleId"`
	Level    string             `json:"level"`
	Message  SarifText          `json:"message"`
	Location []SarifLocationRef `json:"locations"`
}

type SarifLocationRef struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
	Region           *SarifRegion          `json:"region,omitempty"`
}

type SarifArtifactLocation struct {
	URI string `json:"uri"`
}

type SarifRegion struct {
	StartLine int `json:"startLine"`
}

var (
	masterPackages       MasterPackages
	affectedPackageNames map[string]Severity

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

func loadMasterPackagesFromBytes(data []byte) error {
	if err := json.Unmarshal(data, &masterPackages); err != nil {
		return err
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

func loadMasterPackages(path string) error {
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return loadMasterPackagesFromBytes(data)
	}
	if len(embeddedDB) == 0 {
		return fmt.Errorf("embedded compromised-packages.json is empty")
	}
	return loadMasterPackagesFromBytes(embeddedDB)
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

func scanPackageJSON(path string, isDirect bool) []ScanResult {
	p, err := parsePackageJSON(path)
	if err != nil {
		return nil
	}
	all := map[string]string{}
	maps.Copy(all, p.Dependencies)
	maps.Copy(all, p.DevDependencies)
	maps.Copy(all, p.PeerDependencies)
	maps.Copy(all, p.OptionalDependencies)
	var out []ScanResult
	for name, ver := range all {
		if isAffected(name) {
			if ver == "" {
				ver = "unknown"
			}
			out = append(out, ScanResult{
				Package:  name,
				Version:  ver,
				Severity: getPackageSeverity(name),
				IsDirect: isDirect,
				Location: path,
			})
		}
	}
	return out
}

func scanPackageLock(path string) []ScanResult {
	l, err := parsePackageLock(path)
	if err != nil {
		return nil
	}
	var res []ScanResult

	if l.Packages != nil {
		for pkgPath, entry := range l.Packages {
			if !strings.Contains(pkgPath, "node_modules/") {
				continue
			}
			parts := strings.Split(pkgPath, "node_modules/")
			name := parts[len(parts)-1]
			if isAffected(name) {
				ver := entry.Version
				if ver == "" {
					ver = "unknown"
				}
				isDirect := !strings.Contains(pkgPath, "node_modules/node_modules")
				res = append(res, ScanResult{
					Package:  name,
					Version:  ver,
					Severity: getPackageSeverity(name),
					IsDirect: isDirect,
					Location: path,
				})
			}
		}
	}

	if l.Dependencies != nil {
		var scanDeps func(deps map[string]*PackageLockV2Entry, isDirect bool)
		scanDeps = func(deps map[string]*PackageLockV2Entry, isDirect bool) {
			for name, entry := range deps {
				if isAffected(name) {
					ver := entry.Version
					if ver == "" {
						ver = "unknown"
					}
					res = append(res, ScanResult{
						Package:  name,
						Version:  ver,
						Severity: getPackageSeverity(name),
						IsDirect: isDirect,
						Location: path,
					})
				}
				if entry.Dependencies != nil {
					scanDeps(entry.Dependencies, false)
				}
			}
		}
		scanDeps(l.Dependencies, true)
	}

	return res
}

func scanYarnLock(path string) []ScanResult {
	pkgs, err := parseYarnLock(path)
	if err != nil {
		return nil
	}
	var res []ScanResult
	for name, ver := range pkgs {
		if isAffected(name) {
			res = append(res, ScanResult{
				Package:  name,
				Version:  ver,
				Severity: getPackageSeverity(name),
				IsDirect: false,
				Location: path,
			})
		}
	}
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

func checkSuspiciousScripts(path string) []SecurityFinding {
	p, err := parsePackageJSON(path)
	if err != nil || p.Scripts == nil {
		return nil
	}
	var findings []SecurityFinding

	for name, script := range p.Scripts {
		if script == "" {
			continue
		}
		if regexp.MustCompile(`(?i)setup_bun\.js`).MatchString(script) ||
			regexp.MustCompile(`(?i)bun_environment\.js`).MatchString(script) {
			findings = append(findings, SecurityFinding{
				Type:        "suspicious-script",
				Severity:    SeverityCritical,
				Title:       fmt.Sprintf(`Shai-Hulud malicious script in "%s"`, name),
				Description: fmt.Sprintf(`The "%s" script contains a reference to known Shai-Hulud malicious files. This is a strong indicator of compromise.`, name),
				Location:    path,
				Evidence:    fmt.Sprintf(`"%s": "%s"`, name, script),
			})
			continue
		}

		for _, pat := range suspiciousScriptPatterns {
			if pat.re.MatchString(script) {
				isCritical := (name == "preinstall" || name == "postinstall" ||
					name == "prepare" || name == "prepublish") &&
					(regexp.MustCompile(`(?i)curl|wget|eval`).MatchString(script))

				sev := SeverityHigh
				if isCritical {
					sev = SeverityCritical
				}

				evidence := script
				if len(evidence) > 200 {
					evidence = evidence[:200] + "..."
				}

				findings = append(findings, SecurityFinding{
					Type:        "suspicious-script",
					Severity:    sev,
					Title:       fmt.Sprintf(`Suspicious "%s" script`, name),
					Description: pat.description + ". This pattern is commonly used in supply chain attacks.",
					Location:    path,
					Evidence:    fmt.Sprintf(`"%s": "%s"`, name, evidence),
				})
				break
			}
		}
	}

	return findings
}

func checkTrufflehogActivity(root string) []SecurityFinding {
	var findings []SecurityFinding
	var suspiciousFiles []string

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
				name := e.Name()
				if strings.Contains(strings.ToLower(name), "trufflehog") ||
					name == "bun_environment.js" || name == "setup_bun.js" {
					suspiciousFiles = append(suspiciousFiles, full)
				}

				if matched, _ := filepath.Match("*.sh", name); matched ||
					strings.HasSuffix(name, ".js") ||
					strings.HasSuffix(name, ".ts") ||
					strings.HasSuffix(name, ".mjs") ||
					strings.HasSuffix(name, ".cjs") {

					if isExcludedPath(full) {
						continue
					}
					content, err := os.ReadFile(full)
					if err != nil {
						continue
					}
					s := string(content)
					if isDetectorSourceCode(s) {
						continue
					}

					for _, pat := range trufflehogPatterns {
						if pat.re.MatchString(s) {
							findings = append(findings, SecurityFinding{
								Type:        "trufflehog-activity",
								Severity:    SeverityCritical,
								Title:       "TruffleHog activity detected",
								Description: pat.description + ". This may indicate automated credential theft as part of the Shai-Hulud attack.",
								Location:    full,
								Evidence:    pat.re.String(),
							})
							break
						}
					}

					for _, pat := range webhookExfilPatterns {
						if pat.re.MatchString(s) {
							findings = append(findings, SecurityFinding{
								Type:        "secrets-exfiltration",
								Severity:    SeverityCritical,
								Title:       "Data exfiltration endpoint detected",
								Description: pat.description + ". This endpoint may be used to exfiltrate stolen credentials.",
								Location:    full,
								Evidence:    pat.re.String(),
							})
							break
						}
					}
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

	for _, f := range suspiciousFiles {
		basename := filepath.Base(f)
		findings = append(findings, SecurityFinding{
			Type:        "trufflehog-activity",
			Severity:    SeverityCritical,
			Title:       fmt.Sprintf("Suspicious file: %s", basename),
			Description: fmt.Sprintf(`Found file "%s" which is associated with the Shai-Hulud attack. This file may download and execute TruffleHog for credential theft.`, basename),
			Location:    f,
		})
	}

	return findings
}

func checkSecretsExfiltration(root string) []SecurityFinding {
	var findings []SecurityFinding
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
				name := e.Name()
				lower := strings.ToLower(name)
				if name == "actionsSecrets.json" {
					findings = append(findings, SecurityFinding{
						Type:        "secrets-exfiltration",
						Severity:    SeverityCritical,
						Title:       "Secrets exfiltration file detected",
						Description: `Found "actionsSecrets.json" which is used by the Shai-Hulud attack to store stolen credentials with double Base64 encoding before exfiltration.`,
						Location:    full,
					})
				}

				knownMalicious := []string{
					"cloud.json",
					"contents.json",
					"environment.json",
					"trufflesecrets.json",
					"trufflehog_output.json",
				}
				for _, k := range knownMalicious {
					if lower == k {
						findings = append(findings, SecurityFinding{
							Type:        "secrets-exfiltration",
							Severity:    SeverityCritical,
							Title:       fmt.Sprintf("Shai-Hulud output file: %s", name),
							Description: fmt.Sprintf(`Found "%s" which is a known output file from the Shai-Hulud attack containing harvested credentials or environment data.`, name),
							Location:    full,
						})
					}
				}

				if name == "bun_environment.js" {
					info, err := os.Stat(full)
					desc := `Found "bun_environment.js" which is the main obfuscated payload used by the Shai-Hulud attack.`
					evidence := ""
					if err == nil {
						sizeMB := float64(info.Size()) / (1024 * 1024)
						desc = fmt.Sprintf(`Found "bun_environment.js" (%.2fMB). This is the main obfuscated payload used by the Shai-Hulud attack to execute TruffleHog for credential theft.`, sizeMB)
						evidence = fmt.Sprintf("File size: %.2fMB", sizeMB)
					}
					findings = append(findings, SecurityFinding{
						Type:        "trufflehog-activity",
						Severity:    SeverityCritical,
						Title:       "Shai-Hulud payload file: bun_environment.js",
						Description: desc,
						Location:    full,
						Evidence:    evidence,
					})
				}

				if regexp.MustCompile(`(?i)secrets?\.json$`).MatchString(name) ||
					regexp.MustCompile(`(?i)credentials?\.json$`).MatchString(name) ||
					regexp.MustCompile(`(?i)exfil.*\.json$`).MatchString(name) {

					data, err := os.ReadFile(full)
					if err != nil {
						continue
					}
					if regexp.MustCompile(`(?m)^[A-Za-z0-9+/=]{100,}$`).Match(data) {
						findings = append(findings, SecurityFinding{
							Type:        "secrets-exfiltration",
							Severity:    SeverityHigh,
							Title:       "Potential secrets file with encoded data",
							Description: fmt.Sprintf(`Found "%s" containing what appears to be Base64 encoded data. This may be exfiltrated credentials.`, name),
							Location:    full,
						})
					}
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
	return findings
}

func checkMaliciousRunners(root string) []SecurityFinding {
	var findings []SecurityFinding
	workflowDirs := []string{
		filepath.Join(root, ".github", "workflows"),
		filepath.Join(root, ".github"),
	}
	detectorWorkflowRe := regexp.MustCompile(`(?i)gensecaihq\/Shai-Hulud-2\.0-Detector|Shai-Hulud.*Detector|shai-hulud-check|shai-hulud.*security`)

	for _, dir := range workflowDirs {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.Type().IsRegular() {
				continue
			}
			if !(strings.HasSuffix(e.Name(), ".yml") || strings.HasSuffix(e.Name(), ".yaml")) {
				continue
			}
			full := filepath.Join(dir, e.Name())

			for _, pat := range maliciousWorkflowPatterns {
				if pat.re.MatchString(e.Name()) {
					findings = append(findings, SecurityFinding{
						Type:        "malicious-runner",
						Severity:    SeverityCritical,
						Title:       fmt.Sprintf("Suspicious workflow file: %s", e.Name()),
						Description: pat.description + ". This workflow filename matches patterns used by the Shai-Hulud attack for credential theft.",
						Location:    full,
						Evidence:    e.Name(),
					})
				}
			}

			content, err := os.ReadFile(full)
			if err != nil {
				continue
			}
			s := string(content)

			if detectorWorkflowRe.MatchString(s) || detectorWorkflowRe.MatchString(e.Name()) {
				continue
			}

			for _, pat := range maliciousRunnerPatterns {
				if pat.re.MatchString(s) {
					findings = append(findings, SecurityFinding{
						Type:        "malicious-runner",
						Severity:    SeverityCritical,
						Title:       "Malicious GitHub Actions runner detected",
						Description: pat.description + ". The SHA1HULUD runner is used by the Shai-Hulud attack to execute credential theft in CI/CD environments.",
						Location:    full,
						Evidence:    pat.re.String(),
					})
				}
			}

			for _, pat := range shaiHuludRepoPatterns {
				if pat.re.MatchString(s) {
					withoutDetector := detectorWorkflowRe.ReplaceAllString(s, "")
					if pat.re.MatchString(withoutDetector) {
						findings = append(findings, SecurityFinding{
							Type:        "shai-hulud-repo",
							Severity:    SeverityCritical,
							Title:       "Shai-Hulud reference in workflow",
							Description: pat.description + ". This workflow may be configured to exfiltrate data to attacker-controlled repositories.",
							Location:    full,
							Evidence:    pat.re.String(),
						})
					}
				}
			}
		}
	}
	return findings
}

func checkShaiHuludRepos(root string) []SecurityFinding {
	var findings []SecurityFinding

	gitConfigPath := filepath.Join(root, ".git", "config")
	if data, err := os.ReadFile(gitConfigPath); err == nil {
		s := string(data)
		if strings.Contains(s, "Shai-Hulud-2.0-Detector") || strings.Contains(s, "gensecaihq") {
		} else {
			for _, pat := range shaiHuludRepoPatterns {
				if pat.re.MatchString(s) {
					findings = append(findings, SecurityFinding{
						Type:        "shai-hulud-repo",
						Severity:    SeverityCritical,
						Title:       "Shai-Hulud repository reference in git config",
						Description: pat.description + ". Your repository may have been configured to push to an attacker-controlled remote.",
						Location:    gitConfigPath,
					})
				}
			}
		}
	}

	pkgs := findPackageJSONFiles(root)
	for _, p := range pkgs {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		s := string(data)
		if strings.Contains(s, "gensecaihq/Shai-Hulud-2.0-Detector") ||
			strings.Contains(s, "shai-hulud-detector") {
			continue
		}
		for _, pat := range shaiHuludRepoPatterns {
			if pat.re.MatchString(s) {
				withoutDetector := regexp.MustCompile(`(?i)gensecaihq\/Shai-Hulud-2\.0-Detector|shai-hulud-detector`).ReplaceAllString(s, "")
				if pat.re.MatchString(withoutDetector) {
					findings = append(findings, SecurityFinding{
						Type:        "shai-hulud-repo",
						Severity:    SeverityHigh,
						Title:       "Shai-Hulud reference in package.json",
						Description: pat.description + ". Package may be configured to reference attacker infrastructure.",
						Location:    p,
					})
				}
			}
		}
	}

	return findings
}

func checkAffectedNamespaces(path string) []SecurityFinding {
	p, err := parsePackageJSON(path)
	if err != nil {
		return nil
	}
	all := map[string]string{}
	maps.Copy(all, p.Dependencies)
	maps.Copy(all, p.DevDependencies)
	maps.Copy(all, p.PeerDependencies)
	maps.Copy(all, p.OptionalDependencies)

	var findings []SecurityFinding
	for name, ver := range all {
		if isAffected(name) {
			continue
		}
		for _, ns := range affectedNamespaces {
			if strings.HasPrefix(name, ns+"/") {
				if strings.HasPrefix(ver, "^") || strings.HasPrefix(ver, "~") {
					findings = append(findings, SecurityFinding{
						Type:        "compromised-package",
						Severity:    SeverityLow,
						Title:       "Package from affected namespace with semver range",
						Description: fmt.Sprintf(`"%s" is from the %s namespace which has known compromised packages. The version pattern "%s" could auto-update to a compromised version during npm update.`, name, ns, ver),
						Location:    path,
						Evidence:    fmt.Sprintf(`"%s": "%s"`, name, ver),
					})
				}
				break
			}
		}
	}
	return findings
}

func checkSuspiciousBranches(root string) []SecurityFinding {
	var findings []SecurityFinding
	headsPath := filepath.Join(root, ".git", "refs", "heads")
	info, err := os.Stat(headsPath)
	if err != nil || !info.IsDir() {
		return findings
	}
	entries, err := os.ReadDir(headsPath)
	if err != nil {
		return findings
	}
	for _, e := range entries {
		name := e.Name()
		for _, pat := range shaiHuludRepoPatterns {
			if pat.re.MatchString(name) {
				findings = append(findings, SecurityFinding{
					Type:        "shai-hulud-repo",
					Severity:    SeverityMedium,
					Title:       fmt.Sprintf("Suspicious git branch: %s", name),
					Description: pat.description + ". This branch name is associated with the Shai-Hulud attack campaign.",
					Location:    filepath.Join(headsPath, name),
				})
			}
		}
	}
	return findings
}

func runScan(root string, scanLockfiles bool) ScanSummary {
	start := time.Now()
	var allResults []ScanResult
	var allFindings []SecurityFinding
	var scanned []string
	seenPkgs := make(map[string]bool)
	seenFindings := make(map[string]bool)

	pjsonFiles := findPackageJSONFiles(root)
	for _, f := range pjsonFiles {
		scanned = append(scanned, f)
		results := scanPackageJSON(f, true)
		for _, r := range results {
			key := r.Package + "@" + r.Version
			if !seenPkgs[key] {
				seenPkgs[key] = true
				allResults = append(allResults, r)
			}
		}
		for _, fd := range checkSuspiciousScripts(f) {
			key := fd.Type + ":" + fd.Location + ":" + fd.Title
			if !seenFindings[key] {
				seenFindings[key] = true
				allFindings = append(allFindings, fd)
			}
		}
		for _, fd := range checkAffectedNamespaces(f) {
			key := fd.Type + ":" + fd.Location + ":" + fd.Title
			if !seenFindings[key] {
				seenFindings[key] = true
				allFindings = append(allFindings, fd)
			}
		}
	}

	if scanLockfiles {
		lockfiles := findLockfiles(root)
		for _, f := range lockfiles {
			scanned = append(scanned, f)
			var results []ScanResult
			switch {
			case strings.HasSuffix(f, "package-lock.json") || strings.HasSuffix(f, "npm-shrinkwrap.json"):
				results = scanPackageLock(f)
			case strings.HasSuffix(f, "yarn.lock"):
				results = scanYarnLock(f)
			default:
			}
			for _, r := range results {
				key := r.Package + "@" + r.Version
				if !seenPkgs[key] {
					seenPkgs[key] = true
					allResults = append(allResults, r)
				}
			}
		}
	}

	advChecks := []func(string) []SecurityFinding{
		checkTrufflehogActivity,
		checkSecretsExfiltration,
		checkMaliciousRunners,
		checkShaiHuludRepos,
		checkSuspiciousBranches,
	}

	for _, fn := range advChecks {
		fd := fn(root)
		for _, f := range fd {
			key := f.Type + ":" + f.Location + ":" + f.Title
			if !seenFindings[key] {
				seenFindings[key] = true
				allFindings = append(allFindings, f)
			}
		}
	}

	severityOrder := map[Severity]int{
		SeverityCritical: 0,
		SeverityHigh:     1,
		SeverityMedium:   2,
		SeverityLow:      3,
	}
	sort.Slice(allResults, func(i, j int) bool {
		return severityOrder[allResults[i].Severity] < severityOrder[allResults[j].Severity]
	})
	sort.Slice(allFindings, func(i, j int) bool {
		return severityOrder[allFindings[i].Severity] < severityOrder[allFindings[j].Severity]
	})

	affected := len(allResults)
	totalDeps := len(seenPkgs)
	clean := max(totalDeps-affected, 0)

	return ScanSummary{
		TotalDependencies: totalDeps,
		AffectedCount:     affected,
		CleanCount:        clean,
		Results:           allResults,
		SecurityFindings:  allFindings,
		ScannedFiles:      scanned,
		ScanTimeMS:        time.Since(start).Milliseconds(),
		DBVersion:         masterPackages.Version,
		DBLastUpdated:     masterPackages.LastUpdated,
	}
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
		case SeverityMedium:
			level = "note"
		case SeverityLow:
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
		dbPath       string
		format       string
		failOnAny    bool
		failOnCrit   bool
		failOnHigh   bool
		sarifOutPath string
	)
	flag.StringVar(&dir, "dir", ".", "Directory to scan")
	flag.StringVar(&dbPath, "db", "", "Path to compromised packages database (JSON), overrides embedded DB if set")
	flag.StringVar(&format, "format", "text", "Output format: text|json|sarif")
	flag.BoolVar(&failOnAny, "fail-on-any", false, "Exit non-zero if any issues are found")
	flag.BoolVar(&failOnCrit, "fail-on-critical", false, "Exit non-zero if any critical issues are found")
	flag.BoolVar(&failOnHigh, "fail-on-high", false, "Exit non-zero if any high/critical issues are found")
	flag.StringVar(&sarifOutPath, "sarif-out", "shai-hulud-results.sarif", "Path to write SARIF report (for format=sarif)")
	flag.Parse()

	if err := loadMasterPackages(dbPath); err != nil {
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
