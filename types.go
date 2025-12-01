package main

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

// SARIF

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
