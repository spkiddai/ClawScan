package models

import (
	"cmp"
	"slices"
	"time"
)

// Severity represents the risk level of a finding.
type Severity int

const (
	Clean    Severity = 0
	Info     Severity = 1
	Warning  Severity = 2
	Critical Severity = 3
)

func (s Severity) String() string {
	switch s {
	case Clean:
		return "安全"
	case Info:
		return "提示"
	case Warning:
		return "警告"
	case Critical:
		return "严重"
	default:
		return "未知"
	}
}

// Category represents the type of detection check.
type Category string

const (
	CatInstallation Category = "installation"
	CatProcess      Category = "process"
	CatService      Category = "service"
	CatConfig       Category = "config"
	CatCredentials  Category = "credentials"
	CatNetwork      Category = "network"
)

func (c Category) Label() string {
	switch c {
	case CatInstallation:
		return "安装检测"
	case CatProcess:
		return "进程检测"
	case CatService:
		return "服务检测"
	case CatConfig:
		return "配置检测"
	case CatCredentials:
		return "凭证检测"
	case CatNetwork:
		return "网络检测"
	default:
		return string(c)
	}
}

// Finding represents a single detection result.
type Finding struct {
	Category    Category          `json:"category"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Remediation string            `json:"remediation,omitempty"`
	Severity    Severity          `json:"severity"`
	Details     map[string]string `json:"details,omitempty"`
}

// ScanIssue records a non-fatal check failure. The scan still completes, but
// the result may have limited visibility for the affected area.
type ScanIssue struct {
	Check string `json:"check"`
	Error string `json:"error"`
}

// OpenClawInfo holds metadata about the OpenClaw installation.
// Installed is true only when openclaw.json was successfully parsed.
// The path fields and existence flags are always populated regardless.
type OpenClawInfo struct {
	Installed       bool   `json:"installed"`
	Version         string `json:"version,omitempty"`
	HomeDir         string `json:"home_dir"`
	HomeExists      bool   `json:"home_exists"`
	ConfigPath      string `json:"config_path"`
	ConfigExists    bool   `json:"config_exists"`
	Workspace       string `json:"workspace"`
	WorkspaceExists bool   `json:"workspace_exists"`
	IP              string `json:"ip,omitempty"`
	Port            uint16 `json:"port,omitempty"`
	Bind            string `json:"bind,omitempty"`
}

// Channel represents a messaging channel configuration.
type Channel struct {
	Name             string   `json:"name"`
	Enabled          bool     `json:"enabled"`
	PrivateAllowlist []string `json:"private_allowlist"`
	GroupAllowlist   []string `json:"group_allowlist"`
}

// ModelProvider represents a model provider configuration.
type ModelProvider struct {
	Provider string   `json:"provider"`
	BaseURL  string   `json:"base_url"`
	Models   []string `json:"models"`
}

// AuditFinding represents a single finding from openclaw security audit.
type AuditFinding struct {
	CheckID     string `json:"checkId"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation"`
}

// AttackSurface represents an entry in the attack surface analysis.
type AttackSurface struct {
	Item   string `json:"item"`
	Status string `json:"status"`
}

// AuditResult holds the complete output of openclaw security audit.
type AuditResult struct {
	Findings       []AuditFinding  `json:"findings"`
	AttackSurfaces []AttackSurface `json:"-"`
}

// ScanResult holds all findings from a scan.
type ScanResult struct {
	Hostname     string          `json:"hostname"`
	OS           string          `json:"os"`
	Arch         string          `json:"arch"`
	ScanTime     time.Time       `json:"scan_time"`
	Findings     []Finding       `json:"findings"`
	Issues       []ScanIssue     `json:"issues,omitempty"`
	MaxSeverity  Severity        `json:"max_severity"`
	OpenClawInfo *OpenClawInfo   `json:"openclaw_info,omitempty"`
	Channels     []Channel       `json:"channels,omitempty"`
	Models       []ModelProvider `json:"models,omitempty"`
	AuditResult  *AuditResult    `json:"audit_result,omitempty"`
}

// AddFinding appends a finding and updates MaxSeverity.
func (r *ScanResult) AddFinding(f Finding) {
	r.Findings = append(r.Findings, f)
	if f.Severity > r.MaxSeverity {
		r.MaxSeverity = f.Severity
	}
}

// AddFindings appends findings in order and keeps the highest severity.
func (r *ScanResult) AddFindings(findings []Finding) {
	for _, finding := range findings {
		r.AddFinding(finding)
	}
}

// AddIssue records a non-fatal scan issue.
func (r *ScanResult) AddIssue(check string, err error) {
	if err == nil {
		return
	}
	r.Issues = append(r.Issues, ScanIssue{
		Check: check,
		Error: err.Error(),
	})
}

// CountBySeverity returns the number of findings at each severity level.
func (r *ScanResult) CountBySeverity() map[Severity]int {
	counts := map[Severity]int{
		Clean:    0,
		Info:     0,
		Warning:  0,
		Critical: 0,
	}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	return counts
}

// Finalize normalizes result ordering for stable console, JSON, and HTML
// output.
func (r *ScanResult) Finalize() {
	slices.SortStableFunc(r.Findings, compareFinding)
	slices.SortStableFunc(r.Issues, func(a, b ScanIssue) int {
		if diff := cmp.Compare(a.Check, b.Check); diff != 0 {
			return diff
		}
		return cmp.Compare(a.Error, b.Error)
	})
}

func compareFinding(a, b Finding) int {
	if diff := cmp.Compare(int(b.Severity), int(a.Severity)); diff != 0 {
		return diff
	}
	if diff := cmp.Compare(categoryRank(a.Category), categoryRank(b.Category)); diff != 0 {
		return diff
	}
	return cmp.Compare(a.Title, b.Title)
}

func categoryRank(category Category) int {
	switch category {
	case CatInstallation:
		return 0
	case CatProcess:
		return 1
	case CatService:
		return 2
	case CatConfig:
		return 3
	case CatCredentials:
		return 4
	case CatNetwork:
		return 5
	default:
		return 99
	}
}
