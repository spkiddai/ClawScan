package models

import (
	"cmp"
	"slices"
	"time"
)

// ScanIssue records a non-fatal check failure. The scan still completes, but
// the result may have limited visibility for the affected area.
type ScanIssue struct {
	Check string `json:"check"`
	Error string `json:"error"`
}

// OpenClawInfo holds metadata about the OpenClaw installation.
// Installed is true only when openclaw.json was successfully parsed.
// The path fields and existence flags are only populated when the paths exist.
type OpenClawInfo struct {
	Installed         bool   `json:"installed"`
	Version           string `json:"version,omitempty"`
	HomeDir           string `json:"home_dir,omitempty"`
	HomeExists        bool   `json:"home_exists"`
	ConfigPath        string `json:"config_path,omitempty"`
	ConfigExists      bool   `json:"config_exists"`
	Workspace         string `json:"workspace,omitempty"`
	WorkspaceExists   bool   `json:"workspace_exists"`
	AgentsDir         string `json:"agents_dir,omitempty"`
	AgentSessionCount int    `json:"agent_session_count,omitempty"`
	IP                string `json:"ip,omitempty"`
	Port              uint16 `json:"port,omitempty"`
	Bind              string `json:"bind,omitempty"`
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

// ScanResult holds all data collected during a scan.
type ScanResult struct {
	Hostname     string          `json:"hostname"`
	OS           string          `json:"os"`
	Arch         string          `json:"arch"`
	ScanTime     time.Time       `json:"scan_time"`
	Issues       []ScanIssue     `json:"issues,omitempty"`
	OpenClawInfo *OpenClawInfo   `json:"openclaw_info,omitempty"`
	Channels     []Channel       `json:"channels,omitempty"`
	Models       []ModelProvider `json:"models,omitempty"`
	AuditResult  *AuditResult    `json:"audit_result,omitempty"`
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
	slices.SortStableFunc(r.Issues, func(a, b ScanIssue) int {
		if diff := cmp.Compare(a.Check, b.Check); diff != 0 {
			return diff
		}
		return cmp.Compare(a.Error, b.Error)
	})
}
