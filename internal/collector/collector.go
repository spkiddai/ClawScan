package collector

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spkiddai/clawscan/internal/models"
)

type extendedOpenClawConfig struct {
	Version string `json:"version"`
	Gateway struct {
		IP   string `json:"ip"`
		Port uint16 `json:"port"`
		Bind string `json:"bind"`
	} `json:"gateway"`
	Channels []struct {
		Name             string   `json:"name"`
		Enabled          bool     `json:"enabled"`
		PrivateAllowlist []string `json:"private_allowlist"`
		GroupAllowlist   []string `json:"group_allowlist"`
	} `json:"channels"`
	Models []struct {
		Provider string   `json:"provider"`
		BaseURL  string   `json:"base_url"`
		Models   []string `json:"models"`
	} `json:"models"`
}

// openclawVersion tries to get the OpenClaw version string.
// It first uses the value from the parsed config, then falls back to `openclaw --version`.
func openclawVersion(fromConfig string) string {
	if fromConfig != "" {
		return fromConfig
	}
	out, err := exec.Command("openclaw", "--version").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// CollectOpenClawInfo returns OpenClawInfo, channels, and model providers.
// When OpenClaw is not installed (config missing/unparseable), only path fields
// that actually exist on disk are populated.
// When installed, all path fields are set plus agent session information.
func CollectOpenClawInfo(homeDir string) (*models.OpenClawInfo, []models.Channel, []models.ModelProvider) {
	configPath := filepath.Join(homeDir, "openclaw.json")

	info := &models.OpenClawInfo{}

	// Try to parse config; if it fails, populate only existing paths
	data, err := os.ReadFile(configPath)
	if err != nil {
		// Not installed — only populate fields that exist on disk
		if s, err := os.Stat(homeDir); err == nil && s.IsDir() {
			info.HomeExists = true
			info.HomeDir = homeDir
		}
		if _, err := os.Stat(configPath); err == nil {
			info.ConfigExists = true
			info.ConfigPath = configPath
		}
		workspacePath := filepath.Join(homeDir, "workspace")
		if s, err := os.Stat(workspacePath); err == nil && s.IsDir() {
			info.WorkspaceExists = true
			info.Workspace = workspacePath
		}
		agentsDir := filepath.Join(homeDir, "agents")
		if _, err := os.Stat(agentsDir); err == nil {
			info.AgentsDir = agentsDir
			matches, _ := filepath.Glob(filepath.Join(agentsDir, "*/sessions"))
			info.AgentSessionCount = len(matches)
		}
		return info, nil, nil
	}

	var config extendedOpenClawConfig
	if err := json.Unmarshal(data, &config); err != nil {
		// Config exists but unparseable — only populate existing paths
		if s, err := os.Stat(homeDir); err == nil && s.IsDir() {
			info.HomeExists = true
			info.HomeDir = homeDir
		}
		info.ConfigExists = true
		info.ConfigPath = configPath
		workspacePath := filepath.Join(homeDir, "workspace")
		if s, err := os.Stat(workspacePath); err == nil && s.IsDir() {
			info.WorkspaceExists = true
			info.Workspace = workspacePath
		}
		agentsDir := filepath.Join(homeDir, "agents")
		if _, err := os.Stat(agentsDir); err == nil {
			info.AgentsDir = agentsDir
			matches, _ := filepath.Glob(filepath.Join(agentsDir, "*/sessions"))
			info.AgentSessionCount = len(matches)
		}
		return info, nil, nil
	}

	// Config parsed successfully — OpenClaw is considered installed
	info.Installed = true
	info.Version = openclawVersion(config.Version)
	info.IP = config.Gateway.IP
	if info.IP == "" {
		info.IP = "127.0.0.1"
	}
	info.Port = config.Gateway.Port
	info.Bind = config.Gateway.Bind

	// Set all path fields (they exist since config was read)
	info.HomeDir = homeDir
	info.HomeExists = true
	info.ConfigPath = configPath
	info.ConfigExists = true
	workspacePath := filepath.Join(homeDir, "workspace")
	if s, err := os.Stat(workspacePath); err == nil && s.IsDir() {
		info.WorkspaceExists = true
		info.Workspace = workspacePath
	}

	// Agent sessions
	agentsDir := filepath.Join(homeDir, "agents")
	info.AgentsDir = agentsDir
	if _, err := os.Stat(agentsDir); err == nil {
		matches, _ := filepath.Glob(filepath.Join(agentsDir, "*/sessions"))
		info.AgentSessionCount = len(matches)
	}

	var channels []models.Channel
	for _, ch := range config.Channels {
		private := ch.PrivateAllowlist
		if private == nil {
			private = []string{}
		}
		group := ch.GroupAllowlist
		if group == nil {
			group = []string{}
		}
		channels = append(channels, models.Channel{
			Name:             ch.Name,
			Enabled:          ch.Enabled,
			PrivateAllowlist: private,
			GroupAllowlist:   group,
		})
	}

	var modelProviders []models.ModelProvider
	for _, m := range config.Models {
		mods := m.Models
		if mods == nil {
			mods = []string{}
		}
		modelProviders = append(modelProviders, models.ModelProvider{
			Provider: m.Provider,
			BaseURL:  m.BaseURL,
			Models:   mods,
		})
	}

	return info, channels, modelProviders
}
