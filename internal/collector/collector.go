package collector

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spkiddai/clawscan/internal/models"
)

const gatewayPort = 18789

// permString returns the octal permission string (e.g. "700") for a path, or "" on error.
func permString(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%o", fi.Mode().Perm())
}

func isRunning() bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", gatewayPort), 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

type extendedOpenClawConfig struct {
	Version string `json:"version"`
	Gateway struct {
		IP   string `json:"ip"`
		Port uint16 `json:"port"`
		Bind string `json:"bind"`
		Auth struct {
			Mode  string `json:"mode"`
			Token string `json:"token"`
		} `json:"auth"`
	} `json:"gateway"`
	Channels map[string]struct {
		Enabled          bool     `json:"enabled"`
		PrivateAllowlist []string `json:"private_allowlist"`
		GroupAllowlist   []string `json:"group_allowlist"`
	} `json:"channels"`
	Models struct {
		Providers map[string]struct {
			BaseURL string `json:"baseUrl"`
			Models  []struct {
				ID string `json:"id"`
			} `json:"models"`
		} `json:"providers"`
	} `json:"models"`
}

// CollectNodeVersions returns the installed Node.js and npm version strings.
// Returns empty strings when not installed.
func CollectNodeVersions() (nodeVer, npmVer string) {
	if out, err := exec.Command("node", "--version").Output(); err == nil {
		nodeVer = strings.TrimSpace(string(out))
	}
	if out, err := exec.Command("npm", "--version").Output(); err == nil {
		npmVer = strings.TrimSpace(string(out))
	}
	return
}

// isOpenClawNpmInstalled checks whether openclaw is installed as a global npm package.
func isOpenClawNpmInstalled() bool {
	out, err := exec.Command("npm", "list", "-g", "openclaw", "--depth=0").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "openclaw@")
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

// openclawStatusIP tries to obtain the gateway IP from `openclaw status` output.
var reStatusURL = regexp.MustCompile(`(?:wss?|https?)://(\d+\.\d+\.\d+\.\d+):\d+`)
var reStatusIP = regexp.MustCompile(`\b(\d+\.\d+\.\d+\.\d+):\d+`)

func openclawStatusIP() string {
	out, err := exec.Command("openclaw", "status").Output()
	if err != nil {
		return ""
	}
	if m := reStatusURL.FindSubmatch(out); len(m) > 1 {
		return string(m[1])
	}
	if m := reStatusIP.FindSubmatch(out); len(m) > 1 {
		return string(m[1])
	}
	return ""
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
			info.HomeDirPerm = permString(homeDir)
		}
		if _, err := os.Stat(configPath); err == nil {
			info.ConfigExists = true
			info.ConfigPath = configPath
			info.ConfigPerm = permString(configPath)
		}
		agentsDir := filepath.Join(homeDir, "agents")
		if _, err := os.Stat(agentsDir); err == nil {
			info.AgentsDir = agentsDir
			matches, _ := filepath.Glob(filepath.Join(agentsDir, "*/sessions"))
			info.AgentSessionCount = len(matches)
		}
		// npm fallback: openclaw may be installed as a global npm package
		if isOpenClawNpmInstalled() {
			info.Installed = true
			info.Version = openclawVersion("")
		}
		info.Running = isRunning()
		return info, nil, nil
	}

	var config extendedOpenClawConfig
	if err := json.Unmarshal(data, &config); err != nil {
		// Config exists but unparseable — only populate existing paths
		if s, err := os.Stat(homeDir); err == nil && s.IsDir() {
			info.HomeExists = true
			info.HomeDir = homeDir
			info.HomeDirPerm = permString(homeDir)
		}
		info.ConfigExists = true
		info.ConfigPath = configPath
		info.ConfigPerm = permString(configPath)
		agentsDir := filepath.Join(homeDir, "agents")
		if _, err := os.Stat(agentsDir); err == nil {
			info.AgentsDir = agentsDir
			matches, _ := filepath.Glob(filepath.Join(agentsDir, "*/sessions"))
			info.AgentSessionCount = len(matches)
		}
		// npm fallback: openclaw may be installed as a global npm package
		if isOpenClawNpmInstalled() {
			info.Installed = true
			info.Version = openclawVersion("")
		}
		info.Running = isRunning()
		return info, nil, nil
	}

	// Config parsed successfully — OpenClaw is considered installed
	info.Installed = true
	info.Version = openclawVersion(config.Version)
	info.IP = config.Gateway.IP
	if info.IP == "" {
		// Fallback: try to get IP from openclaw status output
		if ip := openclawStatusIP(); ip != "" {
			info.IP = ip
		} else {
			info.IP = "127.0.0.1"
		}
	}
	info.Port = config.Gateway.Port
	info.Bind = config.Gateway.Bind
	info.AuthMode = config.Gateway.Auth.Mode
	// Compute token display value
	if config.Gateway.Auth.Mode != "token" {
		info.AuthToken = "无"
	} else {
		token := config.Gateway.Auth.Token
		if token == "" || strings.HasPrefix(token, "$") || strings.Contains(token, "$(") {
			info.AuthToken = "环境变量"
		} else {
			info.AuthToken = "****"
		}
	}

	// Set all path fields (they exist since config was read)
	info.HomeDir = homeDir
	info.HomeExists = true
	info.HomeDirPerm = permString(homeDir)
	info.ConfigPath = configPath
	info.ConfigExists = true
	info.ConfigPerm = permString(configPath)

	// Agent sessions
	agentsDir := filepath.Join(homeDir, "agents")
	info.AgentsDir = agentsDir
	if _, err := os.Stat(agentsDir); err == nil {
		matches, _ := filepath.Glob(filepath.Join(agentsDir, "*/sessions"))
		info.AgentSessionCount = len(matches)
	}
	info.Running = isRunning()

	// Channels: map of channel name → config
	var channels []models.Channel
	chNames := make([]string, 0, len(config.Channels))
	for name := range config.Channels {
		chNames = append(chNames, name)
	}
	sort.Strings(chNames)
	for _, name := range chNames {
		ch := config.Channels[name]
		private := ch.PrivateAllowlist
		if private == nil {
			private = []string{}
		}
		group := ch.GroupAllowlist
		if group == nil {
			group = []string{}
		}
		channels = append(channels, models.Channel{
			Name:             name,
			Enabled:          ch.Enabled,
			PrivateAllowlist: private,
			GroupAllowlist:   group,
		})
	}

	// Models: models.providers map
	var modelProviders []models.ModelProvider
	providerNames := make([]string, 0, len(config.Models.Providers))
	for name := range config.Models.Providers {
		providerNames = append(providerNames, name)
	}
	sort.Strings(providerNames)
	for _, name := range providerNames {
		p := config.Models.Providers[name]
		var modelIDs []string
		for _, m := range p.Models {
			if m.ID != "" {
				modelIDs = append(modelIDs, m.ID)
			}
		}
		if modelIDs == nil {
			modelIDs = []string{}
		}
		modelProviders = append(modelProviders, models.ModelProvider{
			Provider: name,
			BaseURL:  p.BaseURL,
			Models:   modelIDs,
		})
	}

	return info, channels, modelProviders
}
