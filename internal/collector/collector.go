package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spkiddai/clawscan/internal/models"
)

// permString returns the octal permission string (e.g. "700") for a path, or "" on error.
func permString(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%o", fi.Mode().Perm())
}

const (
	cmdTimeout      = 15 * time.Second // general openclaw commands
	cmdTimeoutQuick = 5 * time.Second  // fast system commands (which, pgrep, node --version)
)

// cmdOutputWithTimeout runs a command with the given timeout and returns stdout.
// Non-zero exit codes are tolerated (output is still returned).
func cmdOutputWithTimeout(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return out, nil
		}
		return nil, err
	}
	return out, nil
}

// cmdOutput runs a command with the default timeout and returns stdout.
func cmdOutput(name string, args ...string) ([]byte, error) {
	return cmdOutputWithTimeout(cmdTimeout, name, args...)
}

// isRunning checks whether the openclaw process is currently running.
func isRunning() bool {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeoutQuick)
	defer cancel()
	switch runtime.GOOS {
	case "windows":
		out, err := exec.CommandContext(ctx, "tasklist", "/FI", "IMAGENAME eq openclaw.exe", "/NH").Output()
		return err == nil && strings.Contains(string(out), "openclaw.exe")
	default:
		return exec.CommandContext(ctx, "pgrep", "-f", "openclaw").Run() == nil
	}
}

// envDisplay converts a config value that references an environment variable.
// "${FOO}" → "环境变量(FOO)", "$FOO" or "$(FOO)" → "环境变量", others unchanged.
func envDisplay(v string) string {
	if strings.HasPrefix(v, "${") && strings.HasSuffix(v, "}") {
		return "环境变量(" + v[2:len(v)-1] + ")"
	}
	if strings.HasPrefix(v, "$") || strings.Contains(v, "$(") {
		return "环境变量"
	}
	return v
}

// reLogPrefix matches timestamp-prefixed log lines from openclaw output.
var reLogPrefix = regexp.MustCompile(`^\d{2,4}[-T:/]\d{2}`)

// isLogLine returns true for lines that are log/warning noise, not real content.
func isLogLine(s string) bool {
	if reLogPrefix.MatchString(s) {
		return true
	}
	for _, prefix := range []string{"Failed to ", "Error:", "Warning:", "INFO ", "WARN ", "DEBUG "} {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// firstContentLine extracts the first non-log, non-empty line from command output.
func firstContentLine(out []byte) string {
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || isLogLine(line) {
			continue
		}
		return line
	}
	return ""
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
		Enabled     bool     `json:"enabled"`
		AllowFrom   []string `json:"allowFrom"`
		GroupPolicy string   `json:"groupPolicy"`
		Groups      struct {
			GroupAllowFrom []string `json:"groupAllowFrom"`
		} `json:"groups"`
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
	if out, err := cmdOutputWithTimeout(cmdTimeoutQuick, "node", "--version"); err == nil {
		nodeVer = strings.TrimSpace(string(out))
	}
	if out, err := cmdOutputWithTimeout(cmdTimeoutQuick, "npm", "--version"); err == nil {
		npmVer = strings.TrimSpace(string(out))
	}
	return
}

// isOpenClawNpmInstalled checks whether openclaw is installed as a global npm package.
func isOpenClawNpmInstalled() bool {
	out, err := cmdOutputWithTimeout(cmdTimeout, "npm", "list", "-g", "openclaw", "--depth=0")
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "openclaw@")
}

// isOpenClawBinaryInstalled checks whether the openclaw binary is on PATH.
func isOpenClawBinaryInstalled() bool {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeoutQuick)
	defer cancel()
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "where", "openclaw")
	} else {
		cmd = exec.CommandContext(ctx, "which", "openclaw")
	}
	return cmd.Run() == nil
}

// isOpenClawInstalled returns true if openclaw is installed: npm first, then binary on PATH.
func isOpenClawInstalled() bool {
	if isOpenClawNpmInstalled() {
		return true
	}
	return isOpenClawBinaryInstalled()
}

// openclawVersion tries to get the OpenClaw version string.
// It first uses the value from the parsed config, then falls back to `openclaw --version`.
func openclawVersion(fromConfig string) string {
	if fromConfig != "" {
		return fromConfig
	}
	out, err := cmdOutput("openclaw", "--version")
	if err != nil || len(out) == 0 {
		return ""
	}
	return firstContentLine(out)
}

// openclawStatusGateway tries to obtain the gateway IP and port from `openclaw status` output.
var reStatusURL = regexp.MustCompile(`(?:wss?|https?)://(\d+\.\d+\.\d+\.\d+):(\d+)`)
var reStatusIP = regexp.MustCompile(`\b(\d+\.\d+\.\d+\.\d+):(\d+)`)

func openclawStatusGateway() (ip string, port uint16) {
	out, err := cmdOutput("openclaw", "status")
	if err != nil || len(out) == 0 {
		return "", 0
	}
	if m := reStatusURL.FindSubmatch(out); len(m) > 2 {
		p, _ := strconv.ParseUint(string(m[2]), 10, 16)
		return string(m[1]), uint16(p)
	}
	if m := reStatusIP.FindSubmatch(out); len(m) > 2 {
		p, _ := strconv.ParseUint(string(m[2]), 10, 16)
		return string(m[1]), uint16(p)
	}
	return "", 0
}

// CollectOpenClawInfo returns OpenClawInfo, channels, and model providers.
func CollectOpenClawInfo(homeDir string) (*models.OpenClawInfo, []models.Channel, []models.ModelProvider) {
	info := &models.OpenClawInfo{}

	// Step 1: Determine installation status (npm first, then binary)
	info.Installed = isOpenClawInstalled()
	if info.Installed {
		info.InstallStatus = "已安装"
		info.Version = openclawVersion("")
	} else {
		info.InstallStatus = "未安装"
		// Populate existing path fields for diagnostics even when not installed
		if s, err := os.Stat(homeDir); err == nil && s.IsDir() {
			info.HomeExists = true
			info.HomeDir = homeDir
			info.HomeDirPerm = permString(homeDir)
		}
		defaultConfig := filepath.Join(homeDir, "openclaw.json")
		if _, err := os.Stat(defaultConfig); err == nil {
			info.ConfigExists = true
			info.ConfigPath = defaultConfig
			info.ConfigPerm = permString(defaultConfig)
		}
		agentsDir := filepath.Join(homeDir, "agents")
		if _, err := os.Stat(agentsDir); err == nil {
			matches, _ := filepath.Glob(filepath.Join(agentsDir, "*/sessions"))
			info.AgentSessionCount = len(matches)
		}
		info.Running = isRunning()
		return info, nil, nil
	}

	// Step 2: Check running status
	info.Running = isRunning()

	// Step 3: Config file path
	configPath := filepath.Join(homeDir, "openclaw.json")

	// Step 4: Populate home + config path fields
	if s, err := os.Stat(homeDir); err == nil && s.IsDir() {
		info.HomeExists = true
		info.HomeDir = homeDir
		info.HomeDirPerm = permString(homeDir)
	}
	info.ConfigPath = configPath
	if _, err := os.Stat(configPath); err == nil {
		info.ConfigExists = true
		info.ConfigPerm = permString(configPath)
	}

	// Agent sessions
	agentsDir := filepath.Join(homeDir, "agents")
	if _, err := os.Stat(agentsDir); err == nil {
		matches, _ := filepath.Glob(filepath.Join(agentsDir, "*/sessions"))
		info.AgentSessionCount = len(matches)
	}

	// Step 5: Parse config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return info, nil, nil
	}
	var config extendedOpenClawConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return info, nil, nil
	}

	// Override version from config if available
	if config.Version != "" {
		info.Version = config.Version
	}

	info.IP = envDisplay(config.Gateway.IP)
	info.Port = config.Gateway.Port
	info.Bind = envDisplay(config.Gateway.Bind)

	// When running and IP or Port is missing from config, query `openclaw status`
	if info.Running && (info.IP == "" || info.Port == 0) {
		statusIP, statusPort := openclawStatusGateway()
		if info.IP == "" {
			info.IP = statusIP
		}
		if info.Port == 0 {
			info.Port = statusPort
		}
	}
	info.AuthMode = config.Gateway.Auth.Mode

	// Channels
	var channels []models.Channel
	chNames := make([]string, 0, len(config.Channels))
	for name := range config.Channels {
		chNames = append(chNames, name)
	}
	sort.Strings(chNames)
	for _, name := range chNames {
		ch := config.Channels[name]
		channels = append(channels, models.Channel{
			Name:                  name,
			Enabled:               ch.Enabled,
			PrivateAllowlistCount: len(ch.AllowFrom),
			GroupPolicy:           ch.GroupPolicy,
			GroupAllowlistCount:   len(ch.Groups.GroupAllowFrom),
		})
	}

	// Models
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
			BaseURL:  envDisplay(p.BaseURL),
			Models:   modelIDs,
		})
	}

	return info, channels, modelProviders
}
