package collector

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spkiddai/clawscan/internal/models"
	"github.com/spkiddai/clawscan/internal/platform"
)

const (
	gatewayPort = 18789
	dialTimeout = 2 * time.Second
)

// dialFunc abstracts net.DialTimeout for testing.
type dialFunc func(network, address string, timeout time.Duration) (net.Conn, error)

// ScanFilesystem checks for OpenClaw installation artifacts on the filesystem.
func ScanFilesystem(homeDir string) ([]models.Finding, error) {
	var findings []models.Finding

	// Check main directory
	if info, err := os.Stat(homeDir); err == nil && info.IsDir() {
		findings = append(findings, models.Finding{
			Category:    models.CatInstallation,
			Title:       "检测到 OpenClaw 安装",
			Description: "OpenClaw 主目录已存在。",
			Remediation: "如非授权安装，请删除该目录并审查安装来源。如为合法使用，请确保版本为最新并定期审计配置。",
			Severity:    models.Info,
			Details:     map[string]string{"path": homeDir},
		})
	} else {
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return findings, err
		}
		return findings, nil // No installation found, skip remaining checks
	}

	// Check config file
	configPath := filepath.Join(homeDir, "openclaw.json")
	if _, err := os.Stat(configPath); err == nil {
		findings = append(findings, models.Finding{
			Category:    models.CatInstallation,
			Title:       "发现配置文件",
			Description: "OpenClaw 配置文件已存在。",
			Remediation: "检查配置文件内容，确保未开启危险选项（如 Shell 访问、外部网络绑定）。建议将配置纳入变更管理。",
			Severity:    models.Info,
			Details:     map[string]string{"path": configPath},
		})
	}

	// Check workspace directory
	workspacePath := filepath.Join(homeDir, "workspace")
	if info, err := os.Stat(workspacePath); err == nil && info.IsDir() {
		findings = append(findings, models.Finding{
			Category:    models.CatInstallation,
			Title:       "发现工作区目录",
			Description: "OpenClaw 工作区目录已存在。",
			Remediation: "审查工作区中的文件内容，确认无敏感数据泄露。如不再使用，建议清理该目录。",
			Severity:    models.Info,
			Details:     map[string]string{"path": workspacePath},
		})
	}

	// Check agent sessions
	agentsPath := filepath.Join(homeDir, "agents")
	if info, err := os.Stat(agentsPath); err == nil && info.IsDir() {
		matches, _ := filepath.Glob(filepath.Join(agentsPath, "*/sessions"))
		if len(matches) > 0 {
			findings = append(findings, models.Finding{
				Category:    models.CatInstallation,
				Title:       "发现 Agent 会话",
				Description: "存在活跃或历史的 Agent 会话目录。",
				Remediation: "审查各 Agent 会话记录，确认无异常操作。定期清理历史会话，避免敏感信息残留。",
				Severity:    models.Info,
				Details:     map[string]string{"count": strconv.Itoa(len(matches)), "path": agentsPath},
			})
		}
	}

	// Check plugin artifacts
	pluginIndicators := []string{
		filepath.Join(homeDir, "index.js"),
		filepath.Join(homeDir, "plugin-sdk"),
	}
	for _, path := range pluginIndicators {
		if _, err := os.Stat(path); err == nil {
			findings = append(findings, models.Finding{
				Category:    models.CatInstallation,
				Title:       "检测到插件文件",
				Description: "发现插件相关文件，可能来自未经信任的 ClawHub 源。",
				Remediation: "审查插件来源和内容，仅保留可信的插件。删除未知或不必要的插件文件，并限制插件安装权限。",
				Severity:    models.Warning,
				Details:     map[string]string{"path": path},
			})
			break
		}
	}

	return findings, nil
}

// ScanCredentials checks for credential files and their permissions.
func ScanCredentials(homeDir string) ([]models.Finding, error) {
	var findings []models.Finding

	credsDir := filepath.Join(homeDir, "credentials")
	info, err := os.Stat(credsDir)
	if err != nil || !info.IsDir() {
		if errors.Is(err, fs.ErrNotExist) || err == nil {
			return findings, nil
		}
		return findings, err
	}

	files, err := credentialFiles(credsDir)
	if err != nil {
		return findings, err
	}
	if len(files) == 0 {
		return findings, nil
	}

	findings = append(findings, models.Finding{
		Category:    models.CatCredentials,
		Title:       "凭证目录已存在",
		Description: "凭证目录中包含文件，可能含有 API 密钥或令牌。",
		Remediation: "审查凭证文件内容，轮换已暴露的密钥和令牌。将凭证迁移到专用的密钥管理服务（如 Vault），并从磁盘上安全删除明文凭证。",
		Severity:    models.Warning,
		Details:     map[string]string{"path": credsDir, "file_count": strconv.Itoa(len(files))},
	})

	// Check permissions (Unix only)
	if runtime.GOOS == "windows" {
		return findings, nil
	}

	for _, path := range files {
		fi, err := os.Stat(path)
		if err != nil {
			continue
		}
		mode := fi.Mode().Perm()
		// Check if world-readable (others have read permission)
		if mode&fs.FileMode(0o004) != 0 {
			findings = append(findings, models.Finding{
				Category:    models.CatCredentials,
				Title:       "凭证文件权限过于宽松",
				Description: "凭证文件可被系统上任意用户读取。",
				Remediation: "立即执行 chmod 600 收紧文件权限，确保仅文件所有者可读写。同时轮换该文件中的所有密钥和令牌，因为它们可能已被其他用户读取。",
				Severity:    models.Critical,
				Details: map[string]string{
					"path":        path,
					"permissions": mode.String(),
				},
			})
		}
	}

	return findings, nil
}

func credentialFiles(root string) ([]string, error) {
	var files []string

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

// ScanNetwork checks whether the OpenClaw gateway port is listening.
func ScanNetwork(dial dialFunc) ([]models.Finding, error) {
	if dial == nil {
		dial = net.DialTimeout
	}
	return scanGatewayPort(dial)
}

func scanGatewayPort(dial dialFunc) ([]models.Finding, error) {
	var findings []models.Finding
	addr := fmt.Sprintf("127.0.0.1:%d", gatewayPort)

	conn, err := dial("tcp", addr, dialTimeout)
	if err != nil {
		// Port not open — no finding
		return findings, nil
	}
	conn.Close()

	findings = append(findings, models.Finding{
		Category:    models.CatNetwork,
		Title:       "网关端口已开放",
		Description: fmt.Sprintf("OpenClaw 网关正在监听端口 %d，该端口暴露了 HTTP API，可能允许远程控制 Agent。", gatewayPort),
		Remediation: fmt.Sprintf("如非必要，关闭网关服务或通过防火墙封锁端口 %d。如需保留，确保仅绑定 127.0.0.1 并启用访问认证。", gatewayPort),
		Severity:    models.Warning,
		Details:     map[string]string{"port": fmt.Sprintf("%d", gatewayPort), "address": addr},
	})

	// Check if also listening on all interfaces (network-exposed)
	allAddr := fmt.Sprintf("0.0.0.0:%d", gatewayPort)
	conn, err = dial("tcp", allAddr, dialTimeout)
	if err != nil {
		return findings, nil
	}
	conn.Close()

	findings = append(findings, models.Finding{
		Category:    models.CatNetwork,
		Title:       "网关暴露到外部网络",
		Description: fmt.Sprintf("OpenClaw 网关端口 %d 在所有网络接口 (0.0.0.0) 上可达，已暴露到整个网络。", gatewayPort),
		Remediation: "立即将网关绑定地址修改为 127.0.0.1，或通过 iptables/firewalld 限制入站流量。检查是否已有未授权的外部连接，并审计访问日志。",
		Severity:    models.Critical,
		Details:     map[string]string{"port": fmt.Sprintf("%d", gatewayPort), "address": allAddr},
	})

	return findings, nil
}

// ScanProcesses checks for running OpenClaw-related processes.
func ScanProcesses(plat platform.Platform) ([]models.Finding, error) {
	var findings []models.Finding

	procs, err := plat.FindProcesses()
	if err != nil {
		return findings, err
	}

	for _, proc := range procs {
		findings = append(findings, models.Finding{
			Category:    models.CatProcess,
			Title:       "OpenClaw 进程正在运行",
			Description: "检测到 OpenClaw 相关进程正在活跃运行。",
			Remediation: "如非授权运行，应立即终止该进程（kill PID）。排查进程启动来源，检查是否有计划任务或开机启动项自动拉起。",
			Severity:    models.Warning,
			Details: map[string]string{
				"pid":     proc.PID,
				"name":    proc.Name,
				"command": proc.Cmd,
			},
		})
	}

	return findings, nil
}

// ScanServices checks for registered OpenClaw system services.
func ScanServices(plat platform.Platform) ([]models.Finding, error) {
	var findings []models.Finding

	services, err := plat.FindServices()
	if err != nil {
		return findings, err
	}

	for _, svc := range services {
		if svc.Active {
			findings = append(findings, models.Finding{
				Category:    models.CatService,
				Title:       "OpenClaw 服务正在运行",
				Description: "已注册的 OpenClaw 系统服务当前处于运行状态。",
				Remediation: "如非授权部署，应立即停止服务（systemctl stop / launchctl unload）并禁用自启动。审查服务配置文件，确认运行用户和权限范围。",
				Severity:    models.Warning,
				Details:     map[string]string{"name": svc.Name, "status": "active"},
			})
		} else {
			findings = append(findings, models.Finding{
				Category:    models.CatService,
				Title:       "OpenClaw 服务已注册",
				Description: "已注册的 OpenClaw 系统服务当前未运行。",
				Remediation: "如不再需要，建议移除服务注册文件以防止意外启动。审查服务配置确认其合法性。",
				Severity:    models.Info,
				Details:     map[string]string{"name": svc.Name, "status": "inactive"},
			})
		}
	}

	return findings, nil
}

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

// CollectOpenClawInfo always returns a non-nil OpenClawInfo.
// It records path existence on disk regardless of whether OpenClaw is installed.
// Channels and Models are only populated when openclaw.json is present and parseable.
func CollectOpenClawInfo(homeDir string) (*models.OpenClawInfo, []models.Channel, []models.ModelProvider) {
	configPath := filepath.Join(homeDir, "openclaw.json")
	workspacePath := filepath.Join(homeDir, "workspace")

	info := &models.OpenClawInfo{
		HomeDir:    homeDir,
		ConfigPath: configPath,
		Workspace:  workspacePath,
	}

	// Check what exists on disk regardless of installation state
	if s, err := os.Stat(homeDir); err == nil && s.IsDir() {
		info.HomeExists = true
	}
	if _, err := os.Stat(configPath); err == nil {
		info.ConfigExists = true
	}
	if s, err := os.Stat(workspacePath); err == nil && s.IsDir() {
		info.WorkspaceExists = true
	}

	// Try to parse config; if it fails, return partial info (no channels/models)
	data, err := os.ReadFile(configPath)
	if err != nil {
		return info, nil, nil
	}

	var config extendedOpenClawConfig
	if err := json.Unmarshal(data, &config); err != nil {
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
