package parser

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spkiddai/clawscan/internal/models"
)

type openClawConfig struct {
	Tools struct {
		Exec struct {
			Security string `json:"security"`
			Ask      string `json:"ask"`
		} `json:"exec"`
	} `json:"tools"`
	Gateway struct {
		Port uint16 `json:"port"`
		Bind string `json:"bind"`
		Auth struct {
			Mode     string `json:"mode"`
			Token    string `json:"token"`
			Password string `json:"password"`
		} `json:"auth"`
		Tailscale struct {
			Mode string `json:"mode"`
		} `json:"tailscale"`
	} `json:"gateway"`
}

// ScanConfig parses the OpenClaw configuration and checks for risky settings.
func ScanConfig(homeDir string) ([]models.Finding, error) {
	var findings []models.Finding

	configPath := filepath.Join(homeDir, "openclaw.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return findings, nil
		}
		return findings, err
	}

	var config openClawConfig
	if err := json.Unmarshal(data, &config); err != nil {
		findings = append(findings, models.Finding{
			Category:    models.CatConfig,
			Title:       "配置文件解析失败",
			Description: "OpenClaw 配置文件存在但无法解析，风险评估可能不完整。",
			Remediation: "检查配置文件格式是否正确（JSON 语法）。如文件已损坏，建议从备份恢复或重新生成配置。",
			Severity:    models.Warning,
			Details: map[string]string{
				"path":  configPath,
				"error": err.Error(),
			},
		})
		return findings, nil
	}

	// Check exec security
	if config.Tools.Exec.Security == "full" {
		findings = append(findings, models.Finding{
			Category:    models.CatConfig,
			Title:       "允许执行任意 Shell 命令",
			Description: "OpenClaw 配置为允许执行所有 Shell 命令，存在严重安全隐患。",
			Remediation: "修改配置文件，将 tools.exec.security 的值修改为 allowlist，仅允许执行特定命令，或修改为 deny，禁止执行所有系统命令。",
			Severity:    models.Critical,
			Details:     map[string]string{"setting": "tools.exec.security", "value": "full"},
		})
	}

	// Check gateway bind address
	if bind := config.Gateway.Bind; strings.HasPrefix(bind, "0.0.0.0") || strings.HasPrefix(bind, "[::]") || strings.HasPrefix(bind, ":") {
		findings = append(findings, models.Finding{
			Category:    models.CatConfig,
			Title:       "网关绑定到所有网络接口",
			Description: "OpenClaw 网关配置为监听所有网络接口，使实例暴露在网络中，可从 localhost 以外访问。",
			Remediation: "修改配置文件，将 gateway.bind 修改为 127.0.0.1 以仅允许本地访问。如需远程访问，应通过防火墙规则或 VPN 限制来源 IP，并启用身份认证。",
			Severity:    models.Critical,
			Details:     map[string]string{"setting": "gateway.bind", "value": bind},
		})
	}

	return findings, nil
}
