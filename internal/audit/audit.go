package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/spkiddai/clawscan/internal/models"
)

type rawAuditOutput struct {
	Summary struct {
		AttackSurface map[string]interface{} `json:"attack_surface"`
	} `json:"summary"`
	Findings []struct {
		CheckID     string `json:"checkId"`
		Severity    string `json:"severity"`
		Title       string `json:"title"`
		Detail      string `json:"detail"`
		Remediation string `json:"remediation"`
	} `json:"findings"`
}

var attackSurfaceKeys = []struct {
	jsonKey string
	label   string
}{
	{"tools_elevated", "提权工具"},
	{"hooks_webhooks", "Webhook 钩子"},
	{"hooks_internal", "内部钩子"},
	{"browser_control", "浏览器控制"},
	{"trust_model", "信任模型"},
}

// RunAudit executes `openclaw security audit --deep --json` and returns the parsed result.
// If openclaw is not installed or the command fails, it returns nil and an error.
func RunAudit() (*models.AuditResult, error) {
	out, err := exec.Command("openclaw", "security", "audit", "--deep", "--json").Output()
	if err != nil {
		return nil, fmt.Errorf("openclaw security audit 执行失败: %w", err)
	}

	start := bytes.IndexByte(out, '{')
	if start == -1 {
		return nil, fmt.Errorf("解析 audit 输出失败: 输出中未找到 JSON 内容")
	}

	var raw rawAuditOutput
	if err := json.NewDecoder(bytes.NewReader(out[start:])).Decode(&raw); err != nil {
		return nil, fmt.Errorf("解析 audit 输出失败: %w", err)
	}

	result := &models.AuditResult{}

	for _, f := range raw.Findings {
		result.Findings = append(result.Findings, models.AuditFinding{
			CheckID:     f.CheckID,
			Severity:    f.Severity,
			Title:       f.Title,
			Detail:      f.Detail,
			Remediation: f.Remediation,
		})
	}

	for _, k := range attackSurfaceKeys {
		status := "未检测"
		if v, ok := raw.Summary.AttackSurface[k.jsonKey]; ok && v != nil {
			status = fmt.Sprintf("%v", v)
		}
		result.AttackSurfaces = append(result.AttackSurfaces, models.AttackSurface{
			Item:   k.label,
			Status: status,
		})
	}

	return result, nil
}
