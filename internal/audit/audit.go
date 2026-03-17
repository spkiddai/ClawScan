package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spkiddai/clawscan/internal/models"
)

type rawAuditOutput struct {
	Findings []struct {
		CheckID     string `json:"checkId"`
		Severity    string `json:"severity"`
		Title       string `json:"title"`
		Detail      string `json:"detail"`
		Remediation string `json:"remediation"`
	} `json:"findings"`
}

var reGroupOpen     = regexp.MustCompile(`open=(\d+)`)
var reGroupAllowlist = regexp.MustCompile(`allowlist=(\d+)`)

// parseAttackSurface converts a raw key/value line into one or more AttackSurface entries
// with Chinese labels and risk-level color classes.
func parseAttackSurface(rawKey, rawValue string) []models.AttackSurface {
	key := strings.ToLower(strings.TrimSpace(rawKey))
	value := strings.TrimSpace(rawValue)

	switch key {
	case "groups":
		openNum := 0
		if m := reGroupOpen.FindStringSubmatch(value); len(m) > 1 {
			openNum, _ = strconv.Atoi(m[1])
		}
		openClass := "green"
		if openNum > 0 {
			openClass = "red"
		}

		allowNum := 0
		if m := reGroupAllowlist.FindStringSubmatch(value); len(m) > 1 {
			allowNum, _ = strconv.Atoi(m[1])
		}
		allowClass := "green"
		if allowNum > 0 {
			allowClass = "yellow"
		}

		return []models.AttackSurface{
			{Item: "群组（开放）", Status: strconv.Itoa(openNum), StatusClass: openClass},
			{Item: "群组（白名单）", Status: strconv.Itoa(allowNum), StatusClass: allowClass},
		}

	case "tools.elevated":
		class, display := "green", "未启用"
		if value == "enabled" {
			class, display = "red", "启用"
		}
		return []models.AttackSurface{{Item: "高权限工具", Status: display, StatusClass: class}}

	case "hooks":
		class, display := "green", "未启用"
		if value == "enabled" {
			class, display = "yellow", "启用"
		}
		return []models.AttackSurface{{Item: "Hooks", Status: display, StatusClass: class}}

	case "hooks.webhooks":
		class, display := "green", "未启用"
		if value == "enabled" {
			class, display = "red", "启用"
		}
		return []models.AttackSurface{{Item: "外部Hooks", Status: display, StatusClass: class}}

	case "hooks.internal":
		class, display := "green", "未启用"
		if value == "enabled" {
			class, display = "yellow", "启用"
		}
		return []models.AttackSurface{{Item: "内部Hook", Status: display, StatusClass: class}}

	case "browser control":
		class, display := "green", "未启用"
		if value == "enabled" {
			class, display = "yellow", "启用"
		}
		return []models.AttackSurface{{Item: "浏览器", Status: display, StatusClass: class}}

	case "trust model":
		return nil

	default:
		return []models.AttackSurface{{Item: rawKey, Status: value}}
	}
}

// RunAudit executes `openclaw security audit --deep --json` and returns the parsed result.
// If openclaw is not installed or the command fails, it returns nil and an error.
func RunAudit() (*models.AuditResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "openclaw", "security", "audit", "--deep", "--json").Output()
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return nil, fmt.Errorf("openclaw security audit 执行失败: %w", err)
		}
		// 非零退出码（如发现 critical 问题时）仍可包含有效 JSON，继续解析
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
		if f.CheckID == "summary.attack_surface" {
			for _, line := range strings.Split(f.Detail, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					result.AttackSurfaces = append(result.AttackSurfaces, parseAttackSurface(parts[0], parts[1])...)
				}
			}
			continue
		}
		result.Findings = append(result.Findings, models.AuditFinding{
			CheckID:     f.CheckID,
			Severity:    f.Severity,
			Title:       f.Title,
			Detail:      f.Detail,
			Remediation: f.Remediation,
		})
	}

	return result, nil
}
