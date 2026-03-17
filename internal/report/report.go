package report

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/spkiddai/clawscan/internal/models"
)

type Format string

const (
	FormatHTML Format = "html"
	FormatJSON Format = "json"
)

func ParseFormat(value string) (Format, error) {
	format := Format(strings.ToLower(value))
	switch format {
	case FormatHTML, FormatJSON:
		return format, nil
	default:
		return "", fmt.Errorf("不支持的格式 %q（可选 html 或 json）", value)
	}
}

// TemplateData is the data passed to the HTML template.
type TemplateData struct {
	ProductName    string
	Result         *models.ScanResult
	Version        string
	CriticalCount  int
	WarnCount      int
	InfoCount      int
	OpenClawInfo   *models.OpenClawInfo // always non-nil
	Channels       []models.Channel
	Models         []models.ModelProvider
	Skills         []models.Skill
	AttackSurfaces []models.AttackSurface
	RiskFindings   []models.AuditFinding
	AuditError     bool
}

// NewTemplateData creates template data from a scan result.
func NewTemplateData(result *models.ScanResult, version string) *TemplateData {
	openClawInfo := result.OpenClawInfo
	if openClawInfo == nil {
		openClawInfo = &models.OpenClawInfo{}
	}

	data := &TemplateData{
		ProductName:  "ClawScan",
		Result:       result,
		Version:      version,
		OpenClawInfo: openClawInfo,
		Channels:     result.Channels,
		Models:       result.Models,
		Skills:       result.Skills,
	}

	if result.AuditResult == nil {
		data.AuditError = true
	} else {
		data.AttackSurfaces = result.AuditResult.AttackSurfaces
		for _, f := range result.AuditResult.Findings {
			switch f.Severity {
			case "critical":
				data.CriticalCount++
			case "warn":
				data.WarnCount++
			case "info":
				data.InfoCount++
			}
			if f.Severity == "critical" || f.Severity == "warn" {
				data.RiskFindings = append(data.RiskFindings, f)
			}
		}
		// Sort: critical first, then warn
		slices.SortStableFunc(data.RiskFindings, func(a, b models.AuditFinding) int {
			order := func(s string) int {
				if s == "critical" {
					return 0
				}
				return 1
			}
			return cmp.Compare(order(a.Severity), order(b.Severity))
		})
	}

	return data
}

func Write(w io.Writer, format Format, result *models.ScanResult, version string) error {
	switch format {
	case FormatJSON:
		return WriteJSON(w, result)
	case FormatHTML:
		return WriteHTML(w, result, version)
	default:
		return fmt.Errorf("不支持的格式 %q", format)
	}
}
