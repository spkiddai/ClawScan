package report

import (
	"fmt"
	"io"
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
	Groups         []FindingGroup
	Version        string
	CriticalCount  int
	WarningCount   int
	InfoCount      int
	TotalFindings  int
	OpenClawInfo   *models.OpenClawInfo // always non-nil
	Channels       []models.Channel
	Models         []models.ModelProvider
	AttackSurfaces []models.AttackSurface
	RiskFindings   []models.AuditFinding
	AuditError     bool
}

type FindingGroup struct {
	Key      string
	Label    string
	Findings []models.Finding
}

// NewTemplateData creates template data from a scan result.
func NewTemplateData(result *models.ScanResult, version string) *TemplateData {
	counts := result.CountBySeverity()

	openClawInfo := result.OpenClawInfo
	if openClawInfo == nil {
		openClawInfo = &models.OpenClawInfo{}
	}

	data := &TemplateData{
		ProductName:   "ClawScan",
		Result:        result,
		Groups:        groupFindings(result.Findings),
		Version:       version,
		CriticalCount: counts[models.Critical],
		WarningCount:  counts[models.Warning],
		InfoCount:     counts[models.Info],
		TotalFindings: len(result.Findings),
		OpenClawInfo:  openClawInfo,
		Channels:      result.Channels,
		Models:        result.Models,
	}

	if result.AuditResult == nil {
		data.AuditError = true
	} else {
		data.AttackSurfaces = result.AuditResult.AttackSurfaces
		for _, f := range result.AuditResult.Findings {
			if f.Severity == "critical" || f.Severity == "warn" {
				data.RiskFindings = append(data.RiskFindings, f)
			}
		}
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

func groupFindings(findings []models.Finding) []FindingGroup {
	order := []models.Category{
		models.CatInstallation,
		models.CatProcess,
		models.CatService,
		models.CatConfig,
		models.CatCredentials,
		models.CatNetwork,
	}

	grouped := make(map[models.Category][]models.Finding)
	for _, finding := range findings {
		grouped[finding.Category] = append(grouped[finding.Category], finding)
	}

	var groups []FindingGroup
	for _, category := range order {
		items := grouped[category]
		if len(items) == 0 {
			continue
		}
		groups = append(groups, FindingGroup{
			Key:      string(category),
			Label:    category.Label(),
			Findings: items,
		})
	}

	for category, items := range grouped {
		if len(items) == 0 || containsCategory(order, category) {
			continue
		}
		groups = append(groups, FindingGroup{
			Key:      string(category),
			Label:    category.Label(),
			Findings: items,
		})
	}

	return groups
}

func containsCategory(categories []models.Category, target models.Category) bool {
	for _, category := range categories {
		if category == target {
			return true
		}
	}
	return false
}
