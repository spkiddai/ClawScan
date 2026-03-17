package report

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"strings"

	"github.com/spkiddai/clawscan/internal/models"
)

//go:embed template/report.html
var templateFS embed.FS

var funcMap = template.FuncMap{
	"joinStrings": func(s []string) string {
		return strings.Join(s, ", ")
	},
}

// WriteHTML renders the scan result as an HTML report to the given writer.
func WriteHTML(w io.Writer, result *models.ScanResult, version string) error {
	tmplContent, err := templateFS.ReadFile("template/report.html")
	if err != nil {
		return fmt.Errorf("读取内嵌模板失败: %w", err)
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(string(tmplContent))
	if err != nil {
		return fmt.Errorf("解析模板失败: %w", err)
	}

	data := NewTemplateData(result, version)
	return tmpl.Execute(w, data)
}
