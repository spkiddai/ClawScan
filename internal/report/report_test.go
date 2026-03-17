package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/spkiddai/clawscan/internal/models"
)

func TestWriteHTMLIncludesGroupedFindingsAndIssues(t *testing.T) {
	result := &models.ScanResult{
		Hostname: "host-1",
		OS:       "linux",
		ScanTime: time.Date(2026, 3, 15, 10, 30, 0, 0, time.UTC),
		Issues: []models.ScanIssue{
			{Check: "services", Error: "launchctl 不可用"},
		},
	}

	var output bytes.Buffer
	if err := WriteHTML(&output, result, "1.2.3"); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}

	rendered := output.String()
	for _, needle := range []string{
		"ClawScan 安全审计报告",
		"主机信息",
		"host-1",
		"OpenClaw 信息",
	} {
		if !strings.Contains(rendered, needle) {
			t.Fatalf("rendered HTML missing %q", needle)
		}
	}
}
