package app

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spkiddai/clawscan/internal/audit"
	"github.com/spkiddai/clawscan/internal/browser"
	"github.com/spkiddai/clawscan/internal/collector"
	"github.com/spkiddai/clawscan/internal/models"
	"github.com/spkiddai/clawscan/internal/parser"
	"github.com/spkiddai/clawscan/internal/platform"
	"github.com/spkiddai/clawscan/internal/report"
)

type Config struct {
	Version string
	Commit  string
}

type options struct {
	output       string
	format       report.Format
	noOpen       bool
	openclawHome string
	quiet        bool
	showVersion  bool
}

func Run(args []string, stdout, stderr io.Writer, cfg Config) int {
	initConsole()

	opts, err := parseOptions(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "错误: %v\n", err)
		return 1
	}

	if opts.showVersion {
		fmt.Fprintf(stdout, "ClawScan %s (%s)\n", cfg.Version, cfg.Commit)
		return 0
	}

	color := colorEnabled()
	plat := platform.New()

	if !opts.quiet {
		title := fmt.Sprintf("ClawScan %s", cfg.Version)
		fmt.Fprintf(stdout, "%s -- OpenClaw 安全扫描器\n\n",
			colorize(title, colorBoldCyan, color))
		fmt.Fprintln(stdout, colorize("正在扫描...", colorGray, color))
	}

	result := runScan(plat, opts.openclawHome)

	if !opts.quiet {
		printFindings(stdout, result, color)
		printIssues(stderr, result, color)
	}

	if !opts.shouldWriteReport() {
		return int(result.MaxSeverity)
	}

	outputPath := opts.output
	if outputPath == "" {
		outputPath = defaultOutputPath(opts.format, time.Now())
	}

	if err := writeReport(outputPath, opts.format, result, cfg.Version); err != nil {
		fmt.Fprintf(stderr, "错误: %v\n", err)
		return 1
	}

	if !opts.quiet {
		fmt.Fprintf(stdout, "\n%s %s\n",
			colorize("报告已保存至", colorGray, color),
			colorize(outputPath, colorBoldWhite, color))
	}

	if opts.shouldOpenBrowser() {
		if !hasDesktopEnvironment() {
			if !opts.quiet {
				fmt.Fprintf(stderr, "%s 未检测到桌面环境，跳过浏览器打开。\n",
					colorize("提示:", colorCyan, color))
				fmt.Fprintf(stderr, "      请将报告文件复制到有浏览器的机器上查看。\n")
			}
		} else if err := openReportInBrowser(plat, outputPath); err != nil && !opts.quiet {
			fmt.Fprintf(stderr, "警告: 无法打开浏览器: %v\n", err)
		}
	}

	return int(result.MaxSeverity)
}

func runScan(plat platform.Platform, openclawHome string) *models.ScanResult {
	homeDir := openclawHome
	if homeDir == "" {
		if env := os.Getenv("OPENCLAW_HOME"); env != "" {
			homeDir = env
		} else {
			homeDir = plat.OpenClawHome()
		}
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	result := &models.ScanResult{
		Hostname: hostname,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		ScanTime: time.Now(),
	}

	if findings, err := collector.ScanFilesystem(homeDir); err != nil {
		result.AddIssue("filesystem", err)
	} else {
		result.AddFindings(findings)
	}

	if findings, err := collector.ScanProcesses(plat); err != nil {
		result.AddIssue("processes", err)
	} else {
		result.AddFindings(findings)
	}

	if findings, err := collector.ScanServices(plat); err != nil {
		result.AddIssue("services", err)
	} else {
		result.AddFindings(findings)
	}

	if findings, err := parser.ScanConfig(homeDir); err != nil {
		result.AddIssue("config", err)
	} else {
		result.AddFindings(findings)
	}

	if findings, err := collector.ScanCredentials(homeDir); err != nil {
		result.AddIssue("credentials", err)
	} else {
		result.AddFindings(findings)
	}

	if findings, err := collector.ScanNetwork(nil); err != nil {
		result.AddIssue("network", err)
	} else {
		result.AddFindings(findings)
	}

	info, channels, modelProviders := collector.CollectOpenClawInfo(homeDir)
	result.OpenClawInfo = info
	result.Channels = channels
	result.Models = modelProviders

	auditResult, err := audit.RunAudit()
	if err != nil {
		result.AddIssue("audit", err)
	} else {
		result.AuditResult = auditResult
	}

	result.Finalize()
	return result
}

func parseOptions(args []string, stderr io.Writer) (options, error) {
	var (
		opts      options
		formatRaw string
	)

	fs := flag.NewFlagSet("clawscan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.output, "o", "", "报告输出路径")
	fs.StringVar(&opts.output, "output", "", "报告输出路径")
	fs.StringVar(&formatRaw, "f", string(report.FormatHTML), "输出格式: html, json")
	fs.StringVar(&formatRaw, "format", string(report.FormatHTML), "输出格式: html, json")
	fs.BoolVar(&opts.noOpen, "no-open", false, "不自动打开浏览器")
	fs.StringVar(&opts.openclawHome, "openclaw-home", "", "指定 OpenClaw 目录")
	fs.BoolVar(&opts.quiet, "q", false, "静默模式，仅返回退出码")
	fs.BoolVar(&opts.quiet, "quiet", false, "静默模式，仅返回退出码")
	fs.BoolVar(&opts.showVersion, "v", false, "显示版本号")
	fs.BoolVar(&opts.showVersion, "version", false, "显示版本号")

	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	if fs.NArg() > 0 {
		return opts, fmt.Errorf("意外的参数: %s", strings.Join(fs.Args(), " "))
	}

	format, err := report.ParseFormat(formatRaw)
	if err != nil {
		return opts, err
	}
	opts.format = format

	return opts, nil
}

func (o options) shouldWriteReport() bool {
	return !o.quiet || o.output != ""
}

func (o options) shouldOpenBrowser() bool {
	return !o.quiet && !o.noOpen && o.format == report.FormatHTML
}

func defaultOutputPath(format report.Format, now time.Time) string {
	dir, err := os.Getwd()
	if err != nil {
		dir = "."
	}
	return filepath.Join(dir, fmt.Sprintf("clawscan-report-%s.%s", now.Format("20060102-150405"), format))
}

func writeReport(path string, format report.Format, result *models.ScanResult, version string) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("创建报告文件失败: %w", err)
	}
	defer file.Close()

	if err := report.Write(file, format, result, version); err != nil {
		return fmt.Errorf("写入 %s 报告失败: %w", format, err)
	}

	return nil
}

func openReportInBrowser(plat platform.Platform, path string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	reportURL := &url.URL{
		Scheme: "file",
		Path:   filepath.ToSlash(absPath),
	}
	return browser.Open(plat, reportURL.String())
}

const separator = "────────────────────────────────────────"

func printFindings(w io.Writer, result *models.ScanResult, color bool) {
	if len(result.Findings) == 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, colorize("  [安全] 未检测到 OpenClaw 安装。", colorBoldGreen, color))
		fmt.Fprintln(w)
		return
	}

	fmt.Fprintln(w)
	for _, finding := range result.Findings {
		icon, tagColor := severityStyle(finding.Severity)
		tag := colorize(fmt.Sprintf(" %s ", finding.Severity), tagColor, color)
		fmt.Fprintf(w, "  %s %s  %s\n", icon, tag, finding.Title)
		fmt.Fprintf(w, "      %s\n", colorize(finding.Description, colorGray, color))
		for k, v := range finding.Details {
			fmt.Fprintf(w, "      %s %s\n",
				colorize(k+":", colorCyan, color),
				v)
		}
		if finding.Remediation != "" {
			fmt.Fprintf(w, "      %s %s\n",
				colorize("治理:", colorBoldGreen, color),
				finding.Remediation)
		}
		fmt.Fprintln(w)
	}

	counts := result.CountBySeverity()
	fmt.Fprintln(w)
	fmt.Fprintln(w, colorize(separator, colorGray, color))

	critical := colorize(fmt.Sprintf("%d 严重", counts[models.Critical]), colorBoldRed, color)
	warning := colorize(fmt.Sprintf("%d 警告", counts[models.Warning]), colorBoldYellow, color)
	info := colorize(fmt.Sprintf("%d 提示", counts[models.Info]), colorBoldBlue, color)
	fmt.Fprintf(w, "  扫描结果:  %s  %s  %s\n", critical, warning, info)

	fmt.Fprintln(w, colorize(separator, colorGray, color))
}

func printIssues(w io.Writer, result *models.ScanResult, color bool) {
	if len(result.Issues) == 0 {
		return
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, colorize("扫描异常:", colorYellow, color))
	for _, issue := range result.Issues {
		fmt.Fprintf(w, "  %s %s: %s\n",
			colorize("-", colorYellow, color),
			colorize(issue.Check, colorBoldYellow, color),
			issue.Error)
	}
	fmt.Fprintln(w)
}

// hasDesktopEnvironment checks whether a graphical desktop is available.
func hasDesktopEnvironment() bool {
	if os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "" {
		return true
	}
	return strings.EqualFold(
		strings.TrimSpace(os.Getenv("OS")), "Windows_NT") ||
		os.Getenv("TERM_PROGRAM") != ""
}

func severityStyle(severity models.Severity) (icon string, tagColor string) {
	switch severity {
	case models.Critical:
		return "\033[31m●\033[0m", colorBoldRed
	case models.Warning:
		return "\033[33m▲\033[0m", colorBoldYellow
	case models.Info:
		return "\033[34m■\033[0m", colorBoldBlue
	default:
		return "\033[32m✔\033[0m", colorBoldGreen
	}
}
