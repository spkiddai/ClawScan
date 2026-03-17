//go:build darwin

package platform

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type darwinPlatform struct{}

func New() Platform {
	return &darwinPlatform{}
}

func (p *darwinPlatform) OpenClawHome() string {
	// Try to find .openclaw in all user home directories
	homeDirs := findAllUserHomeDirs()
	for _, home := range homeDirs {
		openclawDir := filepath.Join(home, ".openclaw")
		if info, err := os.Stat(openclawDir); err == nil && info.IsDir() {
			return openclawDir
		}
	}
	// Fallback to current user's home directory
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".openclaw")
}

func (p *darwinPlatform) FindProcesses() ([]ProcessInfo, error) {
	return FindProcesses()
}

func (p *darwinPlatform) FindServices() ([]ServiceInfo, error) {
	var services []ServiceInfo
	var issue error

	// Check systemd LaunchDaemons
	plistPaths := []string{
		"/Library/LaunchDaemons/ai.openclaw.gateway.plist",
	}
	// Check user LaunchAgents
	homeDirs := findAllUserHomeDirs()
	for _, home := range homeDirs {
		plistPaths = append(plistPaths,
			filepath.Join(home, "Library/LaunchAgents/ai.openclaw.gateway.plist"),
		)
	}

	for _, path := range plistPaths {
		if _, err := os.Stat(path); err == nil {
			name := strings.TrimSuffix(filepath.Base(path), ".plist")
			active := false
			if out, err := exec.Command("launchctl", "list").Output(); err == nil {
				active = strings.Contains(string(out), name)
			} else {
				issue = errors.Join(issue, fmt.Errorf("launchctl list: %w", err))
			}
			services = append(services, ServiceInfo{Name: name, Active: active})
		}
	}
	return services, issue
}

func (p *darwinPlatform) OpenBrowser(url string) error {
	return exec.Command("open", url).Start()
}

// findAllUserHomeDirs returns all user home directories.
func findAllUserHomeDirs() []string {
	var homes []string
	seen := make(map[string]bool)

	usersDir := "/Users"

	entries, err := os.ReadDir("/Users")
	if err != nil {
		return homes
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Skip system/default directories
		if name == "Shared" || strings.HasPrefix(name, ".") {
			continue
		}
		home := filepath.Join(usersDir, name)
		if !seen[home] {
			seen[home] = true
			homes = append(homes, home)
		}
	}

	return homes
}
