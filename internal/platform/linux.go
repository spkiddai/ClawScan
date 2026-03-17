//go:build linux

package platform

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type linuxPlatform struct{}

// New returns the platform implementation for the current OS.
func New() Platform {
	return &linuxPlatform{}
}

func (p *linuxPlatform) OpenClawHome() string {
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

func (p *linuxPlatform) FindProcesses() ([]ProcessInfo, error) {
	return FindProcesses()
}

func (p *linuxPlatform) FindServices() ([]ServiceInfo, error) {
	var services []ServiceInfo
	var issue error

	// Check systemd unit files
	unitPaths := []string{
		"/etc/systemd/system/openclaw.service",
		"/etc/systemd/system/openclaw-gateway.service",
	}
	// Check user unit files
	homeDirs := findAllUserHomeDirs()
	for _, home := range homeDirs {
		unitPaths = append(unitPaths,
			filepath.Join(home, ".config/systemd/user/openclaw.service"),
			filepath.Join(home, ".config/systemd/user/openclaw-gateway.service"),
		)
	}

	for _, path := range unitPaths {
		if _, err := os.Stat(path); err == nil {
			name := strings.TrimSuffix(filepath.Base(path), ".service")
			active := false
			if state, err := systemctlState(false, name); err == nil {
				active = state == "active"
			} else {
				issue = errors.Join(issue, fmt.Errorf("systemctl is-active %s: %w", name, err))
			}
			// Also check user service
			if !active {
				if state, err := systemctlState(true, name); err == nil {
					active = state == "active"
				} else {
					issue = errors.Join(issue, fmt.Errorf("systemctl --user is-active %s: %w", name, err))
				}
			}
			services = append(services, ServiceInfo{Name: name, Active: active})
		}
	}
	return services, issue
}

func (p *linuxPlatform) OpenBrowser(url string) error {
	return exec.Command("xdg-open", url).Start()
}

func systemctlState(user bool, name string) (string, error) {
	cmdArgs := []string{"is-active", name}
	if user {
		cmdArgs = []string{"--user", "is-active", name}
	}

	out, err := exec.Command("systemctl", cmdArgs...).CombinedOutput()
	state := strings.TrimSpace(string(out))
	if state != "" {
		return state, nil
	}
	if err != nil {
		return "", err
	}
	return "", nil
}

// findAllUserHomeDirs reads /etc/passwd and returns all user home directories.
func findAllUserHomeDirs() []string {
	var homes []string
	seen := make(map[string]bool)

	file, err := os.Open("/etc/passwd")
	if err != nil {
		return homes
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// Format: username:x:uid:gid:gecos:home:shell
		fields := strings.Split(line, ":")
		if len(fields) < 6 {
			continue
		}
		home := fields[5]
		if home == "" || seen[home] {
			continue
		}
		seen[home] = true
		homes = append(homes, home)
	}

	return homes
}
