//go:build linux

package platform

import (
	"bufio"
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

func (p *linuxPlatform) OpenBrowser(url string) error {
	return exec.Command("xdg-open", url).Start()
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
