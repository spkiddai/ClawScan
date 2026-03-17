//go:build darwin

package platform

import (
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
