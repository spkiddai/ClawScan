package platform

// ProcessInfo holds information about a running process.
type ProcessInfo struct {
	PID  string
	Name string
	Cmd  string
}

// ServiceInfo holds information about a system service.
type ServiceInfo struct {
	Name   string
	Active bool
}

// Platform abstracts OS-specific operations.
type Platform interface {
	// OpenClawHome returns the default OpenClaw home directory path.
	OpenClawHome() string

	// FindProcesses returns OpenClaw-related processes.
	FindProcesses() ([]ProcessInfo, error)

	// FindServices returns OpenClaw-related registered services.
	FindServices() ([]ServiceInfo, error)

	// OpenBrowser opens the given URL in the default browser.
	OpenBrowser(url string) error
}
