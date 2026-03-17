package platform

// Platform abstracts OS-specific operations.
type Platform interface {
	// OpenClawHome returns the default OpenClaw home directory path.
	OpenClawHome() string

	// OpenBrowser opens the given URL in the default browser.
	OpenBrowser(url string) error
}
