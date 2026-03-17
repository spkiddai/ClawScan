package browser

import "github.com/spkiddai/clawscan/internal/platform"

// Open opens the given URL in the default browser using the platform implementation.
func Open(plat platform.Platform, url string) error {
	return plat.OpenBrowser(url)
}
