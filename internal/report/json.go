package report

import (
	"encoding/json"
	"io"

	"github.com/spkiddai/clawscan/internal/models"
)

// WriteJSON writes the scan result as JSON to the given writer.
func WriteJSON(w io.Writer, result *models.ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
