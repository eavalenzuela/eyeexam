package matrix

import (
	"encoding/json"
	"io"
)

// RenderJSON writes the matrix as pretty-printed JSON.
func (m *Matrix) RenderJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(m)
}
