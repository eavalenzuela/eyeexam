// Package embedded ships pack content compiled into the eyeexam binary.
//
// The builtin pack is a small set of low-destructiveness smoke tests that
// every operator can run without provisioning a separate pack repo —
// `eyeexam run --pack builtin --hosts localhost --max-dest low` is the
// canonical "is this binary working" check.
//
// Embedding (rather than disk loading) lets the binary act as its own
// trust boundary for builtin: when pack signing lands, every disk-loaded
// pack must verify against a trusted key, and this pack is exempt only
// because it isn't loaded from disk in the first place. There is no
// special-case in the signature-verification path.
package embedded

import (
	"embed"
	"io/fs"
)

//go:embed builtin/*.yaml
var raw embed.FS

// BuiltinFS returns an fs.FS rooted at the builtin pack directory.
// The returned filesystem contains *.yaml files at its root, suitable
// for pack.LoadNativeFS.
func BuiltinFS() fs.FS {
	sub, err := fs.Sub(raw, "builtin")
	if err != nil {
		// fs.Sub only fails on bad paths; "builtin" is the directory
		// the embed directive declares, so this is a programming error
		// and not a runtime condition.
		panic("embedded: fs.Sub(builtin) failed: " + err.Error())
	}
	return sub
}
