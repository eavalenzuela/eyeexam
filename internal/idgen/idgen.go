// Package idgen produces sortable opaque ids for runs, executions, hosts,
// and audit entries. The format is "<prefix>-<base32-time><base32-random>"
// — lexicographically sortable by creation time, no external deps.
package idgen

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"strings"
	"sync"
	"time"
)

var (
	enc      = base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz").WithPadding(base32.NoPadding)
	mu       sync.Mutex
	lastTime int64
)

// New returns a new id with the given prefix.
func New(prefix string) string {
	mu.Lock()
	now := time.Now().UTC().UnixMilli()
	if now <= lastTime {
		now = lastTime + 1
	}
	lastTime = now
	mu.Unlock()

	var tBuf [8]byte
	binary.BigEndian.PutUint64(tBuf[:], uint64(now))

	var rBuf [10]byte
	_, _ = rand.Read(rBuf[:])

	var combined [18]byte
	copy(combined[:8], tBuf[:])
	copy(combined[8:], rBuf[:])

	return prefix + "-" + strings.TrimRight(enc.EncodeToString(combined[:]), "0")
}

func Run() string       { return New("r") }
func Execution() string { return New("x") }
func Host() string      { return New("h") }
func Expected() string  { return New("e") }
func Hit() string       { return New("d") }
