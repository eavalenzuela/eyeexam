package ui

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/attack"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

func TestAssertSafeBindAllowsLoopback(t *testing.T) {
	cases := []string{"127.0.0.1:8088", "localhost:8088", "[::1]:8088"}
	for _, c := range cases {
		if err := assertSafeBind(c, false); err != nil {
			t.Errorf("loopback %q rejected: %v", c, err)
		}
	}
}

func TestAssertSafeBindRefusesPublic(t *testing.T) {
	if err := assertSafeBind("0.0.0.0:8088", false); err == nil {
		t.Fatal("expected rejection of 0.0.0.0")
	}
	if err := assertSafeBind("0.0.0.0:8088", true); err != nil {
		t.Fatalf("--insecure-public should allow: %v", err)
	}
}

func TestServerEndpoints(t *testing.T) {
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "ui.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	s, err := New(Options{
		Listen: "127.0.0.1:0", Store: st, Bundle: attack.EmbeddedFallback(),
		MatrixWindow: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Drive the handlers directly via http.NewServeMux instead of binding
	// a port: build a fresh mux and exercise it via httptest-style calls.
	for _, path := range []string{"/", "/runs", "/matrix"} {
		req, _ := http.NewRequest(http.MethodGet, path, nil)
		rec := newRecorder()
		mux := http.NewServeMux()
		s.routes(mux)
		mux.ServeHTTP(rec, req)
		if rec.code != http.StatusOK {
			t.Errorf("GET %s: status=%d body=%s", path, rec.code, rec.body.String())
		}
		body := rec.body.String()
		if !strings.Contains(body, "eyeexam") {
			t.Errorf("GET %s: response missing 'eyeexam' marker", path)
		}
	}
}

// minimal http.ResponseWriter implementation
type recorder struct {
	code int
	hdr  http.Header
	body *capBuf
}

type capBuf struct{ b []byte }

func (b *capBuf) Write(p []byte) (int, error) { b.b = append(b.b, p...); return len(p), nil }
func (b *capBuf) String() string              { return string(b.b) }

func newRecorder() *recorder {
	return &recorder{hdr: http.Header{}, body: &capBuf{}}
}

func (r *recorder) Header() http.Header { return r.hdr }
func (r *recorder) Write(p []byte) (int, error) {
	if r.code == 0 {
		r.code = http.StatusOK
	}
	return r.body.Write(p)
}
func (r *recorder) WriteHeader(code int) { r.code = code }

var _ io.Writer = (*recorder)(nil)
