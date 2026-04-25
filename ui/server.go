// Package ui exposes the read-only HTTP viewer for runs and the ATT&CK
// matrix. There is intentionally no auth: the server defaults to
// 127.0.0.1:8088 and refuses to bind a non-loopback address without an
// explicit operator confirmation flag (per IMPLEMENTATION.md §6.1 / M5).
package ui

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/attack"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

type Options struct {
	Listen         string         // "127.0.0.1:8088"
	InsecurePublic bool           // allow non-loopback bind
	Bundle         *attack.Bundle // ATT&CK metadata for the matrix
	Store          *store.Store
	MatrixWindow   time.Duration // default 30d
	ReadHeader     time.Duration // default 5s
	ReadTotal      time.Duration // default 10s
}

type Server struct {
	opts Options
	srv  *http.Server
}

func New(opts Options) (*Server, error) {
	if opts.Listen == "" {
		opts.Listen = "127.0.0.1:8088"
	}
	if opts.MatrixWindow == 0 {
		opts.MatrixWindow = 30 * 24 * time.Hour
	}
	if opts.ReadHeader == 0 {
		opts.ReadHeader = 5 * time.Second
	}
	if opts.ReadTotal == 0 {
		opts.ReadTotal = 10 * time.Second
	}
	if opts.Store == nil {
		return nil, errors.New("ui: store required")
	}
	if opts.Bundle == nil {
		opts.Bundle = attack.EmbeddedFallback()
	}
	if err := assertSafeBind(opts.Listen, opts.InsecurePublic); err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	s := &Server{opts: opts}
	s.routes(mux)
	s.srv = &http.Server{
		Addr:              opts.Listen,
		Handler:           mux,
		ReadHeaderTimeout: opts.ReadHeader,
		ReadTimeout:       opts.ReadTotal,
	}
	return s, nil
}

func (s *Server) ListenAndServe() error {
	return s.srv.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

// assertSafeBind refuses to bind a public address unless the operator
// has set InsecurePublic explicitly. Loopback (IPv4 127/8 and IPv6 ::1)
// is always allowed.
func assertSafeBind(addr string, insecurePublic bool) error {
	if insecurePublic {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("ui: parse listen %q: %w", addr, err)
	}
	host = strings.TrimSpace(host)
	if host == "" || host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Could be a hostname; resolve and check loopback.
		ips, lookupErr := net.LookupIP(host)
		if lookupErr != nil {
			return fmt.Errorf("ui: resolve %q: %w", host, lookupErr)
		}
		for _, r := range ips {
			if !r.IsLoopback() {
				return fmt.Errorf("ui: refusing to bind non-loopback %s — pass --insecure-public to override", addr)
			}
		}
		return nil
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("ui: refusing to bind non-loopback %s — pass --insecure-public to override", addr)
	}
	return nil
}
