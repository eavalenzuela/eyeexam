package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/eavalenzuela/eyeexam/internal/inventory"
)

// SSH runs commands on remote hosts over SSH. Behavior:
//
//   - Key-only auth (no passwords). Per-host key path comes from
//     inventory.Host.KeyPath; otherwise SSHConfig.DefaultKey is used.
//   - Hostkey verification: knownhosts at SSHConfig.KnownHostsPath; if the
//     file is empty/missing this runner refuses to dial unless
//     InsecureSkipKnownHosts is set (test fixtures only).
//   - One *ssh.Client per host, lazily dialed and reused for the lifetime
//     of the runner. Each Execute opens a fresh session; sessions are NOT
//     reused across unrelated tests.
type SSH struct {
	cfg     SSHConfig
	mu      sync.Mutex
	clients map[string]*ssh.Client // host -> client
	hostKey ssh.HostKeyCallback
}

type SSHConfig struct {
	DefaultUser            string
	DefaultKeyPath         string
	KnownHostsPath         string // ~/.ssh/known_hosts
	ConnectTimeout         time.Duration
	CommandTimeout         time.Duration
	InsecureSkipKnownHosts bool // test only
}

func NewSSH(cfg SSHConfig) (*SSH, error) {
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	if cfg.CommandTimeout == 0 {
		cfg.CommandTimeout = 5 * time.Minute
	}
	s := &SSH{cfg: cfg, clients: map[string]*ssh.Client{}}

	if cfg.InsecureSkipKnownHosts {
		s.hostKey = ssh.InsecureIgnoreHostKey() //nolint:gosec // explicit test opt-in
	} else {
		path := cfg.KnownHostsPath
		if path == "" {
			home, _ := os.UserHomeDir()
			path = filepath.Join(home, ".ssh", "known_hosts")
		}
		if _, err := os.Stat(path); err != nil {
			return nil, fmt.Errorf("ssh: known_hosts %s not found (set runner.ssh.known_hosts or use InsecureSkipKnownHosts in tests): %w", path, err)
		}
		hk, err := knownhosts.New(path)
		if err != nil {
			return nil, fmt.Errorf("ssh: load known_hosts %s: %w", path, err)
		}
		s.hostKey = hk
	}
	return s, nil
}

func (s *SSH) Name() string { return "ssh" }

func (s *SSH) Capabilities() []string { return []string{"shell:bash", "shell:sh"} }

func (s *SSH) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var firstErr error
	for k, c := range s.clients {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		delete(s.clients, k)
	}
	return firstErr
}

func (s *SSH) Execute(ctx context.Context, host inventory.Host, step ExecuteStep) (Result, error) {
	if host.Transport != "ssh" {
		return Result{}, fmt.Errorf("ssh runner: host %q transport=%q", host.Name, host.Transport)
	}
	switch step.Shell {
	case "bash", "sh", "":
	default:
		return Result{}, fmt.Errorf("%w: %q", ErrUnsupportedShell, step.Shell)
	}

	cli, err := s.clientFor(host)
	if err != nil {
		return Result{}, err
	}

	timeout := step.Timeout
	if timeout == 0 {
		timeout = s.cfg.CommandTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	sess, err := cli.NewSession()
	if err != nil {
		return Result{}, fmt.Errorf("ssh: new session: %w", err)
	}
	defer func() { _ = sess.Close() }()

	for k, v := range step.Env {
		_ = sess.Setenv(k, v)
	}

	if step.Stdin != nil {
		sess.Stdin = step.Stdin
	}
	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	shell := step.Shell
	if shell == "" {
		shell = "sh"
	}
	res := Result{Started: time.Now().UTC()}

	done := make(chan error, 1)
	go func() {
		// `bash -c <cmd>` so we get the same semantics as the local runner.
		done <- sess.Run(fmt.Sprintf("%s -c %s", shell, shellQuote(step.Command)))
	}()

	select {
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		_ = sess.Close()
		res.Finished = time.Now().UTC()
		res.Stdout = stdout.Bytes()
		res.Stderr = stderr.Bytes()
		res.ExitCode = -1
		return res, fmt.Errorf("ssh exec %s: %w", host.Name, ctx.Err())
	case runErr := <-done:
		res.Finished = time.Now().UTC()
		res.Stdout = stdout.Bytes()
		res.Stderr = stderr.Bytes()
		if runErr == nil {
			res.ExitCode = 0
			return res, nil
		}
		var exitErr *ssh.ExitError
		if errors.As(runErr, &exitErr) {
			res.ExitCode = exitErr.ExitStatus()
			return res, nil
		}
		res.ExitCode = -1
		return res, fmt.Errorf("ssh exec %s: %w", host.Name, runErr)
	}
}

func (s *SSH) clientFor(host inventory.Host) (*ssh.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.clients[host.Name]; ok {
		return c, nil
	}
	c, err := s.dial(host)
	if err != nil {
		return nil, err
	}
	s.clients[host.Name] = c
	return c, nil
}

func (s *SSH) dial(host inventory.Host) (*ssh.Client, error) {
	user := host.User
	if user == "" {
		user = s.cfg.DefaultUser
	}
	if user == "" {
		return nil, fmt.Errorf("ssh: host %q has no user and no runner.ssh.default_user", host.Name)
	}
	keyPath := host.KeyPath
	if keyPath == "" {
		keyPath = s.cfg.DefaultKeyPath
	}
	if keyPath == "" {
		return nil, fmt.Errorf("ssh: host %q has no key path", host.Name)
	}
	keyPath = expandHome(keyPath)
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("ssh: read key %s: %w", keyPath, err)
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("ssh: parse key %s: %w", keyPath, err)
	}

	addr := host.Address
	if addr == "" {
		addr = host.Name
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "22")
	}

	clientCfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: s.hostKey,
		Timeout:         s.cfg.ConnectTimeout,
	}
	c, err := ssh.Dial("tcp", addr, clientCfg)
	if err != nil {
		return nil, fmt.Errorf("ssh: dial %s@%s: %w", user, addr, err)
	}
	return c, nil
}

// HealthCheck dials a host and runs a noop command. Used by `eyeexam
// inventory check`. Returns nil on success.
func (s *SSH) HealthCheck(ctx context.Context, host inventory.Host) error {
	res, err := s.Execute(ctx, host, ExecuteStep{Shell: "sh", Command: "true", Timeout: s.cfg.ConnectTimeout})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("ssh healthcheck %s: exit %d", host.Name, res.ExitCode)
	}
	return nil
}

func expandHome(p string) string {
	if len(p) > 1 && p[0] == '~' && p[1] == '/' {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, p[2:])
	}
	return p
}

// shellQuote wraps a string in single quotes, escaping any embedded ones.
// We always send 'bash -c <quoted>' to avoid relying on the remote login shell.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + bytesReplaceAll(s, "'", `'\''`) + "'"
}

// bytesReplaceAll is a tiny inlined strings.ReplaceAll without importing
// strings here (we already keep the import surface small in this file).
func bytesReplaceAll(s, old, new string) string {
	var b bytes.Buffer
	b.Grow(len(s))
	for {
		i := indexOf(s, old)
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:i])
		b.WriteString(new)
		s = s[i+len(old):]
	}
}

func indexOf(s, sub string) int {
	if len(sub) == 0 {
		return 0
	}
outer:
	for i := 0; i+len(sub) <= len(s); i++ {
		for j := 0; j < len(sub); j++ {
			if s[i+j] != sub[j] {
				continue outer
			}
		}
		return i
	}
	return -1
}
