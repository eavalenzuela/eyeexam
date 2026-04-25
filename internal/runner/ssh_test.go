package runner

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/eavalenzuela/eyeexam/internal/inventory"
)

// fakeSSHServer is an in-process OpenSSH-compatible server used to drive
// SSH-runner unit tests without depending on a system sshd or docker.
//
// It accepts public-key auth from the configured signer and handles "exec"
// channel requests by running the command through `bash -c` on the host
// running the test (the fixture's current OS user). exec output and exit
// status are returned over the channel.
type fakeSSHServer struct {
	listener net.Listener
	signer   ssh.Signer
	authKey  ssh.PublicKey
	wg       sync.WaitGroup
	stop     chan struct{}
}

func startFakeSSH(t *testing.T, authKey ssh.PublicKey) *fakeSSHServer {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromSigner(hostPriv)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &fakeSSHServer{
		listener: ln, signer: signer, authKey: authKey, stop: make(chan struct{}),
	}
	srv.wg.Add(1)
	go srv.acceptLoop(t)
	return srv
}

func (s *fakeSSHServer) Addr() string { return s.listener.Addr().String() }

func (s *fakeSSHServer) Close() error {
	close(s.stop)
	err := s.listener.Close()
	s.wg.Wait()
	return err
}

func (s *fakeSSHServer) acceptLoop(t *testing.T) {
	defer s.wg.Done()
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(s.authKey.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("unauthorized")
		},
	}
	cfg.AddHostKey(s.signer)

	for {
		c, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stop:
				return
			default:
				t.Logf("fakeSSH: accept: %v", err)
				return
			}
		}
		s.wg.Add(1)
		go s.handle(t, c, cfg)
	}
}

func (s *fakeSSHServer) handle(t *testing.T, nc net.Conn, cfg *ssh.ServerConfig) {
	defer s.wg.Done()
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		_ = nc.Close()
		return
	}
	defer func() { _ = conn.Close() }()
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only session")
			continue
		}
		ch, requests, err := newCh.Accept()
		if err != nil {
			t.Logf("fakeSSH: accept channel: %v", err)
			continue
		}
		go s.handleSession(t, ch, requests)
	}
}

func (s *fakeSSHServer) handleSession(t *testing.T, ch ssh.Channel, requests <-chan *ssh.Request) {
	for req := range requests {
		switch req.Type {
		case "exec":
			cmd := struct{ Cmd string }{}
			if err := ssh.Unmarshal(req.Payload, &cmd); err != nil {
				_ = req.Reply(false, nil)
				return
			}
			_ = req.Reply(true, nil)
			s.runExec(t, ch, cmd.Cmd)
			return
		case "env":
			_ = req.Reply(true, nil)
		default:
			_ = req.Reply(false, nil)
		}
	}
}

func (s *fakeSSHServer) runExec(_ *testing.T, ch ssh.Channel, command string) {
	defer func() { _ = ch.Close() }()
	c := exec.Command("bash", "-c", command)
	c.Stdout = ch
	c.Stderr = ch.Stderr()

	exit := 0
	if err := c.Run(); err != nil {
		var ee *exec.ExitError
		if errAs(err, &ee) {
			exit = ee.ExitCode()
		} else {
			exit = 255
		}
	}
	status := struct{ Status uint32 }{Status: uint32(exit)}
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(&status))
}

// errAs is a tiny errors.As helper.
func errAs(err error, target **exec.ExitError) bool {
	for e := err; e != nil; {
		if ee, ok := e.(*exec.ExitError); ok {
			*target = ee
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}

// writeKeyPair writes an ed25519 private key in OpenSSH format to dir/<name>
// and returns (privPath, signer). The signer's PublicKey() can be passed to
// the fake server's auth callback.
func writeKeyPair(t *testing.T, dir, name string) (string, ssh.Signer) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "eyeexam-test")
	if err != nil {
		t.Fatal(err)
	}
	privPath := filepath.Join(dir, name)
	if err := os.WriteFile(privPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	return privPath, signer
}

func TestSSHRunnerEcho(t *testing.T) {
	if testing.Short() {
		t.Skip("ssh runner test")
	}
	dir := t.TempDir()
	keyPath, signer := writeKeyPair(t, dir, "id_ed25519")

	srv := startFakeSSH(t, signer.PublicKey())
	defer func() { _ = srv.Close() }()

	cfg := SSHConfig{
		DefaultUser:            "tester",
		DefaultKeyPath:         keyPath,
		ConnectTimeout:         5 * time.Second,
		CommandTimeout:         5 * time.Second,
		InsecureSkipKnownHosts: true,
	}
	r, err := NewSSH(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	host := inventory.Host{
		Name: "fake", Address: srv.Addr(), Transport: "ssh",
	}
	res, err := r.Execute(context.Background(), host, ExecuteStep{
		Shell: "bash", Command: "echo hello-ssh && exit 0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit=%d stderr=%q", res.ExitCode, res.Stderr)
	}
	if !strings.Contains(string(res.Stdout), "hello-ssh") {
		t.Fatalf("stdout=%q", res.Stdout)
	}
}

func TestSSHRunnerNonZeroExit(t *testing.T) {
	dir := t.TempDir()
	keyPath, signer := writeKeyPair(t, dir, "id_ed25519")
	srv := startFakeSSH(t, signer.PublicKey())
	defer func() { _ = srv.Close() }()
	r, err := NewSSH(SSHConfig{
		DefaultUser: "tester", DefaultKeyPath: keyPath,
		ConnectTimeout: 5 * time.Second, CommandTimeout: 5 * time.Second,
		InsecureSkipKnownHosts: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	host := inventory.Host{Name: "fake", Address: srv.Addr(), Transport: "ssh"}
	res, err := r.Execute(context.Background(), host, ExecuteStep{
		Shell: "bash", Command: "exit 7",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 7 {
		t.Fatalf("exit=%d", res.ExitCode)
	}
}

func TestSSHHealthCheck(t *testing.T) {
	dir := t.TempDir()
	keyPath, signer := writeKeyPair(t, dir, "id_ed25519")
	srv := startFakeSSH(t, signer.PublicKey())
	defer func() { _ = srv.Close() }()
	r, err := NewSSH(SSHConfig{
		DefaultUser: "tester", DefaultKeyPath: keyPath,
		ConnectTimeout: 5 * time.Second, CommandTimeout: 5 * time.Second,
		InsecureSkipKnownHosts: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	host := inventory.Host{Name: "fake", Address: srv.Addr(), Transport: "ssh"}
	if err := r.HealthCheck(context.Background(), host); err != nil {
		t.Fatal(err)
	}
}
