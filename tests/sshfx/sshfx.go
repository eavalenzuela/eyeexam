// Package sshfx provides a small in-process SSH server fixture for tests
// that need a real SSH daemon endpoint without depending on docker or a
// system sshd. Tests construct a Server, hand its public key to the SSH
// runner, and Close it on teardown. exec channel requests are dispatched
// to bash -c on the host running the test.
package sshfx

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

type Server struct {
	listener net.Listener
	signer   ssh.Signer
	authKey  ssh.PublicKey
	wg       sync.WaitGroup
	stop     chan struct{}
}

// Start launches a fixture server bound to 127.0.0.1:0 that authenticates
// connections presenting authKey.
func Start(t *testing.T, authKey ssh.PublicKey) *Server {
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
	s := &Server{listener: ln, signer: signer, authKey: authKey, stop: make(chan struct{})}
	s.wg.Add(1)
	go s.acceptLoop(t)
	return s
}

func (s *Server) Addr() string { return s.listener.Addr().String() }

func (s *Server) Close() error {
	close(s.stop)
	err := s.listener.Close()
	s.wg.Wait()
	return err
}

func (s *Server) acceptLoop(t *testing.T) {
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
				t.Logf("sshfx: accept: %v", err)
				return
			}
		}
		s.wg.Add(1)
		go s.handle(t, c, cfg)
	}
}

func (s *Server) handle(t *testing.T, nc net.Conn, cfg *ssh.ServerConfig) {
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
			t.Logf("sshfx: accept channel: %v", err)
			continue
		}
		go s.handleSession(ch, requests)
	}
}

func (s *Server) handleSession(ch ssh.Channel, requests <-chan *ssh.Request) {
	for req := range requests {
		switch req.Type {
		case "exec":
			payload := struct{ Cmd string }{}
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				_ = req.Reply(false, nil)
				return
			}
			_ = req.Reply(true, nil)
			runExec(ch, payload.Cmd)
			return
		case "env":
			_ = req.Reply(true, nil)
		default:
			_ = req.Reply(false, nil)
		}
	}
}

func runExec(ch ssh.Channel, command string) {
	defer func() { _ = ch.Close() }()
	c := exec.Command("bash", "-c", command)
	c.Stdout = ch
	c.Stderr = ch.Stderr()
	exit := 0
	if err := c.Run(); err != nil {
		var ee *exec.ExitError
		if asExitError(err, &ee) {
			exit = ee.ExitCode()
		} else {
			exit = 255
		}
	}
	status := struct{ Status uint32 }{Status: uint32(exit)}
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(&status))
}

func asExitError(err error, target **exec.ExitError) bool {
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

// WriteKeyPair writes an ed25519 private key in OpenSSH PEM format under
// dir/name and returns (privPath, signer). The signer's public key can be
// passed to Start to authorize the runner's auth attempts.
func WriteKeyPair(t *testing.T, dir, name string) (string, ssh.Signer) {
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
