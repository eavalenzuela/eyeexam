package runner

import (
	"context"
	"strings"
	"testing"

	"github.com/eavalenzuela/eyeexam/internal/inventory"
)

func TestLocalEcho(t *testing.T) {
	l := NewLocal()
	host := inventory.Host{Name: "localhost", Transport: "local"}
	res, err := l.Execute(context.Background(), host, ExecuteStep{
		Shell: "bash", Command: "echo hello",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit=%d", res.ExitCode)
	}
	if !strings.Contains(string(res.Stdout), "hello") {
		t.Fatalf("stdout=%q", res.Stdout)
	}
}

func TestLocalExitCode(t *testing.T) {
	l := NewLocal()
	res, err := l.Execute(context.Background(), inventory.Host{}, ExecuteStep{
		Shell: "bash", Command: "exit 7",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 7 {
		t.Fatalf("exit=%d", res.ExitCode)
	}
}
