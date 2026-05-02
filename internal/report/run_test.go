package report

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eavalenzuela/eyeexam/internal/store"
)

func TestBuildRunHappyPath(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(tmp, "eye.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := st.UpsertEngagement(ctx, store.Engagement{
		ID: "ENG-1", CreatedAt: rfc("2026-04-01T00:00:00Z"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertHost(ctx, store.Host{ID: "h-1", Name: "web-01", InventoryJSON: "{}"}); err != nil {
		t.Fatal(err)
	}

	mustInsertRun(t, st, "r-detail", "ENG-1", "reported", "2026-04-10T10:00:00Z")
	mustInsertExec(t, st, "x-detail-1", "r-detail", "h-1", "tA", "T1070.003", "caught", "2026-04-10T10:01:00Z")
	insertAudit(t, st, 1, "run_planned", "ENG-1", "r-detail",
		`{"os_user":"alice","os_uid":1000}`, `{"plan_size":1}`, "2026-04-10T09:59:00Z")
	insertAudit(t, st, 2, "test_executed", "ENG-1", "r-detail",
		`{"os_user":"alice","os_uid":1000}`, `{"exit_code":0}`, "2026-04-10T10:01:00Z")

	r, err := BuildRun(ctx, st, "r-detail")
	if err != nil {
		t.Fatal(err)
	}
	if r.Run.ID != "r-detail" {
		t.Errorf("run id: %s", r.Run.ID)
	}
	if len(r.Executions) != 1 {
		t.Errorf("executions: %d, want 1", len(r.Executions))
	}
	if r.HostNames["h-1"] != "web-01" {
		t.Errorf("host name: %s", r.HostNames["h-1"])
	}
	if len(r.AuditEvents) != 2 {
		t.Errorf("audit: %d, want 2", len(r.AuditEvents))
	}

	html, err := RenderHTMLRun(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"<!DOCTYPE html>",
		"Run <code>r-detail</code>",
		"web-01",
		"x-detail-1",
		"run_planned",
		"alice(uid=1000)",
	} {
		if !strings.Contains(string(html), want) {
			t.Errorf("html missing %q", want)
		}
	}

	js, err := RenderJSONRun(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), `"r-detail"`) {
		t.Errorf("json missing run id")
	}
}

func TestBuildRunRequiresID(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "eye.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, err = BuildRun(ctx, st, "")
	if err == nil {
		t.Fatal("expected error for empty run id")
	}
}

func TestBuildRunNotFound(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "eye.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, err = BuildRun(ctx, st, "r-does-not-exist")
	if err == nil {
		t.Fatal("expected not-found error")
	}
}
