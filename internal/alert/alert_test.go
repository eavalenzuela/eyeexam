package alert

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func sampleBundle() Bundle {
	return Bundle{
		ScheduleName: "nightly",
		RunID:        "r-1",
		PriorRunID:   "r-0",
		Engagement:   "TEST",
		GeneratedAt:  time.Now().UTC(),
		Regressions: []Regression{
			{TechniqueID: "T1070", TechniqueName: "Indicator Removal", From: "caught", To: "missed", At: time.Now().UTC()},
		},
	}
}

func TestWebhookPostsJSON(t *testing.T) {
	got := make(chan Bundle, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b Bundle
		_ = json.NewDecoder(r.Body).Decode(&b)
		got <- b
	}))
	defer srv.Close()
	w := NewWebhook("hook", srv.URL)
	if err := w.Send(context.Background(), sampleBundle()); err != nil {
		t.Fatal(err)
	}
	b := <-got
	if b.ScheduleName != "nightly" || len(b.Regressions) != 1 || b.Regressions[0].TechniqueID != "T1070" {
		t.Fatalf("unexpected payload: %+v", b)
	}
}

func TestNtfyPlainText(t *testing.T) {
	got := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- string(body)
	}))
	defer srv.Close()
	n := NewNtfy("n", srv.URL, "alerts")
	if err := n.Send(context.Background(), sampleBundle()); err != nil {
		t.Fatal(err)
	}
	body := <-got
	if !strings.Contains(body, "T1070 — caught → missed") {
		t.Fatalf("ntfy body=%q", body)
	}
}

func TestDiscordEmbeds(t *testing.T) {
	got := make(chan map[string]any, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p map[string]any
		_ = json.NewDecoder(r.Body).Decode(&p)
		got <- p
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	d := NewDiscord("d", srv.URL)
	if err := d.Send(context.Background(), sampleBundle()); err != nil {
		t.Fatal(err)
	}
	p := <-got
	if _, ok := p["embeds"]; !ok {
		t.Fatalf("expected embeds in discord payload: %+v", p)
	}
}

func TestBuildSinksFromConfigs(t *testing.T) {
	sinks, err := BuildSinks([]SinkConfig{
		{Name: "h", Type: "webhook", URL: "http://x"},
		{Name: "n", Type: "ntfy", URL: "http://y", Opts: map[string]any{"topic": "alerts"}},
		{Name: "d", Type: "discord", URL: "http://z"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(sinks) != 3 {
		t.Fatalf("expected 3 sinks, got %d", len(sinks))
	}
}
