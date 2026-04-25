package detector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/pack"
)

// fakeSplunk implements just enough of /servicesNS/-/<app>/search/v2/jobs
// to satisfy the create → poll → results flow.
type fakeSplunk struct {
	pollsBeforeDone int32
	polls           int32
	t               *testing.T
}

func (f *fakeSplunk) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/jobs"):
			if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
				http.Error(w, "auth", http.StatusUnauthorized)
				return
			}
			_ = r.ParseForm()
			search := r.PostForm.Get("search")
			if !strings.Contains(search, `rule_id="rule-s-1"`) {
				http.Error(w, "wrong spl", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"sid":"job-1"}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/jobs/job-1"):
			n := atomic.AddInt32(&f.polls, 1)
			state := "RUNNING"
			if n > f.pollsBeforeDone {
				state = "DONE"
			}
			body, _ := json.Marshal(map[string]any{
				"entry": []map[string]any{
					{"content": map[string]any{"dispatchState": state}},
				},
			})
			_, _ = w.Write(body)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/jobs/job-1/results"):
			_, _ = w.Write([]byte(`{"results":[{"_time":"2026-04-25T14:00:00Z","host":"web-01","rule_id":"rule-s-1","_cd":"42:99"}]}`))
		default:
			http.NotFound(w, r)
		}
	}
}

func TestSplunkSearchFlow(t *testing.T) {
	fs := &fakeSplunk{pollsBeforeDone: 1, t: t}
	srv := httptest.NewServer(fs.handler())
	defer srv.Close()
	d, err := NewSplunk("splunk", SplunkConfig{
		URL: srv.URL, Token: "tok", PollInterval: 5 * time.Millisecond, MaxPolls: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Supports(pack.Expectation{SigmaID: "rule-s-1"}) {
		t.Fatal("should support sigma id")
	}
	hits, err := d.Query(context.Background(), ExpectationQuery{
		Expectation: pack.Expectation{SigmaID: "rule-s-1"},
		HostName:    "web-01",
		Window:      TimeWindow{Start: time.Now().Add(-time.Hour), End: time.Now()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Fatalf("hits=%+v", hits)
	}
	if hits[0].HostHint != "web-01" {
		t.Fatalf("host=%s", hits[0].HostHint)
	}
	if !strings.HasPrefix(hits[0].ID, "splunk-") {
		t.Fatalf("id=%s", hits[0].ID)
	}
}

func TestSplunkBackendFilter(t *testing.T) {
	d, _ := NewSplunk("splunk", SplunkConfig{URL: "http://x"})
	if d.Supports(pack.Expectation{Query: "x", Backend: "elastic"}) {
		t.Fatal("splunk should not claim backend=elastic")
	}
}
