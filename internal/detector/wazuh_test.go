package detector

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/pack"
)

func TestWazuhQueryHit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/_search") {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]any
		_ = json.Unmarshal(body, &parsed)
		// Must contain a bool/must with a range and a term on rule.id.
		want := `"rule.id":"rule-w-1"`
		if !strings.Contains(string(body), want) {
			http.Error(w, "missing rule.id filter", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{
			"hits": {"hits": [
				{"_id":"abc1","_index":"wazuh-alerts-2026.04",
				 "_source":{"@timestamp":"2026-04-25T14:00:00Z","rule":{"id":"rule-w-1"},"agent":{"name":"web-01"}}}
			]}
		}`))
	}))
	defer srv.Close()

	d, err := NewWazuh("wazuh", WazuhConfig{URL: srv.URL, Username: "admin", Password: "changeme"})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Supports(pack.Expectation{SigmaID: "rule-w-1"}) {
		t.Fatal("should support sigma id")
	}
	hits, err := d.Query(context.Background(), ExpectationQuery{
		Expectation: pack.Expectation{SigmaID: "rule-w-1"},
		HostName:    "web-01",
		Window:      TimeWindow{Start: time.Now().Add(-time.Hour), End: time.Now()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].ID != "abc1" {
		t.Fatalf("got %+v", hits)
	}
	if hits[0].HostHint != "web-01" {
		t.Fatalf("host=%s", hits[0].HostHint)
	}
}
