package detector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/pack"
)

func TestLokiQueryHit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/query_range") {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("query") == "" {
			http.Error(w, "missing query", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"status":"success",
			"data":{
				"resultType":"streams",
				"result":[{
					"stream":{"host":"web-01","app":"sshd"},
					"values":[
						["1735689600000000000","sshd: invalid user root from 10.0.0.5"],
						["1735689601000000000","sshd: connection from 10.0.0.5 closed"]
					]
				}]
			}
		}`))
	}))
	defer srv.Close()

	d, err := NewLoki("loki", LokiConfig{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Supports(pack.Expectation{Query: "{app=\"sshd\"}"}) {
		t.Fatal("loki should support query expectations")
	}

	hits, err := d.Query(context.Background(), ExpectationQuery{
		Expectation: pack.Expectation{Query: `{app="sshd"} |= "invalid user"`},
		ExecutionID: "x-1",
		HostName:    "web-01",
		Window: TimeWindow{
			Start: time.Now().Add(-1 * time.Hour),
			End:   time.Now(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 2 {
		t.Fatalf("expected 2 hits, got %d", len(hits))
	}
	if hits[0].HostHint != "web-01" {
		t.Fatalf("host=%q", hits[0].HostHint)
	}
}

func TestLokiQueryNoHits(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"streams","result":[]}}`))
	}))
	defer srv.Close()
	d, err := NewLoki("loki", LokiConfig{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	hits, err := d.Query(context.Background(), ExpectationQuery{
		Expectation: pack.Expectation{Query: `{app="sshd"}`},
		Window: TimeWindow{
			Start: time.Now().Add(-1 * time.Hour),
			End:   time.Now(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("expected 0 hits, got %d", len(hits))
	}
}

func TestLokiBackendFilter(t *testing.T) {
	d, err := NewLoki("loki", LokiConfig{URL: "http://loki.example"})
	if err != nil {
		t.Fatal(err)
	}
	if d.Supports(pack.Expectation{Query: "x", Backend: "elastic"}) {
		t.Fatal("loki should not support backend=elastic")
	}
}
