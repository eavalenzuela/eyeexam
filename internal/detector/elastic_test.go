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

func TestElasticAuthAndQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "ApiKey sekret" {
			http.Error(w, "auth", http.StatusUnauthorized)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/_search") {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{
			"hits":{"hits":[
				{"_id":"e1","_index":"filebeat-2026.04",
				 "_source":{"@timestamp":"2026-04-25T14:00:00Z","host":{"name":"web-01"},"rule":{"uuid":"rule-e-1"}}}
			]}
		}`))
	}))
	defer srv.Close()

	d, err := NewElastic("elastic", ElasticConfig{URL: srv.URL, APIKey: "sekret"})
	if err != nil {
		t.Fatal(err)
	}
	hits, err := d.Query(context.Background(), ExpectationQuery{
		Expectation: pack.Expectation{Query: `event.action:"history-clear"`},
		HostName:    "web-01",
		Window:      TimeWindow{Start: time.Now().Add(-time.Hour), End: time.Now()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].ID != "e1" || hits[0].HostHint != "web-01" {
		t.Fatalf("got %+v", hits)
	}
}

func TestElasticBackendFilter(t *testing.T) {
	d, err := NewElastic("elastic", ElasticConfig{URL: "http://es"})
	if err != nil {
		t.Fatal(err)
	}
	if d.Supports(pack.Expectation{Query: "x", Backend: "wazuh"}) {
		t.Fatal("elastic should not claim backend=wazuh")
	}
}
