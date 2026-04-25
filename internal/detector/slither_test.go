package detector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/pack"
)

func TestSlitherQueryHit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/query" {
			http.NotFound(w, r)
			return
		}
		var got slitherQueryReq
		_ = json.NewDecoder(r.Body).Decode(&got)
		if got.SigmaID != "abc-123" {
			http.Error(w, "wrong sigma_id", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(slitherQueryResp{
			Hits: []slitherHit{{
				ID:    "hit-1",
				At:    time.Now().UTC(),
				Host:  "web-01",
				Event: json.RawMessage(`{"rule":"abc-123"}`),
			}},
		})
	}))
	defer srv.Close()

	d, err := NewSlither("slither", SlitherConfig{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	hits, err := d.Query(context.Background(), ExpectationQuery{
		Expectation: pack.Expectation{SigmaID: "abc-123"},
		HostName:    "web-01",
		Window:      TimeWindow{Start: time.Now().Add(-time.Hour), End: time.Now()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].ID != "hit-1" {
		t.Fatalf("got %+v", hits)
	}
}

func TestSlitherSupports(t *testing.T) {
	d, _ := NewSlither("slither", SlitherConfig{URL: "http://x"})
	if !d.Supports(pack.Expectation{SigmaID: "x"}) {
		t.Fatal("should support sigma id")
	}
	if !d.Supports(pack.Expectation{Tag: "attack.t1059"}) {
		t.Fatal("should support tag")
	}
	if d.Supports(pack.Expectation{Query: "x", Backend: "loki"}) {
		t.Fatal("should not claim loki backend")
	}
}
