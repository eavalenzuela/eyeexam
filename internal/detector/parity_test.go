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

// TestParityAcrossBackends seeds the same logical event in mock servers
// for each detector and asserts that querying the same expectation
// (sigma_id, host_hint, time window) returns one Hit per backend with
// consistent host correlation. This is the M6 acceptance test.
func TestParityAcrossBackends(t *testing.T) {
	now := time.Now().UTC()
	exp := pack.Expectation{SigmaID: "rule-parity-1"}
	q := ExpectationQuery{
		Expectation: exp,
		HostName:    "web-01",
		ExecutionID: "x-parity",
		Window:      TimeWindow{Start: now.Add(-time.Hour), End: now.Add(time.Hour)},
	}

	// Each fake server returns one matching hit when queried with
	// rule-parity-1 + web-01 in the time window.
	wazuhSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/_search") {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"hits":{"hits":[{"_id":"w-1","_source":{"@timestamp":"` +
			now.Format(time.RFC3339) + `","agent":{"name":"web-01"},"rule":{"id":"rule-parity-1"}}}]}}`))
	}))
	defer wazuhSrv.Close()

	elasticSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/_search") {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"hits":{"hits":[{"_id":"e-1","_source":{"@timestamp":"` +
			now.Format(time.RFC3339) + `","host":{"name":"web-01"},"rule":{"uuid":"rule-parity-1"}}}]}}`))
	}))
	defer elasticSrv.Close()

	splunkPolls := int32(0)
	splunkSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/jobs"):
			_, _ = w.Write([]byte(`{"sid":"sid-1"}`))
		case strings.HasSuffix(r.URL.Path, "/jobs/sid-1"):
			n := atomic.AddInt32(&splunkPolls, 1)
			state := "RUNNING"
			if n > 0 {
				state = "DONE"
			}
			body, _ := json.Marshal(map[string]any{
				"entry": []map[string]any{{"content": map[string]any{"dispatchState": state}}},
			})
			_, _ = w.Write(body)
		case strings.HasSuffix(r.URL.Path, "/jobs/sid-1/results"):
			_, _ = w.Write([]byte(`{"results":[{"_time":"` + now.Format(time.RFC3339) +
				`","host":"web-01","rule_id":"rule-parity-1","_cd":"1:1"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer splunkSrv.Close()

	lokiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Loki LogQL doesn't natively know "sigma_id"; this fake just
		// returns the canned hit for any query so parity holds.
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"streams","result":[
			{"stream":{"host":"web-01"},"values":[["` +
			itoa64(now.UnixNano()) + `","loki line"]]}
		]}}`))
	}))
	defer lokiSrv.Close()

	wd, err := NewWazuh("wazuh", WazuhConfig{URL: wazuhSrv.URL})
	if err != nil {
		t.Fatal(err)
	}
	ed, err := NewElastic("elastic", ElasticConfig{URL: elasticSrv.URL, APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	sd, err := NewSplunk("splunk", SplunkConfig{
		URL: splunkSrv.URL, Token: "t",
		PollInterval: 1 * time.Millisecond, MaxPolls: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Loki only supports query-style expectations; clone with Query set
	// for the Loki branch of the parity check.
	ld, err := NewLoki("loki", LokiConfig{URL: lokiSrv.URL})
	if err != nil {
		t.Fatal(err)
	}

	// es-style detectors: same expectation
	esCases := []struct {
		name string
		det  Detector
	}{{"wazuh", wd}, {"elastic", ed}, {"splunk", sd}}
	for _, c := range esCases {
		hits, err := c.det.Query(context.Background(), q)
		if err != nil {
			t.Fatalf("%s query: %v", c.name, err)
		}
		if len(hits) != 1 {
			t.Fatalf("%s: expected 1 hit, got %d", c.name, len(hits))
		}
		if hits[0].HostHint != "web-01" {
			t.Fatalf("%s: host hint = %q", c.name, hits[0].HostHint)
		}
	}

	// Loki uses a query expectation; same intent, different field shape.
	lokiQ := q
	lokiQ.Expectation = pack.Expectation{Query: `{host="web-01"}`}
	hits, err := ld.Query(context.Background(), lokiQ)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Fatalf("loki: expected 1 hit, got %d", len(hits))
	}
	if hits[0].HostHint != "web-01" {
		t.Fatalf("loki: host = %q", hits[0].HostHint)
	}
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
