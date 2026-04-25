package detector

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/pack"
)

// buildESQuery builds an Elasticsearch / OpenSearch query DSL body for an
// expectation in a time window. Wazuh and Elastic both speak this dialect
// (Wazuh's indexer is OpenSearch which forked from ES 7).
//
// Strategy:
//   - Time range on @timestamp (configurable field).
//   - Free `query` strings go through query_string for max compatibility.
//   - Sigma rule ids and tags map to term filters on operator-configured
//     fields; the defaults match what the Sigma → ES converter typically
//     produces.
//   - Optional host_hint maps to a term filter so events without
//     correlation labels still get scoped.
func buildESQuery(e pack.Expectation, hostHint, hostField, ruleField, tagField, timestampField string, window TimeWindow, size int) ([]byte, error) {
	if size <= 0 {
		size = 200
	}
	if timestampField == "" {
		timestampField = "@timestamp"
	}
	if hostField == "" {
		hostField = "agent.name"
	}
	if ruleField == "" {
		ruleField = "rule.id"
	}
	if tagField == "" {
		tagField = "rule.mitre.tactic"
	}

	must := []map[string]any{
		{
			"range": map[string]any{
				timestampField: map[string]any{
					"gte":    window.Start.UTC().Format(time.RFC3339Nano),
					"lte":    window.End.UTC().Format(time.RFC3339Nano),
					"format": "strict_date_optional_time",
				},
			},
		},
	}
	if e.Query != "" {
		must = append(must, map[string]any{
			"query_string": map[string]any{"query": e.Query, "default_operator": "AND"},
		})
	}
	if e.SigmaID != "" {
		must = append(must, map[string]any{"term": map[string]any{ruleField: e.SigmaID}})
	}
	if e.Tag != "" {
		must = append(must, map[string]any{"term": map[string]any{tagField: e.Tag}})
	}
	if hostHint != "" {
		// host hint is best-effort — wrap in a should so it doesn't filter
		// out events on hosts whose label scheme we don't know.
		must = append(must, map[string]any{
			"bool": map[string]any{
				"should": []map[string]any{
					{"term": map[string]any{hostField: hostHint}},
					{"term": map[string]any{"host.name": hostHint}},
					{"term": map[string]any{"hostname": hostHint}},
				},
				"minimum_should_match": 1,
			},
		})
	}

	body := map[string]any{
		"size": size,
		"sort": []any{map[string]any{timestampField: map[string]any{"order": "asc"}}},
		"query": map[string]any{
			"bool": map[string]any{"must": must},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("esquery: marshal: %w", err)
	}
	return b, nil
}

// esResponse is the subset of the ES/OpenSearch search response we read.
type esResponse struct {
	Hits struct {
		Hits []struct {
			ID     string          `json:"_id"`
			Index  string          `json:"_index"`
			Source json.RawMessage `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

// extractESHits maps an ES/OpenSearch response into eyeexam Hits. tsField
// is the path inside _source to the event timestamp, e.g. "@timestamp".
func extractESHits(body []byte, q ExpectationQuery, tsField string) ([]Hit, error) {
	var resp esResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("esquery: parse response: %w", err)
	}
	out := make([]Hit, 0, len(resp.Hits.Hits))
	for _, h := range resp.Hits.Hits {
		var src map[string]any
		_ = json.Unmarshal(h.Source, &src)
		ts := pickTimestamp(src, tsField)
		hostHint := pickStringPath(src, "agent.name")
		if hostHint == "" {
			hostHint = pickStringPath(src, "host.name")
		}
		if hostHint == "" {
			hostHint = q.HostName
		}
		out = append(out, Hit{
			ID:       h.ID,
			At:       ts,
			HostHint: hostHint,
			Raw:      h.Source,
		})
	}
	return out, nil
}

func pickTimestamp(src map[string]any, field string) time.Time {
	if field == "" {
		field = "@timestamp"
	}
	v, ok := src[field]
	if !ok {
		return time.Time{}
	}
	s, ok := v.(string)
	if !ok {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t, _ = time.Parse(time.RFC3339, s)
	}
	return t
}

// pickStringPath looks up a dotted path like "agent.name" against a
// nested map[string]any, supporting both the dotted form and the nested
// form (ECS / OCSF mix in the wild).
func pickStringPath(src map[string]any, path string) string {
	if v, ok := src[path]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	parts := splitDots(path)
	cur := any(src)
	for _, p := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur, ok = m[p]
		if !ok {
			return ""
		}
	}
	if s, ok := cur.(string); ok {
		return s
	}
	return ""
}

func splitDots(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}
