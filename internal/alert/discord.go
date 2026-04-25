package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Discord posts a Discord-webhook-shaped payload.
// https://discord.com/developers/docs/resources/webhook#execute-webhook
type Discord struct {
	name string
	url  string
	cl   *http.Client
}

func NewDiscord(name, url string) *Discord {
	if name == "" {
		name = "discord"
	}
	return &Discord{name: name, url: url, cl: &http.Client{Timeout: 10 * time.Second}}
}

func (d *Discord) Name() string { return d.name }

func (d *Discord) Send(ctx context.Context, b Bundle) error {
	if len(b.Regressions) == 0 {
		return nil
	}
	var fields []map[string]any
	for _, r := range b.Regressions {
		fields = append(fields, map[string]any{
			"name":   r.TechniqueID,
			"value":  fmt.Sprintf("%s → **%s** (%s)", r.From, r.To, r.At.Format(time.RFC3339)),
			"inline": true,
		})
	}
	embed := map[string]any{
		"title":       fmt.Sprintf("eyeexam: %d regression(s) on %s", len(b.Regressions), b.ScheduleName),
		"description": fmt.Sprintf("Run %s · engagement %s", b.RunID, b.Engagement),
		"color":       15158332, // red
		"fields":      fields,
		"timestamp":   b.GeneratedAt.Format(time.RFC3339),
	}
	payload := map[string]any{
		"username": "eyeexam",
		"embeds":   []any{embed},
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.cl.Do(req)
	if err != nil {
		return fmt.Errorf("discord %s: %w", d.name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	// Discord returns 204 on success.
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("discord %s: status %d", d.name, resp.StatusCode)
	}
	return nil
}
