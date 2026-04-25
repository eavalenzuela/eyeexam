package alert

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"time"
)

// Webhook posts the bundle JSON to URL with a 10s timeout. Used for
// generic SOC integrations (PagerDuty events API, custom endpoints).
type Webhook struct {
	name string
	url  string
	cl   *http.Client
}

func NewWebhook(name, url string) *Webhook {
	if name == "" {
		name = "webhook"
	}
	return &Webhook{name: name, url: url, cl: &http.Client{Timeout: 10 * time.Second}}
}

func (w *Webhook) Name() string { return w.name }

func (w *Webhook) Send(ctx context.Context, b Bundle) error {
	body := mustJSON(b)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.cl.Do(req)
	if err != nil {
		return fmt.Errorf("webhook %s: %w", w.name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("webhook %s: status %d", w.name, resp.StatusCode)
	}
	return nil
}
