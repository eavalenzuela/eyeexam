package alert

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Ntfy posts a plain-text notification to an ntfy.sh-compatible server.
// URL is the base (https://ntfy.sh) and Topic is the notification topic
// — eyeexam appends Topic to URL per the ntfy publish convention.
type Ntfy struct {
	name  string
	base  string
	topic string
	cl    *http.Client
}

func NewNtfy(name, base, topic string) *Ntfy {
	if name == "" {
		name = "ntfy"
	}
	if topic == "" {
		topic = "eyeexam"
	}
	return &Ntfy{name: name, base: strings.TrimRight(base, "/"), topic: topic, cl: &http.Client{Timeout: 10 * time.Second}}
}

func (n *Ntfy) Name() string { return n.name }

func (n *Ntfy) Send(ctx context.Context, b Bundle) error {
	if len(b.Regressions) == 0 {
		return nil
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "eyeexam: %d regression(s) on schedule %s (run %s)\n",
		len(b.Regressions), b.ScheduleName, b.RunID)
	for _, r := range b.Regressions {
		fmt.Fprintf(&sb, "  %s — %s → %s\n", r.TechniqueID, r.From, r.To)
	}
	url := n.base + "/" + n.topic
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(sb.String()))
	if err != nil {
		return err
	}
	req.Header.Set("Title", fmt.Sprintf("eyeexam regression(s) on %s", b.ScheduleName))
	req.Header.Set("Priority", "high")
	req.Header.Set("Tags", "rotating_light,siren")
	resp, err := n.cl.Do(req)
	if err != nil {
		return fmt.Errorf("ntfy %s: %w", n.name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("ntfy %s: status %d", n.name, resp.StatusCode)
	}
	return nil
}
