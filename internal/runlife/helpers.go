package runlife

import (
	"context"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/store"
)

func nonEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func parseTimeOrZero(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func durSecs(n int) time.Duration { return time.Duration(n) * time.Second }

func (e *Engine) execByID(ctx context.Context, id string) (store.Execution, error) {
	var ex store.Execution
	err := e.store.DB.GetContext(ctx, &ex, `SELECT * FROM executions WHERE id = ?`, id)
	return ex, err
}
