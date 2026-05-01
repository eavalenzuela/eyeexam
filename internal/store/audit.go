package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// AuditRow mirrors one row of the audit_log table. It's a *read*
// projection — Append is owned by package audit. Hash and signature are
// included so consumers can show "this record's chain hash" without
// needing to recompute it from the file.
type AuditRow struct {
	Seq          int64          `db:"seq"`
	TS           string         `db:"ts"`
	ActorJSON    string         `db:"actor_json"`
	EngagementID sql.NullString `db:"engagement_id"`
	RunID        sql.NullString `db:"run_id"`
	Event        string         `db:"event"`
	PayloadJSON  string         `db:"payload_json"`
	PrevHash     string         `db:"prev_hash"`
	Hash         string         `db:"hash"`
	Signature    string         `db:"signature"`
}

// AuditFilter narrows ListAudit. Empty strings mean "no constraint".
// SinceTS / UntilTS are RFC3339Nano timestamps compared lexicographically
// against ts (which is stored as RFC3339Nano UTC, so this works).
type AuditFilter struct {
	RunID        string
	EngagementID string
	Event        string
	Actor        string // matches against actor_json LIKE %actor% — operator can pass "alice" or "alice@example.com"
	SinceTS      string
	UntilTS      string
	Limit        int // 0 → 200
}

// ListAudit reads audit_log rows matching the filter, ordered by seq
// ascending so consumers see them in the order they were appended.
func (s *Store) ListAudit(ctx context.Context, f AuditFilter) ([]AuditRow, error) {
	q := `SELECT seq, ts, actor_json, engagement_id, run_id, event,
	             payload_json, prev_hash, hash, signature
	      FROM audit_log`
	var clauses []string
	var args []any
	if f.RunID != "" {
		clauses = append(clauses, `run_id = ?`)
		args = append(args, f.RunID)
	}
	if f.EngagementID != "" {
		clauses = append(clauses, `engagement_id = ?`)
		args = append(args, f.EngagementID)
	}
	if f.Event != "" {
		clauses = append(clauses, `event = ?`)
		args = append(args, f.Event)
	}
	if f.Actor != "" {
		clauses = append(clauses, `actor_json LIKE ?`)
		args = append(args, "%"+f.Actor+"%")
	}
	if f.SinceTS != "" {
		clauses = append(clauses, `ts >= ?`)
		args = append(args, f.SinceTS)
	}
	if f.UntilTS != "" {
		clauses = append(clauses, `ts < ?`)
		args = append(args, f.UntilTS)
	}
	if len(clauses) > 0 {
		q += ` WHERE ` + strings.Join(clauses, ` AND `)
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	q += ` ORDER BY seq ASC LIMIT ?`
	args = append(args, limit)

	var out []AuditRow
	if err := s.DB.SelectContext(ctx, &out, q, args...); err != nil {
		return nil, fmt.Errorf("store: list audit: %w", err)
	}
	return out, nil
}
