// Package scheduler runs eyeexam schedules on a cron expression. Each
// fire builds a runlife.PlanRequest, executes the run, computes drift
// against the schedule's prior run, and dispatches alerts.
//
// The scheduler is a foreground daemon (`eyeexam scheduler run`); it does
// not background itself. Operators wire it into systemd / launchd / etc.
package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/eavalenzuela/eyeexam/internal/alert"
	"github.com/eavalenzuela/eyeexam/internal/audit"
	"github.com/eavalenzuela/eyeexam/internal/inventory"
	"github.com/eavalenzuela/eyeexam/internal/pack"
	"github.com/eavalenzuela/eyeexam/internal/runlife"
	"github.com/eavalenzuela/eyeexam/internal/score"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

type Options struct {
	Store  *store.Store
	Audit  *audit.Logger
	Engine *runlife.Engine // pre-built so all runners + detectors are wired
	Logger *slog.Logger
	Now    func() time.Time // injectable for tests

	// AuditLogPath enables periodic chain-integrity verification.
	// When non-empty and AuditVerifyInterval > 0, a background goroutine
	// walks the file + cross-checks the SQLite mirror on each interval
	// and emits an `audit_chain_broken` event if tampering is detected.
	// Sig verification is skipped here (no pub key passed) — chain
	// integrity catches the high-value tampers; full sig verification
	// is the operator-side `eyeexam audit verify`.
	AuditLogPath        string
	AuditVerifyInterval time.Duration
}

type Scheduler struct {
	store  *store.Store
	audit  *audit.Logger
	engine *runlife.Engine
	log    *slog.Logger
	now    func() time.Time

	parser cron.Parser

	auditLogPath        string
	auditVerifyInterval time.Duration

	mu     sync.Mutex
	wg     sync.WaitGroup
	cancel context.CancelFunc
}

func New(opts Options) (*Scheduler, error) {
	if opts.Store == nil {
		return nil, errors.New("scheduler: store required")
	}
	if opts.Engine == nil {
		return nil, errors.New("scheduler: engine required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Scheduler{
		store:               opts.Store,
		audit:               opts.Audit,
		engine:              opts.Engine,
		log:                 opts.Logger,
		now:                 opts.Now,
		parser:              cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor),
		auditLogPath:        opts.AuditLogPath,
		auditVerifyInterval: opts.AuditVerifyInterval,
	}, nil
}

// Run drives a tick loop until ctx is cancelled. interval determines how
// often the scheduler re-reads schedules and checks for due fires.
func (s *Scheduler) Run(ctx context.Context, interval time.Duration) error {
	if interval == 0 {
		interval = 30 * time.Second
	}
	ctx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.cancel = cancel
	s.mu.Unlock()
	defer cancel()

	t := time.NewTicker(interval)
	defer t.Stop()
	s.log.Info("scheduler started", "interval", interval.String())

	if s.auditLogPath != "" && s.auditVerifyInterval > 0 {
		s.wg.Add(1)
		go s.auditVerifyLoop(ctx)
		s.log.Info("audit verify loop started", "interval", s.auditVerifyInterval.String())
	}

	// Track per-schedule "next fire" so we don't double-fire within an
	// interval that's larger than one cron period.
	nextFire := map[string]time.Time{}

	for {
		// Tick once immediately on entry, then on each interval.
		if err := s.tick(ctx, nextFire); err != nil {
			s.log.Warn("scheduler tick failed", "err", err.Error())
		}
		select {
		case <-ctx.Done():
			s.wg.Wait()
			return ctx.Err()
		case <-t.C:
		}
	}
}

// Tick is exposed for tests: drive one tick and return.
func (s *Scheduler) Tick(ctx context.Context, nextFire map[string]time.Time) error {
	return s.tick(ctx, nextFire)
}

// VerifyAuditOnce drives one chain-integrity check + cross-check
// against the SQLite mirror. Test seam; production callers go
// through the timer-driven auditVerifyLoop. Returns the verify
// result (OK or first divergent seq) plus any I/O error.
func (s *Scheduler) VerifyAuditOnce(ctx context.Context) (audit.VerifyResult, error) {
	if s.auditLogPath == "" {
		return audit.VerifyResult{}, errors.New("scheduler: audit log path not configured")
	}
	res, err := audit.VerifyWithMirror(s.auditLogPath, nil, s.store.DB)
	if err != nil {
		return res, err
	}
	if !res.OK {
		s.handleAuditBreak(ctx, res)
	}
	return res, nil
}

func (s *Scheduler) auditVerifyLoop(ctx context.Context) {
	defer s.wg.Done()
	t := time.NewTicker(s.auditVerifyInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			res, err := audit.VerifyWithMirror(s.auditLogPath, nil, s.store.DB)
			if err != nil {
				s.log.Warn("audit verify errored (will retry next interval)",
					"err", err.Error())
				continue
			}
			if !res.OK {
				s.handleAuditBreak(ctx, res)
			}
		}
	}
}

// handleAuditBreak fires when the chain integrity check failed.
// Logs loud, appends an audit_chain_broken record (which itself
// extends the live chain past the break — the broken section is
// permanent and the next verify still reports it), and lets the
// daemon keep running. Refusing to keep running on transient
// corruption (disk error, partial write recovered next boot) is
// worse than the alternative; an attacker who could mute the
// scheduler that way has bigger options anyway.
func (s *Scheduler) handleAuditBreak(ctx context.Context, res audit.VerifyResult) {
	s.log.Error("audit chain integrity check FAILED",
		"first_bad_seq", res.FirstBadSeq,
		"reason", res.Reason,
		"records_checked", res.RecordsChecked)

	if s.audit == nil {
		return
	}
	payload, _ := json.Marshal(map[string]any{
		"first_bad_seq":   res.FirstBadSeq,
		"reason":          res.Reason,
		"records_checked": res.RecordsChecked,
	})
	_, _ = s.audit.Append(ctx, audit.Record{
		Actor:   audit.Actor{OSUser: "scheduler", OSUID: 0},
		Event:   "audit_chain_broken",
		Payload: payload,
	})
}

func (s *Scheduler) tick(ctx context.Context, nextFire map[string]time.Time) error {
	schedules, err := s.store.ListSchedules(ctx, true)
	if err != nil {
		return fmt.Errorf("scheduler: list: %w", err)
	}
	now := s.now()
	for _, sc := range schedules {
		schedSpec, err := s.parser.Parse(sc.CronExpr)
		if err != nil {
			s.log.Warn("scheduler: bad cron", "schedule", sc.Name, "expr", sc.CronExpr, "err", err.Error())
			continue
		}
		base := now
		if sc.LastRunAt.Valid {
			if t, err := time.Parse(time.RFC3339Nano, sc.LastRunAt.String); err == nil {
				base = t
			}
		}
		next, ok := nextFire[sc.Name]
		if !ok {
			next = schedSpec.Next(base)
			nextFire[sc.Name] = next
		}
		if !now.Before(next) {
			s.wg.Add(1)
			go func(sc store.Schedule) {
				defer s.wg.Done()
				if err := s.fire(ctx, sc); err != nil {
					s.log.Warn("scheduler: fire failed",
						"schedule", sc.Name, "err", err.Error())
				}
			}(sc)
			nextFire[sc.Name] = schedSpec.Next(now)
		}
	}
	return nil
}

// fire runs one scheduled execution: plan → execute → drift-vs-prior →
// alert. Errors are returned for logging; the scheduler keeps going.
func (s *Scheduler) fire(ctx context.Context, sc store.Schedule) error {
	var sel inventory.Selector
	_ = json.Unmarshal([]byte(sc.SelectorJSON), &sel)

	// Use an actor synthesised from the schedule's stored authorization
	// rather than the OS user running the daemon — schedule pre-auth is
	// the load-bearing identity for scheduled runs.
	actor := audit.Actor{OSUser: sc.AuthorizedBy, OSUID: 0}
	var appUser *string
	if sc.AppUser.Valid && sc.AppUser.String != "" {
		v := sc.AppUser.String
		actor.AppUser = &v
		appUser = &v
	}

	priorRunID, _ := s.store.PriorRunForSchedule(ctx, sc, "")

	runID, _, err := s.engine.Plan(ctx, runlife.PlanRequest{
		EngagementID: sc.EngagementID,
		Authorized:   true,
		MaxDest:      pack.Dest(sc.MaxDest),
		PackName:     sc.PackName,
		Selector:     sel,
		Actor:        actor,
		AppUser:      appUser,
	})
	if err != nil {
		return fmt.Errorf("plan: %w", err)
	}

	// Audit: scheduled fires emit run_start with trigger=schedule per
	// PLAN.md / IMPLEMENTATION.md M8 DoD.
	if s.audit != nil {
		payload, _ := json.Marshal(map[string]any{
			"schedule":   sc.Name,
			"trigger":    "schedule",
			"prior_run":  priorRunID,
			"engagement": sc.EngagementID,
		})
		_, _ = s.audit.Append(ctx, audit.Record{
			Actor: actor, Engagement: sc.EngagementID, RunID: runID,
			Event: "run_start", Payload: payload,
		})
	}

	if err := s.engine.Execute(ctx, runID, actor); err != nil {
		return fmt.Errorf("execute %s: %w", runID, err)
	}
	if err := s.store.MarkScheduleRan(ctx, sc.ID, runID); err != nil {
		return fmt.Errorf("mark ran: %w", err)
	}

	if priorRunID == "" {
		return nil // no comparison available yet
	}
	regs, err := score.CompareRuns(ctx, s.store, priorRunID, runID)
	if err != nil {
		return fmt.Errorf("drift: %w", err)
	}
	if len(regs) == 0 {
		return nil
	}

	var sinkConfigs []alert.SinkConfig
	if sc.AlertsJSON != "" {
		_ = json.Unmarshal([]byte(sc.AlertsJSON), &sinkConfigs)
	}
	sinks, err := alert.BuildSinks(sinkConfigs)
	if err != nil {
		return fmt.Errorf("sinks: %w", err)
	}

	bundle := alert.Bundle{
		ScheduleName: sc.Name,
		RunID:        runID,
		PriorRunID:   priorRunID,
		Engagement:   sc.EngagementID,
		GeneratedAt:  s.now(),
	}
	for _, r := range regs {
		bundle.Regressions = append(bundle.Regressions, alert.Regression{
			ScheduleName: sc.Name,
			Engagement:   sc.EngagementID,
			RunID:        runID,
			PriorRunID:   priorRunID,
			TechniqueID:  r.Technique,
			From:         string(r.From),
			To:           string(r.To),
			At:           r.At,
		})
	}

	alert.Send(ctx, sinks, bundle, func(name string, err error) {
		s.log.Warn("alert send failed", "sink", name, "err", err.Error())
	})

	if s.audit != nil {
		payload, _ := json.Marshal(map[string]any{
			"schedule":    sc.Name,
			"run_id":      runID,
			"prior_run":   priorRunID,
			"regressions": bundle.Regressions,
		})
		_, _ = s.audit.Append(ctx, audit.Record{
			Actor: actor, Engagement: sc.EngagementID, RunID: runID,
			Event: "drift_alerted", Payload: payload,
		})
	}
	return nil
}
