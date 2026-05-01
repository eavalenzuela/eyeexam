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
}

type Scheduler struct {
	store  *store.Store
	audit  *audit.Logger
	engine *runlife.Engine
	log    *slog.Logger
	now    func() time.Time

	parser cron.Parser

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
		store:  opts.Store,
		audit:  opts.Audit,
		engine: opts.Engine,
		log:    opts.Logger,
		now:    opts.Now,
		parser: cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor),
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
