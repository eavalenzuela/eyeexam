package runlife

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/audit"
	"github.com/eavalenzuela/eyeexam/internal/idgen"
	"github.com/eavalenzuela/eyeexam/internal/inventory"
	"github.com/eavalenzuela/eyeexam/internal/pack"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

// PlanRequest describes what to plan. The engine resolves it against the
// pack registry + inventory and persists the resulting run.
type PlanRequest struct {
	EngagementID string
	Authorized   bool
	MaxDest      pack.Dest
	PackName     string
	Selector     inventory.Selector
	Seed         int64
	Actor        audit.Actor
	AppUser      *string
}

// PlannedTest is one (host, test) tuple in the resolved plan.
type PlannedTest struct {
	HostName string `json:"host"`
	HostID   string `json:"host_id"`
	TestID   string `json:"test_id"`
}

type Plan struct {
	Tests   []PlannedTest `json:"tests"`
	Refused []string      `json:"refused"` // refused test ids
	Skipped []SkipNote    `json:"skipped"` // skipped + reason (cap, platform, glob)
}

type SkipNote struct {
	HostName string `json:"host"`
	TestID   string `json:"test_id"`
	Reason   string `json:"reason"`
}

// Plan resolves req into a concrete plan and persists a `planned` Run row.
// Returns the runID.
func (e *Engine) Plan(ctx context.Context, req PlanRequest) (string, *Plan, error) {
	if req.EngagementID == "" {
		return "", nil, fmt.Errorf("runlife: engagement id required")
	}
	if !req.Authorized {
		return "", nil, fmt.Errorf("runlife: --authorized required")
	}
	if req.MaxDest == "" {
		req.MaxDest = pack.DestLow
	}

	hosts, warns, err := e.inv.Apply(req.Selector)
	if err != nil {
		return "", nil, err
	}
	for _, w := range warns {
		e.log.Warn("selector", "msg", w)
	}
	if len(hosts) == 0 {
		return "", nil, fmt.Errorf("runlife: selector matched zero hosts")
	}

	allowed, refusedTests, err := e.reg.FromPack(req.PackName)
	if err != nil {
		return "", nil, err
	}

	// Apply test-id glob filter from selector.
	var pickedTests []pack.Test
	for _, t := range allowed {
		if !req.Selector.MatchTestID(t.ID) {
			continue
		}
		pickedTests = append(pickedTests, t)
	}

	plan := &Plan{}
	for _, t := range refusedTests {
		plan.Refused = append(plan.Refused, t.ID)
	}

	// Deterministic order: sort hosts by name, tests by id, then shuffle by seed.
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Name < hosts[j].Name })
	sort.Slice(pickedTests, func(i, j int) bool { return pickedTests[i].ID < pickedTests[j].ID })

	for _, h := range hosts {
		hostCap := e.inv.CapForHost(h)
		// the run-level cap also applies
		effectiveCap := hostCap
		if req.MaxDest.Rank() < effectiveCap.Rank() {
			effectiveCap = req.MaxDest
		}
		for _, t := range pickedTests {
			if !platformAllowed(t.Platforms, hostPlatform(h)) {
				plan.Skipped = append(plan.Skipped, SkipNote{
					HostName: h.Name, TestID: t.ID,
					Reason: fmt.Sprintf("platform mismatch: host=%s test=%v",
						hostPlatform(h), t.Platforms),
				})
				continue
			}
			if !t.Destructiveness.AtMost(effectiveCap) {
				plan.Skipped = append(plan.Skipped, SkipNote{
					HostName: h.Name, TestID: t.ID,
					Reason: fmt.Sprintf("destructiveness %s exceeds cap %s",
						t.Destructiveness, effectiveCap),
				})
				continue
			}
			plan.Tests = append(plan.Tests, PlannedTest{
				HostName: h.Name,
				TestID:   t.ID,
			})
		}
	}

	if req.Seed != 0 {
		r := rand.New(rand.NewSource(req.Seed))
		r.Shuffle(len(plan.Tests), func(i, j int) {
			plan.Tests[i], plan.Tests[j] = plan.Tests[j], plan.Tests[i]
		})
	}

	if len(plan.Tests) == 0 {
		return "", plan, fmt.Errorf("runlife: plan empty after filtering (refused=%d skipped=%d)",
			len(plan.Refused), len(plan.Skipped))
	}

	// Persist hosts referenced by plan.
	for _, h := range hosts {
		if !planUsesHost(plan, h.Name) {
			continue
		}
		invJSON, _ := json.Marshal(h)
		hostRow := store.Host{
			ID:            idgen.Host(),
			Name:          h.Name,
			InventoryJSON: string(invJSON),
		}
		if err := e.store.UpsertHost(ctx, hostRow); err != nil {
			return "", nil, err
		}
	}
	// fill in HostIDs in the plan
	for i := range plan.Tests {
		row, err := e.store.GetHostByName(ctx, plan.Tests[i].HostName)
		if err != nil {
			return "", nil, err
		}
		plan.Tests[i].HostID = row.ID
	}

	// Persist engagement + run.
	if err := e.store.UpsertEngagement(ctx, store.Engagement{
		ID: req.EngagementID, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}); err != nil {
		return "", nil, err
	}

	selJSON, _ := json.Marshal(req.Selector)
	planJSON, _ := json.Marshal(plan)
	runID := idgen.Run()
	r := store.Run{
		ID: runID, EngagementID: req.EngagementID, Seed: req.Seed,
		MaxDest: string(req.MaxDest), SelectorJSON: string(selJSON),
		PlanJSON: string(planJSON), Phase: "planned",
		AuthorizedBy: req.Actor.String(),
	}
	if req.AppUser != nil {
		r.AppUser.Valid = true
		r.AppUser.String = *req.AppUser
	}
	if err := e.store.InsertRun(ctx, r); err != nil {
		return "", nil, err
	}

	if e.audit != nil {
		payload, _ := json.Marshal(map[string]any{
			"pack":      req.PackName,
			"selector":  req.Selector,
			"max_dest":  req.MaxDest,
			"plan_size": len(plan.Tests),
			"refused":   plan.Refused,
			"skipped":   plan.Skipped,
		})
		if _, err := e.audit.Append(ctx, audit.Record{
			Actor: req.Actor, Engagement: req.EngagementID, RunID: runID,
			Event: "run_planned", Payload: payload,
		}); err != nil {
			return "", nil, err
		}
		for _, refusedID := range plan.Refused {
			p, _ := json.Marshal(map[string]string{"test_id": refusedID})
			if _, err := e.audit.Append(ctx, audit.Record{
				Actor: req.Actor, Engagement: req.EngagementID, RunID: runID,
				Event: "test_refused", Payload: p,
			}); err != nil {
				return "", nil, err
			}
		}
		for _, sk := range plan.Skipped {
			p, _ := json.Marshal(sk)
			if _, err := e.audit.Append(ctx, audit.Record{
				Actor: req.Actor, Engagement: req.EngagementID, RunID: runID,
				Event: "test_skipped", Payload: p,
			}); err != nil {
				return "", nil, err
			}
		}
	}

	return runID, plan, nil
}

func planUsesHost(p *Plan, name string) bool {
	for _, t := range p.Tests {
		if t.HostName == name {
			return true
		}
	}
	return false
}

func platformAllowed(platforms []string, host string) bool {
	if len(platforms) == 0 {
		return true
	}
	for _, p := range platforms {
		if p == host {
			return true
		}
	}
	return false
}

func hostPlatform(h inventory.Host) string {
	for _, t := range h.Tags {
		switch t {
		case "linux", "darwin", "windows":
			return t
		}
	}
	return "linux" // M1 default
}
