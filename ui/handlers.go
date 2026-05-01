package ui

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/matrix"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

func (s *Server) routes(mux *http.ServeMux) {
	mux.Handle("/static/", http.FileServer(http.FS(assets)))
	mux.HandleFunc("/", s.handleHome)
	mux.HandleFunc("/runs", s.handleRunsList)
	mux.HandleFunc("/runs/", s.handleRunDetail) // /runs/<id>
	mux.HandleFunc("/matrix", s.handleMatrix)
	mux.HandleFunc("/matrix.json", s.handleMatrixJSON)
}

// pages maps logical page names to their parsed template. Each page is
// parsed independently with base.html so the {{define "content"}} block
// in one page doesn't overwrite another's. (html/template's ParseFS
// merges all "define" blocks into a single namespace; that's wrong for
// multi-page sites.)
var pages = func() map[string]*template.Template {
	out := map[string]*template.Template{}
	for _, name := range []string{"home.html", "runs_list.html", "run_detail.html", "matrix.html"} {
		t := template.Must(template.New(name).Funcs(template.FuncMap{
			"detectClass": detectClass,
		}).ParseFS(assets, "templates/base.html", "templates/"+name))
		out[name] = t
	}
	return out
}()

// detectClass maps an executions.detection_state / expected_detection.state
// value to a CSS class. Centralised so templates don't carry their own
// switch statements.
func detectClass(s string) string {
	switch s {
	case "caught":
		return "green"
	case "uncertain":
		return "yellow"
	case "missed":
		return "red"
	default:
		return "grey"
	}
}

type pageMeta struct {
	Title     string
	Active    string
	Generated time.Time
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	rows, err := s.opts.Store.ListRuns(ctx, "", 5)
	if err != nil {
		writeServerError(w, err)
		return
	}
	since := time.Now().UTC().Add(-s.opts.MatrixWindow)
	m, err := matrix.Build(ctx, s.opts.Store, s.opts.Bundle, since)
	if err != nil {
		writeServerError(w, err)
		return
	}
	render(w, "home.html", map[string]any{
		"Meta":   pageMeta{Title: "eyeexam", Active: "home", Generated: time.Now().UTC()},
		"Runs":   rows,
		"Drift":  m.Drift,
		"Window": m.Window,
	})
}

func (s *Server) handleRunsList(w http.ResponseWriter, r *http.Request) {
	rows, err := s.opts.Store.ListRuns(r.Context(), r.URL.Query().Get("engagement"), 200)
	if err != nil {
		writeServerError(w, err)
		return
	}
	render(w, "runs_list.html", map[string]any{
		"Meta": pageMeta{Title: "runs · eyeexam", Active: "runs", Generated: time.Now().UTC()},
		"Runs": rows,
	})
}

func (s *Server) handleRunDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/runs/")
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	run, err := s.opts.Store.GetRun(ctx, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	execs, err := s.opts.Store.ListExecutionsForRun(ctx, id)
	if err != nil {
		writeServerError(w, err)
		return
	}
	hostNames := map[string]string{}
	for _, ex := range execs {
		if _, ok := hostNames[ex.HostID]; ok {
			continue
		}
		if h, err := s.opts.Store.GetHostByID(ctx, ex.HostID); err == nil {
			hostNames[ex.HostID] = h.Name
		}
	}
	type expectationRow struct {
		ExecutionID string
		store.ExpectedDetection
	}
	var expectations []expectationRow
	for _, ex := range execs {
		eds, err := s.opts.Store.ListExpectedDetectionsForExecution(ctx, ex.ID)
		if err != nil {
			writeServerError(w, err)
			return
		}
		for _, ed := range eds {
			expectations = append(expectations, expectationRow{ExecutionID: ex.ID, ExpectedDetection: ed})
		}
	}
	auditRows, err := s.opts.Store.ListAudit(ctx, store.AuditFilter{RunID: id, Limit: 500})
	if err != nil {
		writeServerError(w, err)
		return
	}
	type auditRowView struct {
		Seq     int64
		TS      string
		Event   string
		Actor   string
		Payload string
	}
	auditView := make([]auditRowView, 0, len(auditRows))
	for _, r := range auditRows {
		auditView = append(auditView, auditRowView{
			Seq:     r.Seq,
			TS:      r.TS,
			Event:   r.Event,
			Actor:   summarizeActorJSON(r.ActorJSON),
			Payload: r.PayloadJSON,
		})
	}
	render(w, "run_detail.html", map[string]any{
		"Meta":         pageMeta{Title: id + " · eyeexam", Active: "runs", Generated: time.Now().UTC()},
		"Run":          run,
		"Executions":   execs,
		"HostNames":    hostNames,
		"Expectations": expectations,
		"AuditEvents":  auditView,
	})
}

// summarizeActorJSON produces a one-line label from a JSON-encoded
// audit.Actor. Mirrors the Actor.String() format without importing the
// audit package (avoids a UI→audit dependency).
func summarizeActorJSON(actorJSON string) string {
	var a struct {
		OSUser  string  `json:"os_user"`
		OSUID   int     `json:"os_uid"`
		AppUser *string `json:"app_user,omitempty"`
	}
	if err := json.Unmarshal([]byte(actorJSON), &a); err != nil {
		return actorJSON
	}
	if a.AppUser != nil {
		return fmt.Sprintf("%s/%s(uid=%d)", *a.AppUser, a.OSUser, a.OSUID)
	}
	return fmt.Sprintf("%s(uid=%d)", a.OSUser, a.OSUID)
}

func (s *Server) handleMatrix(w http.ResponseWriter, r *http.Request) {
	since := time.Now().UTC().Add(-s.opts.MatrixWindow)
	m, err := matrix.Build(r.Context(), s.opts.Store, s.opts.Bundle, since)
	if err != nil {
		writeServerError(w, err)
		return
	}
	render(w, "matrix.html", map[string]any{
		"Meta":   pageMeta{Title: "matrix · eyeexam", Active: "matrix", Generated: time.Now().UTC()},
		"Matrix": m,
	})
}

func (s *Server) handleMatrixJSON(w http.ResponseWriter, r *http.Request) {
	since := time.Now().UTC().Add(-s.opts.MatrixWindow)
	m, err := matrix.Build(r.Context(), s.opts.Store, s.opts.Bundle, since)
	if err != nil {
		writeServerError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := m.RenderJSON(w); err != nil {
		writeServerError(w, err)
	}
}

func render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t, ok := pages[name]
	if !ok {
		writeServerError(w, fmt.Errorf("unknown template %q", name))
		return
	}
	if err := t.ExecuteTemplate(w, name, data); err != nil {
		writeServerError(w, err)
	}
}

func writeServerError(w http.ResponseWriter, err error) {
	http.Error(w, fmt.Sprintf("eyeexam: %v", err), http.StatusInternalServerError)
}
