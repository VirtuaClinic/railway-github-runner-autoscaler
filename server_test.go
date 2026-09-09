package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRailway records which Railway GraphQL operation each request carried and
// returns a configurable response, so tests can assert scaling behaviour without
// reaching the real API.
type fakeRailway struct {
	mu     sync.Mutex
	ops    []string
	status int
	body   string
}

func (f *fakeRailway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	var req gqlRequest
	_ = json.Unmarshal(b, &req)

	f.mu.Lock()
	var op, body string
	switch {
	case strings.Contains(req.Query, "deploymentRedeploy"):
		op = "redeploy"
	case strings.Contains(req.Query, "deployments("):
		op = "list"
		body = `{"data":{"deployments":{"edges":[{"node":{"id":"dep1","status":"SUCCESS","canRedeploy":true}}]}}}`
	case strings.Contains(req.Query, "environmentPatchCommit"):
		op = "patch"
	default:
		op = "other"
	}
	f.ops = append(f.ops, op)
	status := f.status
	if body == "" {
		body = f.body
	}
	f.mu.Unlock()

	if status == 0 {
		status = http.StatusOK
	}
	if body == "" {
		body = `{"data":{}}`
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func (f *fakeRailway) operations() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ops...)
}

func newTestServer(t *testing.T) (*Server, *fakeRailway) {
	t.Helper()
	fr := &fakeRailway{}
	ts := httptest.NewServer(fr)
	t.Cleanup(ts.Close)

	cfg := Config{
		WebhookSecret:     "secret",
		RailwayToken:      "token",
		RailwayURL:        ts.URL,
		ServiceID:         "svc",
		EnvironmentID:     "env",
		ProjectID:         "proj",
		MaxRunners:        3,
		Region:            "region",
		RunnerLabels:      []string{"self-hosted", "railway"},
		ReconcileInterval: time.Minute,
		StuckThreshold:    4 * time.Minute,
	}
	s := &Server{cfg: cfg, state: &State{
		queued:     make(map[int64]time.Time),
		inProgress: make(map[int64]struct{}),
		completed:  make(map[int64]struct{}),
	}}
	return s, fr
}

func containsOp(ops []string, want string) bool {
	for _, op := range ops {
		if op == want {
			return true
		}
	}
	return false
}

// The core issue #858 fix: a fresh single job must trigger a real redeploy, not
// just a replica patch that Railway treats as a no-op. The redeploy first looks
// up the latest deployment, then redeploys it.
func TestScaleUpFirstJobForcesRedeploy(t *testing.T) {
	s, fr := newTestServer(t)

	if err := s.scaleUp(context.Background(), 1); err != nil {
		t.Fatalf("scaleUp: %v", err)
	}

	if got, want := fr.operations(), []string{"patch", "list", "redeploy"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("operations = %v, want %v", got, want)
	}
}

// A redeploy replaces running replicas, so scaling up while a job is in progress
// must not redeploy -- it would kill the running job.
func TestScaleUpWithJobInProgressDoesNotRedeploy(t *testing.T) {
	s, fr := newTestServer(t)
	s.state.inProgress[99] = struct{}{}

	if err := s.scaleUp(context.Background(), 1); err != nil {
		t.Fatalf("scaleUp: %v", err)
	}

	if got := fr.operations(); !reflect.DeepEqual(got, []string{"patch"}) {
		t.Fatalf("operations = %v, want a single patch and no redeploy", got)
	}
}

// A job stuck in the queued set past the threshold must be recovered by the
// reconcile loop with a redeploy.
func TestReconcileStuckForcesRedeploy(t *testing.T) {
	s, fr := newTestServer(t)
	s.state.queued[7] = time.Now().Add(-10 * time.Minute) // stuck
	s.state.queued[8] = time.Now()                        // fresh, not stuck

	s.reconcileStuck(context.Background())

	if !containsOp(fr.operations(), "redeploy") {
		t.Fatalf("operations = %v, want a redeploy for the stuck job", fr.operations())
	}
}

func TestReconcileStuckNoStuckJobsIsNoop(t *testing.T) {
	s, fr := newTestServer(t)
	s.state.queued[8] = time.Now()

	s.reconcileStuck(context.Background())

	if got := fr.operations(); len(got) != 0 {
		t.Fatalf("operations = %v, want no Railway calls", got)
	}
}

// A failed scale call must not surface as HTTP 500: GitHub never retries
// workflow_job deliveries, so the job must stay queued for the reconcile loop.
func TestWebhookReturns200OnRailwayError(t *testing.T) {
	s, fr := newTestServer(t)
	fr.status = http.StatusInternalServerError
	fr.body = "boom"

	body := `{"action":"queued","workflow_job":{"id":42,"labels":["self-hosted","railway"]}}`
	rec := httptest.NewRecorder()
	s.handleWebhook(rec, signedRequest(s.cfg.WebhookSecret, body))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	s.state.mu.Lock()
	_, queued := s.state.queued[42]
	s.state.mu.Unlock()
	if !queued {
		t.Fatal("job 42 should remain queued after a failed scale")
	}
}

// When a batch finishes with jobs still pending, those jobs must get fresh
// runners via a redeploy.
func TestScaleDownResumesPendingJobsWithRedeploy(t *testing.T) {
	s, fr := newTestServer(t)
	s.state.inProgress[1] = struct{}{}
	s.state.queued[2] = time.Now()

	if err := s.scaleDown(context.Background(), 1); err != nil {
		t.Fatalf("scaleDown: %v", err)
	}

	if !containsOp(fr.operations(), "redeploy") {
		t.Fatalf("operations = %v, want a redeploy to resume the pending job", fr.operations())
	}
}

// When the last job completes and nothing is pending, resetting to the base
// replica needs no redeploy -- the next scaleUp starts a fresh runner.
func TestScaleDownAllCompleteDoesNotRedeploy(t *testing.T) {
	s, fr := newTestServer(t)
	s.state.inProgress[1] = struct{}{}

	if err := s.scaleDown(context.Background(), 1); err != nil {
		t.Fatalf("scaleDown: %v", err)
	}

	if containsOp(fr.operations(), "redeploy") {
		t.Fatalf("operations = %v, want no redeploy on idle reset", fr.operations())
	}
}

func signedRequest(secret, body string) *http.Request {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(body))
	req.Header.Set("X-GitHub-Event", "workflow_job")
	req.Header.Set("X-Hub-Signature-256", sig)
	return req
}
