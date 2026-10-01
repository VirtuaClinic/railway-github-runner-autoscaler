package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fakeRailway records the numReplicas each environmentPatchCommit asks for.
type fakeRailway struct {
	mu       sync.Mutex
	replicas []int
	other    int // any non-patch GraphQL call (e.g. a wedge redeploy)
}

func (f *fakeRailway) handler(serviceID, region string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		f.mu.Lock()
		defer f.mu.Unlock()
		patch, ok := req.Variables["patch"].(map[string]any)
		if !ok {
			f.other++
		} else {
			svc := patch["services"].(map[string]any)[serviceID].(map[string]any)
			cfg := svc["deploy"].(map[string]any)["multiRegionConfig"].(map[string]any)[region].(map[string]any)
			f.replicas = append(f.replicas, int(cfg["numReplicas"].(float64)))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{}}`))
	}
}

func newTestServer(t *testing.T, queued, inProgress, completed int) (*Server, *fakeRailway) {
	t.Helper()
	fake := &fakeRailway{}
	ts := httptest.NewServer(fake.handler("svc", "region"))
	t.Cleanup(ts.Close)

	old := railwayGQLURL
	railwayGQLURL = ts.URL
	t.Cleanup(func() { railwayGQLURL = old })

	st := &State{
		queued:     map[int64]struct{}{},
		inProgress: map[int64]struct{}{},
		completed:  map[int64]struct{}{},
	}
	next := int64(1000)
	add := func(m map[int64]struct{}, n int) {
		for i := 0; i < n; i++ {
			next++
			m[next] = struct{}{}
		}
	}
	add(st.queued, queued)
	add(st.inProgress, inProgress)
	add(st.completed, completed)

	return &Server{
		cfg: Config{
			ServiceID:       "svc",
			Region:          "region",
			MaxRunners:      3,
			WedgeCheckDelay: time.Hour, // never fires during a test
		},
		state: st,
	}, fake
}

func TestScaleUpReplicaCount(t *testing.T) {
	cases := []struct {
		name                          string
		queued, inProgress, completed int // already tracked, before the new job
		want                          int
	}{
		{"first job, idle system", 0, 0, 0, 1},
		// The regression: next job queues in the same second the previous one
		// completed, so `completed` hasn't been cleared yet. Nothing is
		// running, so this must stay at 1 (no spurious 1 -> 2 redeploy).
		{"back-to-back job, previous not yet cleared", 0, 0, 1, 1},
		{"back-to-back, several stale completed", 0, 0, 2, 1},
		// Concurrency behaviour must be unchanged.
		{"second job while one is running", 0, 1, 0, 2},
		{"second job while one running and one completed", 0, 1, 1, 3},
		{"two queued, nothing running", 1, 0, 0, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, fake := newTestServer(t, c.queued, c.inProgress, c.completed)
			if err := s.scaleUp(context.Background(), 1); err != nil {
				t.Fatalf("scaleUp: %v", err)
			}
			if len(fake.replicas) != 1 || fake.replicas[0] != c.want {
				t.Fatalf("requested replicas = %v, want [%d]", fake.replicas, c.want)
			}
			if fake.other != 0 {
				t.Fatalf("unexpected extra Railway calls: %d", fake.other)
			}
		})
	}
}
