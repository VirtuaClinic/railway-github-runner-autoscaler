package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

const (
	railwayGQLURL = "https://backboard.railway.app/graphql/v2"
	maxBodyBytes  = 5 * 1024 * 1024 // 5MB
)

type WorkflowJobEvent struct {
	Action      string      `json:"action"`
	WorkflowJob WorkflowJob `json:"workflow_job"`
}

type WorkflowJob struct {
	ID     int64    `json:"id"`
	Labels []string `json:"labels"`
}

type gqlRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

type gqlResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}

	if !validateHMAC(body, r.Header.Get("X-Hub-Signature-256"), s.cfg.WebhookSecret) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	if r.Header.Get("X-GitHub-Event") != "workflow_job" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var event WorkflowJobEvent
	if err := json.Unmarshal(body, &event); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if !hasLabels(event.WorkflowJob.Labels, s.cfg.RunnerLabels) {
		log.Printf("webhook ignored: labels %v do not match required %v", event.WorkflowJob.Labels, s.cfg.RunnerLabels)
		w.WriteHeader(http.StatusOK)
		return
	}

	log.Printf("webhook received: action=%s labels=%v", event.Action, event.WorkflowJob.Labels)

	id := event.WorkflowJob.ID
	switch event.Action {
	case "queued":
		if err := s.scaleUp(r.Context(), id); err != nil {
			log.Printf("scale up error: %v", err)
			http.Error(w, "failed to scale up", http.StatusInternalServerError)
			return
		}
	case "in_progress":
		s.markInProgress(id)
	case "completed":
		if err := s.scaleDown(r.Context(), id); err != nil {
			log.Printf("scale down error: %v", err)
			http.Error(w, "failed to scale down", http.StatusInternalServerError)
			return
		}
	default:
		log.Printf("webhook ignored: action=%s not handled", event.Action)
	}

	w.WriteHeader(http.StatusOK)
}

func validateHMAC(body []byte, sigHeader, secret string) bool {
	const prefix = "sha256="
	if !strings.HasPrefix(sigHeader, prefix) {
		return false
	}
	provided, err := hex.DecodeString(sigHeader[len(prefix):])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hmac.Equal(mac.Sum(nil), provided)
}

// hasLabels returns true if every label in required appears in jobLabels (case-insensitive).
func hasLabels(jobLabels, required []string) bool {
	lower := make(map[string]struct{}, len(jobLabels))
	for _, l := range jobLabels {
		lower[strings.ToLower(l)] = struct{}{}
	}
	for _, req := range required {
		if _, ok := lower[req]; !ok {
			return false
		}
	}
	return true
}

func (s *Server) markInProgress(id int64) {
	s.state.mu.Lock()
	delete(s.state.queued, id)
	s.state.inProgress[id] = struct{}{}
	queued := len(s.state.queued)
	inProgress := len(s.state.inProgress)
	s.state.mu.Unlock()
	log.Printf("job in progress: id=%d queued=%d inProgress=%d", id, queued, inProgress)
}

func (s *Server) scaleUp(ctx context.Context, id int64) error {
	s.state.mu.Lock()
	s.state.queued[id] = struct{}{}
	total := len(s.state.queued) + len(s.state.inProgress) + len(s.state.completed)
	queued := len(s.state.queued)
	inProgress := len(s.state.inProgress)
	completed := len(s.state.completed)
	s.state.mu.Unlock()

	if total > s.cfg.MaxRunners {
		log.Printf("at max runners (%d), job %d queued and waiting (queued=%d inProgress=%d completed=%d)",
			s.cfg.MaxRunners, id, queued, inProgress, completed)
		return nil
	}

	if err := s.setReplicas(ctx, total); err != nil {
		return err
	}
	log.Printf("scaled up: replicas=%d (job id=%d, queued=%d inProgress=%d completed=%d)", total, id, queued, inProgress, completed)

	// setReplicas alone is not enough to guarantee a container actually
	// exists -- confirmed live, issue #858: requesting the same replica
	// count Railway already has declared (the common single-job case, 1
	// staying 1) succeeds with no error but never triggers real
	// infrastructure reconciliation, leaving the ephemeral runner's exited
	// container never replaced. Force a genuine redeploy of the runner's
	// latest deployment to guarantee a real instance is running.
	//
	// Only when inProgress==0: redeploying while another job is actually
	// mid-execution on this service would kill it. When inProgress>0 a
	// real container is already known to be alive (it's running that
	// job), and setReplicas above already requested a genuinely higher
	// count for the concurrent case, which is a real value change and
	// should reconcile normally.
	if inProgress == 0 {
		if err := s.ensureRunnerAlive(ctx); err != nil {
			log.Printf("ensure runner alive error (non-fatal, setReplicas already succeeded): %v", err)
		}
	}
	return nil
}

func (s *Server) scaleDown(ctx context.Context, id int64) error {
	s.state.mu.Lock()
	// A job cancelled while still queued (never reached in_progress, so
	// never went through markInProgress's delete) would otherwise leave a
	// permanent stale entry here, inflating every future total/next
	// calculation for the life of this process.
	delete(s.state.queued, id)
	delete(s.state.inProgress, id)
	s.state.completed[id] = struct{}{}
	queued := len(s.state.queued)
	inProgress := len(s.state.inProgress)
	s.state.mu.Unlock()

	if inProgress > 0 {
		// Decreasing the replicas while jobs are still in progress can cause them to be killed before completion, so we wait until all in-progress jobs are done before scaling down.
		log.Printf("scaled down: job %d complete, queued=%d inProgress=%d, replicas unchanged", id, queued, inProgress)
		return nil
	}

	next := max(1, min(queued, s.cfg.MaxRunners))
	if err := s.setReplicas(ctx, next); err != nil {
		return err
	}

	// completed jobs are no longer using up inactive replicas we need to count for
	s.state.mu.Lock()
	s.state.completed = make(map[int64]struct{})
	s.state.mu.Unlock()

	if queued == 0 {
		log.Printf("scaled down: all jobs complete, reset to 1 replica")
	} else {
		log.Printf("scaled down: in-progress batch done, resuming %d pending job(s) with %d replica(s)", queued, next)
	}
	return nil
}

// setReplicas patches the runner service's desired replica count and commits
// it in one step -- the same environmentPatchCommit mutation Railway's own
// CLI uses for `railway scale` (railwayapp/cli's src/commands/scale.rs).
// Declares intent (so a genuinely higher concurrent-job count provisions
// additional replicas) but is NOT sufficient on its own to guarantee a
// container exists -- see ensureRunnerAlive below, which scaleUp always
// calls alongside this for the common single-replica case.
//
// The original serviceInstanceUpdate mutation this replaced only updates
// Railway's staged config layer, not the actual running instances -- it
// reports success and even updates the dashboard UI, but never triggers
// real infrastructure reconciliation (confirmed via Railway's own community
// support forum: https://station.railway.com/questions/service-instance-update-with-multi-region-co-d7c0d260,
// "Config accepted... NOT... Infrastructure reconciled"). That's the root
// cause of issue #858: every prior scale call here looked successful but
// may never have actually done anything, leaving the ephemeral runner's
// respawn entirely up to Railway's own (separately unreliable, see
// station.railway.com/questions/restart-policy-don-t-always-work-2624a2b8)
// restart-on-exit behavior.
//
// Switching to environmentPatchCommit alone turned out NOT to fully fix
// #858 either -- confirmed live, 2026-09-09: a real queued job still sat
// with no runner for 2.5+ minutes even with this mutation firing
// successfully, because requesting the SAME replica count (1 staying 1,
// the common case) still doesn't force reconciliation. Only a genuine
// redeployDeployment call (see ensureRunnerAlive) actually unstuck it.
func (s *Server) setReplicas(ctx context.Context, n int) error {
	const mutation = `
mutation EnvironmentPatchCommit($environmentId: String!, $patch: EnvironmentConfig!, $commitMessage: String) {
  environmentPatchCommit(environmentId: $environmentId, patch: $patch, commitMessage: $commitMessage)
}`
	patch := map[string]any{
		"services": map[string]any{
			s.cfg.ServiceID: map[string]any{
				"deploy": map[string]any{
					"multiRegionConfig": map[string]any{
						s.cfg.Region: map[string]any{"numReplicas": n},
					},
				},
			},
		},
	}
	return s.gqlDo(ctx, gqlRequest{
		Query: mutation,
		Variables: map[string]any{
			"environmentId": s.cfg.EnvironmentID,
			"patch":         patch,
			"commitMessage": fmt.Sprintf("autoscaler: scale to %d replica(s)", n),
		},
	}, nil)
}

// ensureRunnerAlive forces a genuine redeploy of the runner service's latest
// deployment -- the same deploymentRedeploy mutation Railway's own CLI uses
// for `railway redeploy` (railwayapp/cli's src/commands/redeploy.rs), fed by
// the same `deployments` query the CLI uses to resolve which deployment ID
// that is. Unlike setReplicas, this is a real infrastructure action, not a
// declarative config patch, so it reconciles even when nothing about the
// desired state numerically changed. Caller (scaleUp) only invokes this when
// no job is currently in_progress, since redeploying would kill one that is.
func (s *Server) ensureRunnerAlive(ctx context.Context) error {
	id, canRedeploy, err := s.latestRunnerDeployment(ctx)
	if err != nil {
		return fmt.Errorf("fetch latest runner deployment: %w", err)
	}
	if !canRedeploy {
		log.Printf("skipping redeploy: latest runner deployment %s is not currently redeployable (building/deploying/removed)", id)
		return nil
	}
	if err := s.redeployDeployment(ctx, id); err != nil {
		return fmt.Errorf("redeploy deployment %s: %w", id, err)
	}
	log.Printf("ensured runner alive: redeployed latest deployment %s", id)
	return nil
}

func (s *Server) latestRunnerDeployment(ctx context.Context) (id string, canRedeploy bool, err error) {
	const query = `
query Deployments($input: DeploymentListInput!, $first: Int) {
  deployments(input: $input, first: $first) {
    edges { node { id status canRedeploy } }
  }
}`
	var out struct {
		Deployments struct {
			Edges []struct {
				Node struct {
					ID          string `json:"id"`
					Status      string `json:"status"`
					CanRedeploy bool   `json:"canRedeploy"`
				} `json:"node"`
			} `json:"edges"`
		} `json:"deployments"`
	}
	err = s.gqlDo(ctx, gqlRequest{
		Query: query,
		Variables: map[string]any{
			"input": map[string]any{
				"projectId":     s.cfg.ProjectID,
				"environmentId": s.cfg.EnvironmentID,
				"serviceId":     s.cfg.ServiceID,
			},
			"first": 1,
		},
	}, &out)
	if err != nil {
		return "", false, err
	}
	if len(out.Deployments.Edges) == 0 {
		return "", false, fmt.Errorf("no deployments found for service %s", s.cfg.ServiceID)
	}
	node := out.Deployments.Edges[0].Node
	return node.ID, node.CanRedeploy, nil
}

func (s *Server) redeployDeployment(ctx context.Context, deploymentID string) error {
	const mutation = `
mutation DeploymentRedeploy($id: String!) {
  deploymentRedeploy(id: $id) { id }
}`
	return s.gqlDo(ctx, gqlRequest{
		Query:     mutation,
		Variables: map[string]any{"id": deploymentID},
	}, nil)
}

func (s *Server) gqlDo(ctx context.Context, req gqlRequest, out any) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, railwayGQLURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+s.cfg.RailwayToken)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("railway api: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("[ERROR] railway api %d | request: %s | response: %s", resp.StatusCode, body, respBody)
		return fmt.Errorf("railway api returned %d", resp.StatusCode)
	}

	var gqlResp gqlResponse
	if err := json.Unmarshal(respBody, &gqlResp); err != nil {
		log.Printf("[ERROR] railway api unmarshal | request: %s | response: %s", body, respBody)
		return fmt.Errorf("unmarshal response: %w", err)
	}
	if len(gqlResp.Errors) > 0 {
		log.Printf("[ERROR] railway graphql | request: %s | response: %s", body, respBody)
		return fmt.Errorf("railway graphql error: %s", gqlResp.Errors[0].Message)
	}

	if out != nil && gqlResp.Data != nil {
		if err := json.Unmarshal(gqlResp.Data, out); err != nil {
			return fmt.Errorf("unmarshal data: %w", err)
		}
	}
	return nil
}
