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
