package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultMaxRunners  = 3
	defaultPort        = "8080"
	defaultRunnerLabel = "self-hosted,railway"
	// Railway's multiRegionConfig keys the desired replica count per
	// region -- must match the region the runner service actually deploys
	// to, or environmentPatchCommit silently patches a region with no
	// instances in it. Override via RAILWAY_REGION_ID if that ever
	// changes; see RAILWAY_REGION_ID in loadConfig.
	defaultRegion = "us-east4-eqdc4a"
	// Tuning for the reconcile loop; see reconcileLoop in server.go.
	defaultReconcileInterval = 60 * time.Second
	defaultStuckThreshold    = 4 * time.Minute
)

type Config struct {
	WebhookSecret     string
	RailwayToken      string
	RailwayURL        string
	ServiceID         string
	EnvironmentID     string
	ProjectID         string
	MaxRunners        int
	Port              string
	RunnerLabels      []string
	Region            string
	ReconcileInterval time.Duration
	StuckThreshold    time.Duration
}

type State struct {
	mu sync.Mutex
	// queued maps a job id to when it was queued, so the reconcile loop can
	// tell how long a job has waited with no runner.
	queued     map[int64]time.Time
	inProgress map[int64]struct{}
	completed  map[int64]struct{}
}

type Server struct {
	cfg   Config
	state *State
}

func loadConfig() (Config, error) {
	secret := os.Getenv("GITHUB_WEBHOOK_SECRET")
	token := os.Getenv("RAILWAY_API_TOKEN")
	serviceID := os.Getenv("RAILWAY_RUNNER_SERVICE_ID")

	if secret == "" {
		return Config{}, fmt.Errorf("GITHUB_WEBHOOK_SECRET is required")
	}
	if token == "" {
		return Config{}, fmt.Errorf("RAILWAY_API_TOKEN is required")
	}
	if serviceID == "" {
		return Config{}, fmt.Errorf("RAILWAY_RUNNER_SERVICE_ID is required")
	}

	maxRunners, err := parseIntEnv("MAX_RUNNERS", defaultMaxRunners)
	if err != nil {
		return Config{}, err
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	labelStr := os.Getenv("RUNNER_LABELS")
	if labelStr == "" {
		labelStr = defaultRunnerLabel
	}
	labels := strings.Split(labelStr, ",")
	for i, l := range labels {
		labels[i] = strings.TrimSpace(strings.ToLower(l))
	}

	region := os.Getenv("RAILWAY_REGION_ID")
	if region == "" {
		region = defaultRegion
	}

	reconcileSeconds, err := parseIntEnv("RECONCILE_INTERVAL_SECONDS", int(defaultReconcileInterval/time.Second))
	if err != nil {
		return Config{}, err
	}

	stuckSeconds, err := parseIntEnv("STUCK_JOB_THRESHOLD_SECONDS", int(defaultStuckThreshold/time.Second))
	if err != nil {
		return Config{}, err
	}

	return Config{
		WebhookSecret:     secret,
		RailwayToken:      token,
		RailwayURL:        railwayGQLURL,
		ServiceID:         serviceID,
		EnvironmentID:     os.Getenv("RAILWAY_ENVIRONMENT_ID"),
		ProjectID:         os.Getenv("RAILWAY_PROJECT_ID"),
		MaxRunners:        maxRunners,
		Port:              port,
		RunnerLabels:      labels,
		Region:            region,
		ReconcileInterval: time.Duration(reconcileSeconds) * time.Second,
		StuckThreshold:    time.Duration(stuckSeconds) * time.Second,
	}, nil
}

// parseIntEnv reads a positive integer from the named environment variable,
// returning def when it is unset.
func parseIntEnv(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%s must be a positive integer, got %q", key, v)
	}
	return n, nil
}

func main() {
	log.SetOutput(os.Stdout)

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	srv := &Server{cfg: cfg, state: &State{
		queued:     make(map[int64]time.Time),
		inProgress: make(map[int64]struct{}),
		completed:  make(map[int64]struct{}),
	}}

	log.Printf("startup: counters initialised (queued=0 inProgress=0), base replica ready")

	go srv.reconcileLoop(context.Background())
	log.Printf("reconcile loop started: interval=%s stuck threshold=%s", cfg.ReconcileInterval, cfg.StuckThreshold)

	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", srv.handleWebhook)
	mux.HandleFunc("/health", srv.handleHealth)

	log.Printf("starting on :%s | service=%s region=%s max=%d labels=%v",
		cfg.Port, cfg.ServiceID, cfg.Region, cfg.MaxRunners, cfg.RunnerLabels)
	if err := http.ListenAndServe(":"+cfg.Port, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
