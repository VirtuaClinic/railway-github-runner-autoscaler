package main

import (
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
	// A brand-new queued job normally reaches in_progress within ~10-20s
	// (confirmed live, #858). #858's original wedge sat queued 28+ minutes.
	// This delay must clear the happy path comfortably while still catching
	// a real wedge quickly -- see checkForWedge in server.go, and issue #862
	// for why firing on every queued webhook instead of after this delay
	// took down 3/3 build jobs on a single PR merge.
	defaultWedgeCheckDelaySeconds = 45
)

type Config struct {
	WebhookSecret   string
	RailwayToken    string
	ServiceID       string
	EnvironmentID   string
	ProjectID       string
	MaxRunners      int
	Port            string
	RunnerLabels    []string
	Region          string
	WedgeCheckDelay time.Duration
}

type State struct {
	mu         sync.Mutex
	queued     map[int64]struct{}
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

	maxRunners := defaultMaxRunners
	if v := os.Getenv("MAX_RUNNERS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return Config{}, fmt.Errorf("MAX_RUNNERS must be a positive integer, got %q", v)
		}
		maxRunners = n
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

	wedgeCheckDelaySeconds := defaultWedgeCheckDelaySeconds
	if v := os.Getenv("WEDGE_CHECK_DELAY_SECONDS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return Config{}, fmt.Errorf("WEDGE_CHECK_DELAY_SECONDS must be a positive integer, got %q", v)
		}
		wedgeCheckDelaySeconds = n
	}

	return Config{
		WebhookSecret:   secret,
		RailwayToken:    token,
		ServiceID:       serviceID,
		EnvironmentID:   os.Getenv("RAILWAY_ENVIRONMENT_ID"),
		ProjectID:       os.Getenv("RAILWAY_PROJECT_ID"),
		MaxRunners:      maxRunners,
		Port:            port,
		RunnerLabels:    labels,
		Region:          region,
		WedgeCheckDelay: time.Duration(wedgeCheckDelaySeconds) * time.Second,
	}, nil
}

func main() {
	log.SetOutput(os.Stdout)

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	srv := &Server{cfg: cfg, state: &State{
		queued:     make(map[int64]struct{}),
		inProgress: make(map[int64]struct{}),
		completed:  make(map[int64]struct{}),
	}}

	log.Printf("startup: counters initialised (queued=0 inProgress=0), base replica ready")

	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", srv.handleWebhook)
	mux.HandleFunc("/health", srv.handleHealth)

	log.Printf("starting on :%s | service=%s region=%s max=%d labels=%v",
		cfg.Port, cfg.ServiceID, cfg.Region, cfg.MaxRunners, cfg.RunnerLabels)
	if err := http.ListenAndServe(":"+cfg.Port, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
