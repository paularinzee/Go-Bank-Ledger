package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/jwtauth/v5"
	"github.com/joho/godotenv"
	"golang.org/x/time/rate"

	// FIX 2: Explicitly import pq driver side-effects to register "postgres" with database/sql
	_ "github.com/lib/pq"
	_ "github.com/paularinzee/bank-ledger/docs"
	"github.com/paularinzee/bank-ledger/internal/api"
	"github.com/paularinzee/bank-ledger/internal/db"
	"github.com/paularinzee/bank-ledger/internal/ratelimit"
	"github.com/paularinzee/bank-ledger/internal/service"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	httpSwagger "github.com/swaggo/http-swagger"
)

func initLogger() {
	// Use millisecond precision in logs so request timing is easy to follow in demos.
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	zlog.Logger = zlog.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).With().Caller().Logger()
	zlog.Info().Msg("Logger initialized")
}

func parseAllowedOrigins() []string {
	// In production, restrict origins
	if os.Getenv("ENVIRONMENT") == "production" {
		if prodURL := os.Getenv("PROD_FRONTEND_URL"); prodURL != "" {
			return []string{prodURL}
		}
		// Fallback to no CORS in production if not specified (better to be restrictive)
		return []string{}
	}

	origins := os.Getenv("CORS_ALLOWED_ORIGINS")
	if strings.TrimSpace(origins) == "" {
		return []string{
			"http://localhost:3000",
			"http://127.0.0.1:3000",
			"http://localhost:5173",
			"http://127.0.0.1:5173",
		}
	}

	parts := strings.Split(origins, ",")
	allowed := make([]string, 0, len(parts))
	for _, origin := range parts {
		trimmed := strings.TrimSpace(origin)
		if trimmed != "" {
			allowed = append(allowed, trimmed)
		}
	}

	if len(allowed) == 0 {
		return []string{
			"http://localhost:3000",
			"http://127.0.0.1:3000",
			"http://localhost:5173",
			"http://127.0.0.1:5173",
		}
	}

	return allowed
}

func resolveDBURL() string {
	connStr := strings.TrimSpace(os.Getenv("DB_URL"))
	fallbackVars := []string{"INTERNAL_DATABASE_URL", "RDS_DATABASE_URL", "DATABASE_URL"}

	if connStr == "" {
		for _, envVar := range fallbackVars {
			if value := strings.TrimSpace(os.Getenv(envVar)); value != "" {
				return value
			}
		}

		if os.Getenv("RENDER") == "true" {
			zlog.Fatal().Msg(
				"DB_URL is not configured. " +
					"Fix: Render dashboard → your web service → Environment → add DB_URL " +
					"set to the Internal Connection String from your PostgreSQL service.",
			)
		}

		return "postgresql://root:secret@localhost:5432/bank_ledger?sslmode=disable"
	}

	lower := strings.ToLower(connStr)
	isLocalHostURL := strings.Contains(lower, "@localhost:") || strings.Contains(lower, "@127.0.0.1:") || strings.Contains(lower, "@[::1]:")
	if isLocalHostURL {
		for _, envVar := range fallbackVars {
			if value := strings.TrimSpace(os.Getenv(envVar)); value != "" {
				return value
			}
		}
		if os.Getenv("RENDER") == "true" {
			zlog.Fatal().Msg(
				"DB_URL resolves to localhost, which is not valid on Render. " +
					"Fix: Render dashboard → your web service → Environment → update DB_URL " +
					"to the Internal Connection String from your PostgreSQL service.",
			)
		}
	}

	return connStr
}

func validateEnvironment() error {
	required := []string{"JWT_SECRET"}
	if os.Getenv("ENVIRONMENT") == "production" {
		required = append(required, "PROD_FRONTEND_URL")
	}

	var missing []string
	for _, env := range required {
		if strings.TrimSpace(os.Getenv(env)) == "" {
			missing = append(missing, env)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required environment variables: %v", missing)
	}
	return nil
}

// securityHeaders adds security-related headers to all responses
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// requestSizeLimiter limits the size of incoming requests
func requestSizeLimiter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1048576) // 1MB limit
		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware provides structured logging with request IDs
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		start := time.Now()

		// Create a context with logger that includes request_id
		logger := zlog.With().Str("request_id", reqID).Logger()
		ctx := logger.WithContext(r.Context())

		// Capture status code
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		logger.Info().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Str("remote_ip", r.RemoteAddr).
			Str("user_agent", r.UserAgent()).
			Msg("HTTP request received")

		next.ServeHTTP(ww, r.WithContext(ctx))

		logger.Info().
			Int("status", ww.Status()).
			Int("bytes", ww.BytesWritten()).
			Dur("duration_ms", time.Since(start)).
			Msg("HTTP request completed")
	})
}

// @title           Bank Ledger API
// @version         1.0
// @description     Production-grade double-entry accounting ledger
// @securityDefinitions.apikey Bearer
// @in                         header
// @name                       Authorization
// @description                Type 'Bearer <your_jwt_token>' to authenticate

func main() {
	// Capture startup time so health endpoint can report uptime.
	startTime := time.Now()

	initLogger()

	if err := godotenv.Load(); err != nil {
		zlog.Warn().Err(err).Msg("No .env file found – using system env")
	}

	// Validate required environment variables
	if err := validateEnvironment(); err != nil {
		zlog.Fatal().Err(err).Msg("Environment validation failed")
	}

	if err := api.InitTokenAuthFromEnv(); err != nil {
		zlog.Fatal().Err(err).Msg("Failed to initialize JWT auth")
	}

	connStr := resolveDBURL()
	if strings.Contains(connStr, "@localhost:") || strings.Contains(connStr, "@127.0.0.1:") || strings.Contains(connStr, "@[::1]:") {
		zlog.Warn().Msg("Using localhost DB_URL; this is only valid for local development")
	}

	dbConn, err := sql.Open("postgres", connStr)
	if err != nil {
		zlog.Fatal().Err(err).Msg("Failed to open DB connection")
	}

	// FIX 5: Hardening connection limits to prevent exhaustion of DB resources
	dbConn.SetMaxOpenConns(25)                  // Max concurrent active connections
	dbConn.SetMaxIdleConns(25)                  // Keeps a warm pool of connections ready
	dbConn.SetConnMaxLifetime(10 * time.Minute) // recycles connection handlers to pick up network updates
	dbConn.SetConnMaxIdleTime(5 * time.Minute)

	pingCtx, pingCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer pingCancel()
	if err := dbConn.PingContext(pingCtx); err != nil {
		zlog.Fatal().Err(err).Msg("Failed to connect to DB")
	}
	zlog.Info().Msg("Database connectivity verified")

	store := db.NewStore(dbConn)
	ledgerSvc := service.NewLedgerService(store)
	h := api.NewHandler(ledgerSvc, store)

	r := chi.NewRouter()

	// Expose standard Prometheus metrics scraping path
	r.Handle("/metrics", promhttp.Handler())

	// Core infrastructure middleware handlers
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(securityHeaders)
	r.Use(requestSizeLimiter)
	r.Use(loggingMiddleware)

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   parseAllowedOrigins(),
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		ExposedHeaders:   []string{"Link", "X-Cache-Idempotency"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Create rate limiters with different strategies
	globalLimiter := ratelimit.NewRateLimiter(
		rate.Limit(100), // 100 requests per second
		50,              // burst of 50
		10*time.Minute,  // keep inactive clients for 10 minutes
	)

	// Create endpoint-specific rate limiter
	endpointLimiter := ratelimit.NewEndpointRateLimiter()
	endpointLimiter.SetEndpointRate("/login", rate.Limit(5), 3, 15*time.Minute)         // 5 req/sec for login
	endpointLimiter.SetEndpointRate("/register", rate.Limit(3), 2, 30*time.Minute)      // 3 req/sec for register
	endpointLimiter.SetEndpointRate("/accounts/*", rate.Limit(200), 100, 5*time.Minute) // Higher for account operations

	// Apply global rate limiter middleware
	r.Use(globalLimiter.Middleware())

	// Public routes
	r.Post("/register", h.Register)
	r.Post("/login", h.Login)

	// Health check endpoint with dependency checks
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		health := map[string]interface{}{
			"status":  "healthy",
			"version": "1.0.0",
			"uptime":  time.Since(startTime).String(),
			"checks":  map[string]string{},
		}

		// Check database connectivity
		if err := dbConn.PingContext(r.Context()); err != nil {
			health["status"] = "unhealthy"
			health["checks"].(map[string]string)["database"] = "failed: " + err.Error()
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			health["checks"].(map[string]string)["database"] = "connected"
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(health)
	})

	// Readiness probe endpoint for orchestration
	r.Get("/ready", func(w http.ResponseWriter, r *http.Request) {
		// Check if database is ready
		if err := dbConn.PingContext(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("database not ready"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ready"))
	})

	// FIX 4: Explicit route fallback handling to prevent 404 errors on trailing slash variations
	r.Get("/swagger", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/swagger/index.html", http.StatusMovedPermanently)
	})

	// Mount Swagger documentation
	r.Mount("/swagger", httpSwagger.WrapHandler)

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(api.TokenAuth))
		r.Use(jwtauth.Authenticator(api.TokenAuth))
		r.Use(endpointLimiter.Middleware()) // Apply endpoint-specific rate limiting

		// Validate and intercept duplicate transaction requests
		r.Use(h.IdempotencyMiddleware)

		r.Post("/accounts", h.CreateAccount)
		r.Get("/accounts", h.ListAccounts)
		r.Get("/accounts/{id}", h.GetAccount)
		r.Post("/accounts/{id}/deposit", h.Deposit)
		r.Post("/accounts/{id}/withdraw", h.Withdraw)
		r.Post("/transfers", h.Transfer)
		r.Get("/accounts/{id}/entries", h.GetEntries)
		r.Get("/accounts/{id}/reconcile", h.ReconcileAccount)
		r.Get("/transactions/{id}", h.GetTransactions)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           r,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// FIX 1: Running the network socket worker step inside a non-blocking background routine
	serverErrors := make(chan error, 1)
	go func() {
		zlog.Info().Str("port", port).Msg("Starting server")
		serverErrors <- srv.ListenAndServe()
	}()

	// Intercept execution trap signals coming from OS orchestration layers (Docker, Render, k8s)
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		zlog.Fatal().Err(err).Msg("Server forced premature structural closure")

	case sig := <-shutdown:
		zlog.Info().Str("signal", sig.String()).Msg("Graceful shutdown sequence initialized...")

		// Provide a 30-second grace window for mid-flight database entry writes to safely commit
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Gracefully shutdown the HTTP server
		if err := srv.Shutdown(ctx); err != nil {
			zlog.Error().Err(err).Msg("Graceful listener wrap up failed; forcing socket close")
			_ = srv.Close()
		}

		// Cleanup rate limiter resources if they support Close
		if closer, ok := globalLimiter.(interface{ Close() error }); ok {
			if err := closer.Close(); err != nil {
				zlog.Error().Err(err).Msg("Error closing global rate limiter")
			}
		}

		if closer, ok := endpointLimiter.(interface{ Close() error }); ok {
			if err := closer.Close(); err != nil {
				zlog.Error().Err(err).Msg("Error closing endpoint rate limiter")
			}
		}

		// Close connection pool gracefully down to zero connections
		if err := dbConn.Close(); err != nil {
			zlog.Error().Err(err).Msg("Error encountered while recycling connection pools")
		}
	}
	zlog.Info().Msg("Server stopped completely")
}
