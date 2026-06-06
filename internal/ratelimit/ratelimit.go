// internal/ratelimit/ratelimit.go
package ratelimit

import (
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/time/rate"
)

// ClientLimiter holds rate limiter for each client
type ClientLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// RateLimiter manages rate limiting for all clients
type RateLimiter struct {
	mu      sync.RWMutex
	clients map[string]*ClientLimiter
	rate    rate.Limit    // requests per second
	burst   int           // max burst size
	ttl     time.Duration // how long to keep inactive clients
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(r rate.Limit, burst int, ttl time.Duration) *RateLimiter {
	rl := &RateLimiter{
		clients: make(map[string]*ClientLimiter),
		rate:    r,
		burst:   burst,
		ttl:     ttl,
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

// getLimiter returns the rate limiter for a specific client
func (rl *RateLimiter) getLimiter(clientID string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if client, exists := rl.clients[clientID]; exists {
		client.lastSeen = time.Now()
		return client.limiter
	}

	limiter := rate.NewLimiter(rl.rate, rl.burst)
	rl.clients[clientID] = &ClientLimiter{
		limiter:  limiter,
		lastSeen: time.Now(),
	}

	return limiter
}

// cleanup removes inactive clients periodically
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for id, client := range rl.clients {
			if now.Sub(client.lastSeen) > rl.ttl {
				delete(rl.clients, id)
				log.Debug().Str("client_id", id).Msg("Removed inactive rate limiter")
			}
		}
		rl.mu.Unlock()
	}
}

// Middleware creates HTTP middleware for rate limiting
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract client identifier (IP address or API key)
		clientID := r.RemoteAddr

		// If using API key, prioritize that
		if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
			clientID = "api:" + apiKey
		}

		// For authenticated users, use user ID from JWT
		if userID := r.Context().Value("user_id"); userID != nil {
			clientID = "user:" + userID.(string)
		}

		limiter := rl.getLimiter(clientID)

		if !limiter.Allow() {
			log.Warn().
				Str("client_id", clientID).
				Str("path", r.URL.Path).
				Msg("Rate limit exceeded")

			w.Header().Set("X-RateLimit-Limit", string(rune(rl.burst)))
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("Retry-After", "1")
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}

		// Add rate limit headers
		w.Header().Set("X-RateLimit-Limit", string(rune(rl.burst)))

		next.ServeHTTP(w, r)
	})
}

// PerEndpointLimiter allows different rates for different endpoints
type PerEndpointLimiter struct {
	limiters map[string]*RateLimiter
	defaults *RateLimiter
	mu       sync.RWMutex
}

// NewPerEndpointLimiter creates a limiter with endpoint-specific rates
func NewPerEndpointLimiter(defaultRate rate.Limit, defaultBurst int) *PerEndpointLimiter {
	return &PerEndpointLimiter{
		limiters: make(map[string]*RateLimiter),
		defaults: NewRateLimiter(defaultRate, defaultBurst, 10*time.Minute),
	}
}

// SetEndpointRate configures rate limits for a specific endpoint pattern
func (pel *PerEndpointLimiter) SetEndpointRate(pattern string, rate rate.Limit, burst int, ttl time.Duration) {
	pel.mu.Lock()
	defer pel.mu.Unlock()
	pel.limiters[pattern] = NewRateLimiter(rate, burst, ttl)
}

// Middleware returns HTTP middleware with endpoint-aware rate limiting
func (pel *PerEndpointLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Find matching limiter for this endpoint
		var limiter *RateLimiter
		pel.mu.RLock()
		for pattern, l := range pel.limiters {
			if matchPath(pattern, r.URL.Path) {
				limiter = l
				break
			}
		}
		pel.mu.RUnlock()

		if limiter == nil {
			limiter = pel.defaults
		}

		// Apply rate limiting
		clientID := getClientID(r)
		clientLimiter := limiter.getLimiter(clientID)

		if !clientLimiter.Allow() {
			log.Warn().
				Str("client_id", clientID).
				Str("path", r.URL.Path).
				Msg("Rate limit exceeded")

			http.Error(w, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Helper functions
func getClientID(r *http.Request) string {
	// Try to get user ID from context (JWT authenticated)
	if userID := r.Context().Value("user_id"); userID != nil {
		return "user:" + userID.(string)
	}

	// Fall back to IP address
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.RemoteAddr
	}
	return "ip:" + ip
}

func matchPath(pattern, path string) bool {
	// Simple pattern matching - can be enhanced with regex or path templates
	return pattern == path || (len(pattern) > 0 && pattern[len(pattern)-1] == '*' &&
		len(path) >= len(pattern)-1 && path[:len(pattern)-1] == pattern[:len(pattern)-1])
}
