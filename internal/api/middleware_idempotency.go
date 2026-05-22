package api

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"io"
	"net/http"

	"github.com/go-chi/jwtauth/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/paularinzee/bank-ledger/db/sqlc"
)

// responseBufferInterceptor captures writing hooks to save execution output safely
type responseBufferInterceptor struct {
	http.ResponseWriter
	statusCode int
	bodyBuffer bytes.Buffer
}

func (i *responseBufferInterceptor) WriteHeader(code int) {
	i.statusCode = code
	i.ResponseWriter.WriteHeader(code)
}

func (i *responseBufferInterceptor) Write(b []byte) (int, error) {
	if i.statusCode == 0 {
		i.statusCode = http.StatusOK
	}
	i.bodyBuffer.Write(b)
	return i.ResponseWriter.Write(b)
}

// IdempotencyMiddleware prevents duplicate execution of mutating ledger endpoints using SQLC
func (h *Handler) IdempotencyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only track mutating actions (POST, PUT, PATCH)
		if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodPatch {
			next.ServeHTTP(w, r)
			return
		}

		// Support both standard header casing and common proxy variations
		rawKey := r.Header.Get("X-Idempotency-Key")
		if rawKey == "" {
			rawKey = r.Header.Get("Idempotency-Key")
		}

		// If no idempotency key is passed, let it run normally (or return a 400 if you want it mandatory)
		if rawKey == "" {
			log.Debug().Msg("No Idempotency-Key found; passing through without tracking")
			next.ServeHTTP(w, r)
			return
		}

		// Extract authenticated user ID from context
		_, claims, err := jwtauth.FromContext(r.Context())
		if err != nil {
			log.Warn().Err(err).Msg("Idempotency failed: could not extract JWT claims from context")
			next.ServeHTTP(w, r)
			return
		}
		userIDStr, _ := claims["user_id"].(string)
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			log.Warn().Err(err).Str("user_id_str", userIDStr).Msg("Idempotency failed: invalid user_id UUID")
			next.ServeHTTP(w, r)
			return
		}

		// Intercept request body stream to tie payload structure context to the tracking hash
		var bodyPayload []byte
		if r.Body != nil {
			bodyPayload, _ = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewBuffer(bodyPayload))
		}

		// Calculate compound hash (Key + User ID + Body Payload)
		hasher := sha256.New()
		hasher.Write([]byte(rawKey))
		hasher.Write([]byte(userID.String()))
		hasher.Write(bodyPayload)
		compoundHash := hex.EncodeToString(hasher.Sum(nil))

		// FIX: Safely parse UserID field for SQLC parameters mapping
		// If your sqlc parameters use uuid.NullUUID, swap 'userID' below with: uuid.NullUUID{UUID: userID, Valid: true}
		cachedKey, dbErr := h.store.GetIdempotencyKey(r.Context(), sqlc.GetIdempotencyKeyParams{
			ID:     compoundHash,
			UserID: userID,
		})

		if dbErr == nil {
			log.Info().Str("idempotency_key", rawKey).Str("user_id", userID.String()).Msg("Idempotent track hit! Returning cached response payload")
			w.Header().Set("X-Cache-Idempotency", "HIT")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(int(cachedKey.ResponseCode))
			w.Write(cachedKey.ResponseBody)
			return
		}

		if dbErr != sql.ErrNoRows {
			log.Error().Err(dbErr).Msg("Database connectivity glitch checking idempotency key store")
		}

		// Intercept execution path
		interceptor := &responseBufferInterceptor{ResponseWriter: w, statusCode: 0}
		next.ServeHTTP(interceptor, r)

		if interceptor.statusCode == 0 {
			interceptor.statusCode = http.StatusOK
		}

		// Only store operational outcomes or domain validation exceptions (2xx, 4xx).
		if interceptor.statusCode < 500 {
			_, saveErr := h.store.CreateIdempotencyKey(r.Context(), sqlc.CreateIdempotencyKeyParams{
				ID:           compoundHash,
				UserID:       userID, // Match type used above
				ResponseCode: int32(interceptor.statusCode),
				ResponseBody: interceptor.bodyBuffer.Bytes(),
			})
			if saveErr != nil {
				log.Error().Err(saveErr).Msg("Failed to save idempotency key signature to database")
			}
		}
	})
}
