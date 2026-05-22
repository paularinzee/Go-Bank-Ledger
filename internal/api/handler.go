// Package api exposes HTTP handlers, middleware, and response types for the ledger service.
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"

	"github.com/paularinzee/bank-ledger/db/sqlc"
	"github.com/paularinzee/bank-ledger/internal/db"
	"github.com/paularinzee/bank-ledger/internal/service"
)

// Explicit request schemas replacing invalid anonymous object types in Swag parser
type AuthRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type CreateAccountRequest struct {
	Name string `json:"name" binding:"required"`
}

type AmountRequest struct {
	Amount string `json:"amount" binding:"required"`
}

type TransferRequest struct {
	Amount        interface{} `json:"amount" binding:"required"`
	FromID        string      `json:"from_id"`
	ToID          string      `json:"to_id"`
	FromAccountID string      `json:"from_account_id"`
	ToAccountID   string      `json:"to_account_id"`
}

// Handler serves HTTP requests backed by the ledger and store layers.
type Handler struct {
	ledger *service.LedgerService
	store  *db.Store
}

// NewHandler constructs a Handler with the required service and persistence dependencies.
func NewHandler(ledger *service.LedgerService, store *db.Store) *Handler {
	return &Handler{ledger: ledger, store: store}
}

// Register godoc
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var input AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		log.Warn().Err(err).Msg("Failed to decode register request")
		respondError(w, http.StatusBadRequest, "invalid input")
		return
	}

	if input.Email == "" || input.Password == "" {
		respondError(w, http.StatusBadRequest, "email and password required")
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Error().Err(err).Msg("Failed to hash password")
		respondError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	user, err := h.store.CreateUser(r.Context(), sqlc.CreateUserParams{
		Email:          input.Email,
		HashedPassword: string(hashed),
	})
	if err != nil {
		log.Error().Err(err).Str("email", input.Email).Msg("Failed to create user")
		respondError(w, http.StatusConflict, "user already exists or failed")
		return
	}

	token, err := GenerateToken(user.ID)
	if err != nil {
		log.Error().Err(err).Str("user_id", user.ID.String()).Msg("Failed to generate token")
		respondError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	log.Info().Str("user_id", user.ID.String()).Str("email", user.Email).Msg("User registered successfully")
	respondJSON(w, http.StatusCreated, RegisterResponse{
		UserID: user.ID.String(),
		Email:  user.Email,
		Token:  token,
	})
}

// Login godoc
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var input AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		log.Warn().Err(err).Msg("Failed to decode login request")
		respondError(w, http.StatusBadRequest, "invalid input")
		return
	}

	user, err := h.store.GetUserByEmail(r.Context(), input.Email)
	if err != nil {
		log.Warn().Err(err).Str("email", input.Email).Msg("Login failed - user not found")
		respondError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if compareErr := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(input.Password)); compareErr != nil {
		log.Warn().Str("email", input.Email).Msg("Login failed - invalid password")
		respondError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	token, err := GenerateToken(user.ID)
	if err != nil {
		log.Error().Err(err).Str("user_id", user.ID.String()).Msg("Failed to generate token")
		respondError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	log.Info().Str("user_id", user.ID.String()).Str("email", user.Email).Msg("User logged in successfully")
	respondJSON(w, http.StatusOK, TokenResponse{Token: token})
}

// CreateAccount godoc
func (h *Handler) CreateAccount(w http.ResponseWriter, r *http.Request) {
	_, claims, err := jwtauth.FromContext(r.Context())
	if err != nil {
		log.Warn().Err(err).Msg("Failed to extract JWT from context")
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	userIDStr, ok := claims["user_id"].(string)
	if !ok {
		log.Warn().Msg("user_id claim missing or invalid in JWT")
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		log.Error().Err(err).Str("user_id_str", userIDStr).Msg("Invalid user_id UUID in token")
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}

	var input CreateAccountRequest
	if decodeErr := json.NewDecoder(r.Body).Decode(&input); decodeErr != nil || input.Name == "" {
		respondError(w, http.StatusBadRequest, "name required")
		return
	}

	acc, err := h.store.CreateAccount(r.Context(), sqlc.CreateAccountParams{
		OwnerID:  uuid.NullUUID{UUID: userID, Valid: true},
		Name:     input.Name,
		Currency: "USD",
		IsSystem: false,
	})
	if err != nil {
		log.Error().Err(err).Str("user_id", userID.String()).Str("name", input.Name).Msg("Failed to create account")
		respondError(w, http.StatusInternalServerError, "failed to create account")
		return
	}

	log.Info().Str("account_id", acc.ID.String()).Str("user_id", userID.String()).Str("name", acc.Name).Msg("Account created")
	respondJSON(w, http.StatusCreated, toAccountResponse(acc))
}

// ListAccounts godoc
func (h *Handler) ListAccounts(w http.ResponseWriter, r *http.Request) {
	_, claims, err := jwtauth.FromContext(r.Context())
	if err != nil {
		log.Warn().Err(err).Msg("Failed to extract JWT from context")
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	userIDStr, ok := claims["user_id"].(string)
	if !ok {
		log.Warn().Msg("user_id claim missing or invalid in JWT")
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		log.Error().Err(err).Str("user_id_str", userIDStr).Msg("Invalid user_id UUID in token")
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}

	accounts, err := h.store.ListAccountsByOwner(r.Context(), uuid.NullUUID{UUID: userID, Valid: true})
	if err != nil {
		log.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to list accounts")
		respondError(w, http.StatusInternalServerError, "failed to list accounts")
		return
	}

	response := make([]AccountResponse, len(accounts))
	for i, acc := range accounts {
		response[i] = toAccountResponse(acc)
	}

	respondJSON(w, http.StatusOK, response)
}

// GetAccount godoc
func (h *Handler) GetAccount(w http.ResponseWriter, r *http.Request) {
	_, claims, err := jwtauth.FromContext(r.Context())
	if err != nil {
		log.Warn().Err(err).Msg("Failed to extract JWT from context")
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	userIDStr, ok := claims["user_id"].(string)
	if !ok {
		log.Warn().Msg("user_id claim missing or invalid in JWT")
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		log.Error().Err(err).Str("user_id_str", userIDStr).Msg("Invalid user_id UUID in token")
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}

	accountIDStr := chi.URLParam(r, "id")
	accountID, err := uuid.Parse(accountIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid account ID")
		return
	}

	acc, err := h.store.GetAccount(r.Context(), accountID)
	if err != nil {
		log.Warn().Err(err).Str("account_id", accountID.String()).Msg("Account not found")
		respondError(w, http.StatusNotFound, "account not found")
		return
	}

	if acc.OwnerID.Valid && acc.OwnerID.UUID != userID {
		log.Warn().Str("account_id", accountID.String()).Str("user_id", userID.String()).Str("owner_id", acc.OwnerID.UUID.String()).Msg("Access denied to account")
		respondError(w, http.StatusForbidden, "access denied")
		return
	}

	respondJSON(w, http.StatusOK, toAccountResponse(acc))
}

// Deposit godoc

// @Summary      Deposit money into an account
// @Description  Deposits a specified fiat amount into the given ledger account.
// @Tags         accounts
// @Accept       json
// @Produce      json
// @Param        X-Idempotency-Key header    string  true  "Unique transaction execution key"
// @Param        id                path      string  true  "Account UUID"
// @Param        body              body      AmountRequest true "Deposit Amount Payload"
// @Success      200               {object}  MessageResponse
// @Failure      400               {object}  string "Invalid input or currency mismatch"
// @Failure      401               {object}  string "Unauthorized token"
// @Router       /accounts/{id}/deposit [post]

func (h *Handler) Deposit(w http.ResponseWriter, r *http.Request) {
	_, claims, err := jwtauth.FromContext(r.Context())
	if err != nil {
		log.Warn().Err(err).Msg("Failed to extract JWT from context")
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	userIDStr, ok := claims["user_id"].(string)
	if !ok {
		log.Warn().Msg("user_id claim missing or invalid in JWT")
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		log.Error().Err(err).Str("user_id_str", userIDStr).Msg("Invalid user_id UUID in token")
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}

	accountID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid account ID")
		return
	}

	acc, err := h.store.GetAccount(r.Context(), accountID)
	if err != nil {
		log.Warn().Err(err).Str("account_id", accountID.String()).Msg("Deposit failed - account not found")
		respondError(w, http.StatusNotFound, "account not found")
		return
	}
	if acc.OwnerID.Valid && acc.OwnerID.UUID != userID {
		log.Warn().Str("account_id", accountID.String()).Str("user_id", userID.String()).Msg("Deposit denied - access forbidden")
		respondError(w, http.StatusForbidden, "access denied")
		return
	}

	amount, err := decodeAmountFromBody(r)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to decode deposit request")
		respondError(w, http.StatusBadRequest, "invalid input")
		return
	}

	err = h.ledger.Deposit(r.Context(), accountID, amount)
	if err != nil {
		log.Error().Err(err).Str("account_id", accountID.String()).Str("amount", amount).Msg("Deposit failed")
		code := http.StatusInternalServerError
		if errors.Is(err, service.ErrInvalidAmount) || errors.Is(err, service.ErrCurrencyMismatch) {
			code = http.StatusBadRequest
		}
		respondError(w, code, err.Error())
		return
	}

	log.Info().Str("account_id", accountID.String()).Str("user_id", userID.String()).Str("amount", amount).Msg("Deposit successful")
	respondJSON(w, http.StatusOK, MessageResponse{Message: "deposit successful"})
}

// Withdraw godoc
// @Summary      Withdraw money from an account
// @Description  Withdraws a specified fiat amount from the given ledger account.
// @Tags         accounts
// @Accept       json
// @Produce      json
// @Param        X-Idempotency-Key header    string  true  "Unique transaction execution key"
// @Param        id                path      string  true  "Account UUID"
// @Param        body              body      AmountRequest true "Withdrawal Amount Payload"
// @Success      200               {object}  MessageResponse
// @Failure      400               {object}  string "Insufficient funds or invalid input"
// @Failure      401               {object}  string "Unauthorized token"
// @Router       /accounts/{id}/withdraw [post]
func (h *Handler) Withdraw(w http.ResponseWriter, r *http.Request) {
	_, claims, err := jwtauth.FromContext(r.Context())
	if err != nil {
		log.Warn().Err(err).Msg("Failed to extract JWT from context")
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	userIDStr, ok := claims["user_id"].(string)
	if !ok {
		log.Warn().Msg("user_id claim missing or invalid in JWT")
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		log.Error().Err(err).Str("user_id_str", userIDStr).Msg("Invalid user_id UUID in token")
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}

	accountID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid account ID")
		return
	}

	acc, err := h.store.GetAccount(r.Context(), accountID)
	if err != nil {
		log.Warn().Err(err).Str("account_id", accountID.String()).Msg("Withdrawal failed - account not found")
		respondError(w, http.StatusNotFound, "account not found")
		return
	}
	if acc.OwnerID.Valid && acc.OwnerID.UUID != userID {
		log.Warn().Str("account_id", accountID.String()).Str("user_id", userID.String()).Msg("Withdrawal denied - access forbidden")
		respondError(w, http.StatusForbidden, "access denied")
		return
	}

	amount, err := decodeAmountFromBody(r)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to decode withdrawal request")
		respondError(w, http.StatusBadRequest, "invalid input")
		return
	}

	err = h.ledger.Withdraw(r.Context(), accountID, amount)
	if err != nil {
		log.Error().Err(err).Str("account_id", accountID.String()).Str("amount", amount).Msg("Withdrawal failed")
		code := http.StatusInternalServerError
		if errors.Is(err, service.ErrInsufficientFunds) || errors.Is(err, service.ErrInvalidAmount) || errors.Is(err, service.ErrCurrencyMismatch) {
			code = http.StatusBadRequest
		}
		respondError(w, code, err.Error())
		return
	}

	log.Info().Str("account_id", accountID.String()).Str("user_id", userID.String()).Str("amount", amount).Msg("Withdrawal successful")
	respondJSON(w, http.StatusOK, MessageResponse{Message: "withdrawal successful"})
}

// Transfer godoc
// @Summary      Transfer money between accounts
// @Description  Transfers funds between accounts with atomic double-entry verification.
// @Tags         transfers
// @Accept       json
// @Produce      json
// @Param        X-Idempotency-Key header    string  true  "Unique transaction execution key"
// @Param        body              body      TransferRequest true "Transfer Payload"
// @Success      200               {object}  MessageResponse
// @Failure      400               {object}  string "Invalid payload structure"
// @Failure      401               {object}  string "Unauthorized token"
// @Router       /transfers [post]
func (h *Handler) Transfer(w http.ResponseWriter, r *http.Request) {
	_, claims, err := jwtauth.FromContext(r.Context())
	if err != nil {
		log.Warn().Err(err).Msg("Failed to extract JWT from context")
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	userIDStr, ok := claims["user_id"].(string)
	if !ok {
		log.Warn().Msg("user_id claim missing or invalid in JWT")
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		log.Error().Err(err).Str("user_id_str", userIDStr).Msg("Invalid user_id UUID in token")
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}

	var input TransferRequest
	dec := json.NewDecoder(r.Body)
	dec.UseNumber()
	if decodeErr := dec.Decode(&input); decodeErr != nil {
		log.Warn().Err(decodeErr).Msg("Failed to decode transfer request")
		respondError(w, http.StatusBadRequest, "invalid input")
		return
	}

	fromIDRaw := strings.TrimSpace(input.FromID)
	if fromIDRaw == "" {
		fromIDRaw = strings.TrimSpace(input.FromAccountID)
	}
	toIDRaw := strings.TrimSpace(input.ToID)
	if toIDRaw == "" {
		toIDRaw = strings.TrimSpace(input.ToAccountID)
	}

	log.Info().Str("from_id", fromIDRaw).Str("to_id", toIDRaw).Interface("amount", input.Amount).Msg("Transfer request received")

	if fromIDRaw == "" {
		respondError(w, http.StatusBadRequest, "from_id (or from_account_id) is required")
		return
	}
	if toIDRaw == "" {
		respondError(w, http.StatusBadRequest, "to_id (or to_account_id) is required")
		return
	}

	fromID, err := uuid.Parse(fromIDRaw)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid from_id format")
		return
	}

	toID, err := uuid.Parse(toIDRaw)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid to_id format")
		return
	}

	amount, err := normalizeAmountInput(input.Amount)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid input")
		return
	}

	fromAcc, err := h.store.GetAccount(r.Context(), fromID)
	if err != nil {
		respondError(w, http.StatusNotFound, "from account not found")
		return
	}
	if fromAcc.OwnerID.Valid && fromAcc.OwnerID.UUID != userID {
		respondError(w, http.StatusForbidden, "access denied")
		return
	}

	err = h.ledger.Transfer(r.Context(), fromID, toID, amount)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, MessageResponse{Message: "transfer successful"})
}

// GetEntries godoc
func (h *Handler) GetEntries(w http.ResponseWriter, r *http.Request) {
	_, claims, err := jwtauth.FromContext(r.Context())
	if err != nil {
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	userIDStr, ok := claims["user_id"].(string)
	if !ok {
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}

	accountID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid account ID")
		return
	}

	acc, err := h.store.GetAccount(r.Context(), accountID)
	if err != nil {
		respondError(w, http.StatusNotFound, "account not found")
		return
	}
	if acc.OwnerID.Valid && acc.OwnerID.UUID != userID {
		respondError(w, http.StatusForbidden, "access denied")
		return
	}

	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := 20
	offset := 0

	if v, parseErr := strconv.Atoi(limitStr); parseErr == nil && v > 0 {
		limit = min(v, 100)
	}
	if v, parseErr := strconv.Atoi(offsetStr); parseErr == nil && v >= 0 {
		offset = v
	}

	entries, err := h.store.ListEntriesByAccount(r.Context(), sqlc.ListEntriesByAccountParams{
		AccountID: accountID,
		Limit:     int32(limit),
		Offset:    int32(offset),
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to fetch entries")
		return
	}

	response := make([]EntryResponse, len(entries))
	for i, entry := range entries {
		response[i] = toEntryResponse(entry)
	}

	respondJSON(w, http.StatusOK, response)
}

// GetTransactions godoc
func (h *Handler) GetTransactions(w http.ResponseWriter, r *http.Request) {
	_, claims, err := jwtauth.FromContext(r.Context())
	if err != nil {
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	userIDStr, ok := claims["user_id"].(string)
	if !ok {
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}

	transactionIDStr := chi.URLParam(r, "id")
	transactionID, err := uuid.Parse(transactionIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid transaction ID")
		return
	}

	entries, err := h.store.ListEntriesByTransaction(r.Context(), transactionID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to fetch transaction")
		return
	}

	if len(entries) == 0 {
		respondError(w, http.StatusNotFound, "transaction not found")
		return
	}

	authorized := false
	for _, entry := range entries {
		acc, err := h.store.GetAccount(r.Context(), entry.AccountID)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to authorize transaction")
			return
		}
		if acc.OwnerID.Valid && acc.OwnerID.UUID == userID {
			authorized = true
			break
		}
	}

	if !authorized {
		respondError(w, http.StatusForbidden, "access denied")
		return
	}

	response := make([]EntryResponse, len(entries))
	for i, entry := range entries {
		response[i] = toEntryResponse(entry)
	}

	respondJSON(w, http.StatusOK, response)
}

// ReconcileAccount godoc
func (h *Handler) ReconcileAccount(w http.ResponseWriter, r *http.Request) {
	_, claims, err := jwtauth.FromContext(r.Context())
	if err != nil {
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	userIDStr, ok := claims["user_id"].(string)
	if !ok {
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "invalid token")
		return
	}

	accountID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid account ID")
		return
	}

	acc, err := h.store.GetAccount(r.Context(), accountID)
	if err != nil {
		respondError(w, http.StatusNotFound, "account not found")
		return
	}
	if acc.OwnerID.Valid && acc.OwnerID.UUID != userID {
		respondError(w, http.StatusForbidden, "access denied")
		return
	}

	matched, err := h.ledger.ReconcileAccount(r.Context(), accountID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, ReconcileResponse{
		Matched: matched,
		Message: "Account reconciled successfully",
	})
}
