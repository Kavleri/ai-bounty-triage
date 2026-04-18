package api

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"secure-bounty-board/backend/internal/store"
)

type Server struct {
	store      *store.PostgresStore
	corsOrigin string
	jwtSecret  string
	loginLimit *loginRateLimiter
}

type authResponse struct {
	Token string     `json:"token"`
	User  store.User `json:"user"`
}

func NewServer(st *store.PostgresStore, corsOrigin, jwtSecret string) http.Handler {
	s := &Server{
		store:      st,
		corsOrigin: corsOrigin,
		jwtSecret:  jwtSecret,
		loginLimit: newLoginRateLimiter(10, time.Minute),
	}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("POST /api/v1/auth/register", s.register)
	mux.Handle("POST /api/v1/auth/login", s.withLoginRateLimit(http.HandlerFunc(s.login)))
	mux.Handle("GET /api/v1/auth/me", s.authMiddleware(http.HandlerFunc(s.me)))
	mux.Handle("GET /api/v1/findings", s.authMiddleware(s.requireRoles(http.HandlerFunc(s.listFindings), "researcher", "triager", "admin")))
	mux.Handle("POST /api/v1/findings", s.authMiddleware(s.requireRoles(http.HandlerFunc(s.createFinding), "researcher", "admin")))
	mux.Handle("POST /api/v1/findings/{id}/triage", s.authMiddleware(s.requireRoles(http.HandlerFunc(s.triageFinding), "triager", "admin")))
	mux.Handle("GET /api/v1/audit-logs", s.authMiddleware(s.requireRoles(http.HandlerFunc(s.listAuditLogs), "admin")))

	return s.withSecurityHeaders(s.withCORS(mux))
}

func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'self'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && (origin == s.corsOrigin || s.corsOrigin == "*") {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_json", "invalid json body")
		return
	}

	in.Username = strings.TrimSpace(in.Username)
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if len(in.Password) < 8 || in.Username == "" || in.Email == "" {
		writeAPIError(w, http.StatusBadRequest, "validation_error", "username, email, and password are required")
		return
	}

	passwordHash, err := hashPassword(in.Password)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "password_hash_failed", "failed to process password")
		return
	}

	user, err := s.store.CreateUser(r.Context(), store.CreateUserParams{
		Username:     in.Username,
		Email:        in.Email,
		Role:         "researcher",
		PasswordHash: passwordHash,
	})
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			writeAPIError(w, http.StatusConflict, "user_exists", "user already exists")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "user_create_failed", "failed to create user")
		return
	}

	token, err := issueToken(user, s.jwtSecret, 24*time.Hour)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "token_issue_failed", "failed to create token")
		return
	}

	_ = s.store.InsertAuditLog(r.Context(), &user.ID, "auth.register", "user", &user.ID, map[string]any{"email": user.Email, "role": user.Role})
	writeJSON(w, http.StatusCreated, authResponse{Token: token, User: user})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_json", "invalid json body")
		return
	}

	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if in.Email == "" || in.Password == "" {
		writeAPIError(w, http.StatusBadRequest, "validation_error", "email and password are required")
		return
	}

	user, err := s.store.GetUserByEmail(r.Context(), in.Email)
	if err != nil {
		writeAPIError(w, http.StatusUnauthorized, "invalid_credentials", "invalid credentials")
		return
	}

	if err := comparePassword(user.PasswordHash, in.Password); err != nil {
		writeAPIError(w, http.StatusUnauthorized, "invalid_credentials", "invalid credentials")
		return
	}

	now := time.Now().UTC()
	_ = s.store.UpdateUserLastLogin(r.Context(), user.ID, now)
	_ = s.store.InsertAuditLog(r.Context(), &user.ID, "auth.login", "user", &user.ID, map[string]any{"email": user.Email})

	token, err := issueToken(user, s.jwtSecret, 24*time.Hour)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "token_issue_failed", "failed to create token")
		return
	}

	writeJSON(w, http.StatusOK, authResponse{Token: token, User: user})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUserFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
		return
	}

	current, err := s.store.GetUserByID(r.Context(), user.ID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "user_load_failed", "failed to load user")
		return
	}

	writeJSON(w, http.StatusOK, current)
}

func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListFindings(r.Context())
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "findings_list_failed", "failed to list findings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type createFindingInput struct {
	ProjectID   *int64  `json:"project_id"`
	Title       string  `json:"title"`
	Severity    string  `json:"severity"`
	CVSSScore   float64 `json:"cvss_score"`
	Description string  `json:"description"`
}

func (s *Server) createFinding(w http.ResponseWriter, r *http.Request) {
	actor, ok := currentUserFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
		return
	}

	var in createFindingInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_json", "invalid json body")
		return
	}

	in.Title = strings.TrimSpace(in.Title)
	in.Description = strings.TrimSpace(in.Description)
	in.Severity = strings.ToLower(strings.TrimSpace(in.Severity))

	if in.Title == "" || in.Description == "" {
		writeAPIError(w, http.StatusBadRequest, "validation_error", "title and description are required")
		return
	}
	if in.CVSSScore < 0 || in.CVSSScore > 10 {
		writeAPIError(w, http.StatusBadRequest, "validation_error", "cvss_score must be between 0 and 10")
		return
	}

	allowed := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	if !allowed[in.Severity] {
		writeAPIError(w, http.StatusBadRequest, "validation_error", "invalid severity")
		return
	}

	triage := buildAITriage(in.Title, in.Severity, in.Description, in.CVSSScore)
	item, err := s.store.CreateFinding(r.Context(), store.CreateFindingParams{
		ProjectID:        in.ProjectID,
		Title:            in.Title,
		Severity:         in.Severity,
		CVSSScore:        in.CVSSScore,
		Description:      in.Description,
		AISummary:        triage.Summary,
		AIRecommendation: triage.Recommendation,
		AIPriority:       triage.Priority,
		AIConfidence:     triage.Confidence,
	})
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "finding_create_failed", "failed to create finding")
		return
	}

	_ = s.store.InsertAuditLog(r.Context(), &actor.ID, "finding.created", "finding", &item.ID, map[string]any{
		"title":      item.Title,
		"severity":   item.Severity,
		"priority":   item.AIPriority,
		"confidence": item.AIConfidence,
	})

	writeJSON(w, http.StatusCreated, item)
}

type triageInput struct {
	Status string `json:"status"`
	Note   string `json:"note"`
}

func (s *Server) triageFinding(w http.ResponseWriter, r *http.Request) {
	actor, ok := currentUserFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
		return
	}

	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeAPIError(w, http.StatusBadRequest, "validation_error", "invalid finding id")
		return
	}

	var in triageInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil && !errors.Is(err, http.ErrBodyNotAllowed) {
		writeAPIError(w, http.StatusBadRequest, "invalid_json", "invalid json body")
		return
	}

	status := strings.ToLower(strings.TrimSpace(in.Status))
	if status == "" {
		status = "triaged"
	}
	allowed := map[string]bool{"triaged": true, "resolved": true, "closed": true}
	if !allowed[status] {
		writeAPIError(w, http.StatusBadRequest, "validation_error", "invalid triage status")
		return
	}

	item, err := s.store.UpdateFindingStatus(r.Context(), store.UpdateFindingStatusParams{
		ID:               id,
		Status:           status,
		ReviewedByUserID: &actor.ID,
	})
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "finding_update_failed", "failed to update finding")
		return
	}

	_ = s.store.InsertAuditLog(r.Context(), &actor.ID, "finding.triaged", "finding", &item.ID, map[string]any{
		"status": status,
		"note":   strings.TrimSpace(in.Note),
	})

	writeJSON(w, http.StatusOK, item)
}

func (s *Server) listAuditLogs(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListAuditLogs(r.Context(), 100)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "audit_logs_list_failed", "failed to list audit logs")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

type apiErrorResponse struct {
	Error apiError `json:"error"`
}

func writeAPIError(w http.ResponseWriter, status int, code, message string, details ...any) {
	resp := apiErrorResponse{
		Error: apiError{Code: code, Message: message},
	}
	if len(details) > 0 {
		resp.Error.Details = details[0]
	}
	writeJSON(w, status, resp)
}

type loginRateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	entries map[string]loginRateEntry
}

type loginRateEntry struct {
	count   int
	resetAt time.Time
}

func newLoginRateLimiter(limit int, window time.Duration) *loginRateLimiter {
	return &loginRateLimiter{
		limit:   limit,
		window:  window,
		entries: make(map[string]loginRateEntry),
	}
}

func (l *loginRateLimiter) allow(key string, now time.Time) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry, ok := l.entries[key]
	if !ok || now.After(entry.resetAt) {
		l.entries[key] = loginRateEntry{count: 1, resetAt: now.Add(l.window)}
		return true, 0
	}

	if entry.count >= l.limit {
		retryAfter := int(time.Until(entry.resetAt).Seconds())
		if retryAfter < 1 {
			retryAfter = 1
		}
		return false, retryAfter
	}

	entry.count++
	l.entries[key] = entry
	return true, 0
}

func (s *Server) withLoginRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		client := requestClientIP(r)
		allowed, retryAfter := s.loginLimit.allow(client, time.Now())
		if !allowed {
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			writeAPIError(w, http.StatusTooManyRequests, "rate_limited", "too many login attempts, try again later", map[string]any{"retry_after_seconds": retryAfter})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requestClientIP(r *http.Request) string {
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	if strings.TrimSpace(r.RemoteAddr) == "" {
		return "unknown"
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
