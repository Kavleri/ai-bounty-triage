package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"secure-bounty-board/backend/internal/store"
)

type Server struct {
	store      *store.PostgresStore
	corsOrigin string
	jwtSecret  string
}

type authResponse struct {
	Token string     `json:"token"`
	User  store.User `json:"user"`
}

func NewServer(st *store.PostgresStore, corsOrigin, jwtSecret string) http.Handler {
	s := &Server{store: st, corsOrigin: corsOrigin, jwtSecret: jwtSecret}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("POST /api/v1/auth/register", s.register)
	mux.HandleFunc("POST /api/v1/auth/login", s.login)
	mux.Handle("GET /api/v1/auth/me", s.authMiddleware(http.HandlerFunc(s.me)))
	mux.Handle("GET /api/v1/findings", s.authMiddleware(s.requireRoles(http.HandlerFunc(s.listFindings), "researcher", "triager", "admin")))
	mux.Handle("POST /api/v1/findings", s.authMiddleware(s.requireRoles(http.HandlerFunc(s.createFinding), "researcher", "admin")))
	mux.Handle("POST /api/v1/findings/{id}/triage", s.authMiddleware(s.requireRoles(http.HandlerFunc(s.triageFinding), "triager", "admin")))
	mux.Handle("GET /api/v1/audit-logs", s.authMiddleware(s.requireRoles(http.HandlerFunc(s.listAuditLogs), "admin")))

	return s.withCORS(mux)
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
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json body"})
		return
	}

	in.Username = strings.TrimSpace(in.Username)
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if len(in.Password) < 8 || in.Username == "" || in.Email == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username, email, and password are required"})
		return
	}

	passwordHash, err := hashPassword(in.Password)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to process password"})
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
			writeJSON(w, http.StatusConflict, map[string]string{"error": "user already exists"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create user"})
		return
	}

	token, err := issueToken(user, s.jwtSecret, 24*time.Hour)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create token"})
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
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json body"})
		return
	}

	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if in.Email == "" || in.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email and password are required"})
		return
	}

	user, err := s.store.GetUserByEmail(r.Context(), in.Email)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	if err := comparePassword(user.PasswordHash, in.Password); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	now := time.Now().UTC()
	_ = s.store.UpdateUserLastLogin(r.Context(), user.ID, now)
	_ = s.store.InsertAuditLog(r.Context(), &user.ID, "auth.login", "user", &user.ID, map[string]any{"email": user.Email})

	token, err := issueToken(user, s.jwtSecret, 24*time.Hour)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create token"})
		return
	}

	writeJSON(w, http.StatusOK, authResponse{Token: token, User: user})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUserFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	current, err := s.store.GetUserByID(r.Context(), user.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load user"})
		return
	}

	writeJSON(w, http.StatusOK, current)
}

func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListFindings(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list findings"})
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
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	var in createFindingInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json body"})
		return
	}

	in.Title = strings.TrimSpace(in.Title)
	in.Description = strings.TrimSpace(in.Description)
	in.Severity = strings.ToLower(strings.TrimSpace(in.Severity))

	if in.Title == "" || in.Description == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "title and description are required"})
		return
	}
	if in.CVSSScore < 0 || in.CVSSScore > 10 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cvss_score must be between 0 and 10"})
		return
	}

	allowed := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	if !allowed[in.Severity] {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid severity"})
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create finding"})
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
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid finding id"})
		return
	}

	var in triageInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil && !errors.Is(err, http.ErrBodyNotAllowed) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json body"})
		return
	}

	status := strings.ToLower(strings.TrimSpace(in.Status))
	if status == "" {
		status = "triaged"
	}
	allowed := map[string]bool{"triaged": true, "resolved": true, "closed": true}
	if !allowed[status] {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid triage status"})
		return
	}

	item, err := s.store.UpdateFindingStatus(r.Context(), store.UpdateFindingStatusParams{
		ID:               id,
		Status:           status,
		ReviewedByUserID: &actor.ID,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update finding"})
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list audit logs"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
