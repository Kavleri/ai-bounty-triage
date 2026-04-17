package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	pool *pgxpool.Pool
}

type User struct {
	ID           int64      `json:"id"`
	Username     string     `json:"username"`
	Email        string     `json:"email"`
	Role         string     `json:"role"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	PasswordHash string     `json:"-"`
}

type Finding struct {
	ID               int64      `json:"id"`
	ProjectID        *int64     `json:"project_id,omitempty"`
	Title            string     `json:"title"`
	Severity         string     `json:"severity"`
	CVSSScore        float64    `json:"cvss_score"`
	Description      string     `json:"description"`
	Status           string     `json:"status"`
	AISummary        string     `json:"ai_summary,omitempty"`
	AIRecommendation string     `json:"ai_recommendation,omitempty"`
	AIPriority       string     `json:"ai_priority,omitempty"`
	AIConfidence     float64    `json:"ai_confidence,omitempty"`
	ReviewedBy       *int64     `json:"reviewed_by,omitempty"`
	ReviewedAt       *time.Time `json:"reviewed_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

type AuditLog struct {
	ID          int64          `json:"id"`
	ActorUserID *int64         `json:"actor_user_id,omitempty"`
	Action      string         `json:"action"`
	EntityType  string         `json:"entity_type"`
	EntityID    *int64         `json:"entity_id,omitempty"`
	Metadata    map[string]any `json:"metadata"`
	CreatedAt   time.Time      `json:"created_at"`
}

type CreateUserParams struct {
	Username     string
	Email        string
	Role         string
	PasswordHash string
}

type CreateFindingParams struct {
	ProjectID        *int64
	Title            string
	Severity         string
	CVSSScore        float64
	Description      string
	AISummary        string
	AIRecommendation string
	AIPriority       string
	AIConfidence     float64
}

type UpdateFindingStatusParams struct {
	ID               int64
	Status           string
	ReviewedByUserID *int64
}

func NewPostgresStore(ctx context.Context, databaseURL string) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, err
	}
	return &PostgresStore{pool: pool}, nil
}

func (s *PostgresStore) Close() {
	s.pool.Close()
}

func (s *PostgresStore) CreateUser(ctx context.Context, in CreateUserParams) (User, error) {
	const query = `
		INSERT INTO users (username, email, role, password_hash)
		VALUES ($1, $2, $3, $4)
		RETURNING id, username, email, role, password_hash, last_login_at, created_at
	`

	var user User
	if err := s.pool.QueryRow(ctx, query, in.Username, in.Email, in.Role, in.PasswordHash).
		Scan(&user.ID, &user.Username, &user.Email, &user.Role, &user.PasswordHash, &user.LastLoginAt, &user.CreatedAt); err != nil {
		return User{}, err
	}

	return user, nil
}

func (s *PostgresStore) GetUserByEmail(ctx context.Context, email string) (User, error) {
	const query = `
		SELECT id, username, email, role, password_hash, last_login_at, created_at
		FROM users
		WHERE email = $1
	`

	var user User
	if err := s.pool.QueryRow(ctx, query, email).
		Scan(&user.ID, &user.Username, &user.Email, &user.Role, &user.PasswordHash, &user.LastLoginAt, &user.CreatedAt); err != nil {
		return User{}, err
	}

	return user, nil
}

func (s *PostgresStore) GetUserByID(ctx context.Context, id int64) (User, error) {
	const query = `
		SELECT id, username, email, role, password_hash, last_login_at, created_at
		FROM users
		WHERE id = $1
	`

	var user User
	if err := s.pool.QueryRow(ctx, query, id).
		Scan(&user.ID, &user.Username, &user.Email, &user.Role, &user.PasswordHash, &user.LastLoginAt, &user.CreatedAt); err != nil {
		return User{}, err
	}

	return user, nil
}

func (s *PostgresStore) UpdateUserLastLogin(ctx context.Context, id int64, lastLoginAt time.Time) error {
	const query = `
		UPDATE users
		SET last_login_at = $2
		WHERE id = $1
	`
	_, err := s.pool.Exec(ctx, query, id, lastLoginAt)
	return err
}

func (s *PostgresStore) ListFindings(ctx context.Context) ([]Finding, error) {
	const query = `
		SELECT id, project_id, title, severity, cvss_score, description, status,
		       COALESCE(ai_summary, ''),
		       COALESCE(ai_recommendation, ''),
		       COALESCE(ai_priority, ''),
		       COALESCE(ai_confidence, 0),
		       reviewed_by, reviewed_at, created_at
		FROM findings
		ORDER BY id DESC
	`

	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]Finding, 0)
	for rows.Next() {
		var item Finding
		var projectID sql.NullInt64
		var reviewedBy sql.NullInt64
		var reviewedAt sql.NullTime
		if err := rows.Scan(
			&item.ID,
			&projectID,
			&item.Title,
			&item.Severity,
			&item.CVSSScore,
			&item.Description,
			&item.Status,
			&item.AISummary,
			&item.AIRecommendation,
			&item.AIPriority,
			&item.AIConfidence,
			&reviewedBy,
			&reviewedAt,
			&item.CreatedAt,
		); err != nil {
			return nil, err
		}
		item.ProjectID = nullInt64Ptr(projectID)
		item.ReviewedBy = nullInt64Ptr(reviewedBy)
		item.ReviewedAt = nullTimePtr(reviewedAt)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return items, nil
}

func (s *PostgresStore) CreateFinding(ctx context.Context, in CreateFindingParams) (Finding, error) {
	const query = `
		INSERT INTO findings (
			project_id, title, severity, cvss_score, description, status,
			ai_summary, ai_recommendation, ai_priority, ai_confidence
		)
		VALUES ($1, $2, $3, $4, $5, 'open', $6, $7, $8, $9)
		RETURNING id, project_id, title, severity, cvss_score, description, status,
		          COALESCE(ai_summary, ''),
		          COALESCE(ai_recommendation, ''),
		          COALESCE(ai_priority, ''),
		          COALESCE(ai_confidence, 0),
		          reviewed_by, reviewed_at, created_at
	`

	var item Finding
	var projectID sql.NullInt64
	var reviewedBy sql.NullInt64
	var reviewedAt sql.NullTime
	if err := s.pool.QueryRow(
		ctx,
		query,
		in.ProjectID,
		in.Title,
		in.Severity,
		in.CVSSScore,
		in.Description,
		in.AISummary,
		in.AIRecommendation,
		in.AIPriority,
		in.AIConfidence,
	).Scan(
		&item.ID,
		&projectID,
		&item.Title,
		&item.Severity,
		&item.CVSSScore,
		&item.Description,
		&item.Status,
		&item.AISummary,
		&item.AIRecommendation,
		&item.AIPriority,
		&item.AIConfidence,
		&reviewedBy,
		&reviewedAt,
		&item.CreatedAt,
	); err != nil {
		return Finding{}, err
	}

	item.ProjectID = nullInt64Ptr(projectID)
	item.ReviewedBy = nullInt64Ptr(reviewedBy)
	item.ReviewedAt = nullTimePtr(reviewedAt)
	return item, nil
}

func (s *PostgresStore) UpdateFindingStatus(ctx context.Context, in UpdateFindingStatusParams) (Finding, error) {
	const query = `
		UPDATE findings
		SET status = $2,
		    reviewed_by = $3,
		    reviewed_at = NOW()
		WHERE id = $1
		RETURNING id, project_id, title, severity, cvss_score, description, status,
		          COALESCE(ai_summary, ''),
		          COALESCE(ai_recommendation, ''),
		          COALESCE(ai_priority, ''),
		          COALESCE(ai_confidence, 0),
		          reviewed_by, reviewed_at, created_at
	`

	var item Finding
	var projectID sql.NullInt64
	var reviewedBy sql.NullInt64
	var reviewedAt sql.NullTime
	if err := s.pool.QueryRow(ctx, query, in.ID, in.Status, in.ReviewedByUserID).
		Scan(
			&item.ID,
			&projectID,
			&item.Title,
			&item.Severity,
			&item.CVSSScore,
			&item.Description,
			&item.Status,
			&item.AISummary,
			&item.AIRecommendation,
			&item.AIPriority,
			&item.AIConfidence,
			&reviewedBy,
			&reviewedAt,
			&item.CreatedAt,
		); err != nil {
		return Finding{}, err
	}

	item.ProjectID = nullInt64Ptr(projectID)
	item.ReviewedBy = nullInt64Ptr(reviewedBy)
	item.ReviewedAt = nullTimePtr(reviewedAt)
	return item, nil
}

func (s *PostgresStore) ListAuditLogs(ctx context.Context, limit int32) ([]AuditLog, error) {
	const query = `
		SELECT id, actor_user_id, action, entity_type, entity_id, metadata, created_at
		FROM audit_logs
		ORDER BY id DESC
		LIMIT $1
	`

	rows, err := s.pool.Query(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]AuditLog, 0)
	for rows.Next() {
		var item AuditLog
		var actorUserID sql.NullInt64
		var entityID sql.NullInt64
		var metadataRaw []byte
		if err := rows.Scan(&item.ID, &actorUserID, &item.Action, &item.EntityType, &entityID, &metadataRaw, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.ActorUserID = nullInt64Ptr(actorUserID)
		item.EntityID = nullInt64Ptr(entityID)
		if len(metadataRaw) > 0 {
			_ = json.Unmarshal(metadataRaw, &item.Metadata)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return items, nil
}

func (s *PostgresStore) InsertAuditLog(ctx context.Context, actorUserID *int64, action, entityType string, entityID *int64, metadata map[string]any) error {
	const query = `
		INSERT INTO audit_logs (actor_user_id, action, entity_type, entity_id, metadata)
		VALUES ($1, $2, $3, $4, $5)
	`

	if metadata == nil {
		metadata = map[string]any{}
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	_, err = s.pool.Exec(ctx, query, actorUserID, action, entityType, entityID, metadataJSON)
	return err
}

func nullInt64Ptr(v sql.NullInt64) *int64 {
	if !v.Valid {
		return nil
	}
	value := v.Int64
	return &value
}

func nullTimePtr(v sql.NullTime) *time.Time {
	if !v.Valid {
		return nil
	}
	value := v.Time
	return &value
}
