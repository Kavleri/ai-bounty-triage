package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"secure-bounty-board/backend/internal/api"
	"secure-bounty-board/backend/internal/store"
)

func main() {
	ctx := context.Background()

	databaseURL := getEnv("DATABASE_URL", "postgres://postgres:postgres@localhost:55432/secure_bounty?sslmode=disable")
	port := getEnv("PORT", "8080")
	corsOrigin := getEnv("CORS_ORIGIN", "http://localhost:5173")
	jwtSecret := strings.TrimSpace(os.Getenv("JWT_SECRET"))
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET is required and cannot be empty")
	}

	st, err := store.NewPostgresStore(ctx, databaseURL)
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}
	defer st.Close()

	handler := api.NewServer(st, corsOrigin, jwtSecret)

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("server running on :%s", port)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

func getEnv(key string, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
