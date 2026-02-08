package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dmorris/wopi/internal/config"
	"github.com/dmorris/wopi/internal/handlers"
	"github.com/dmorris/wopi/internal/middleware"
	"github.com/dmorris/wopi/internal/storage"
	"github.com/dmorris/wopi/internal/wopi"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	cfg, err := config.LoadFromEnv()
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	ctx := context.Background()
	s3Store, err := storage.NewS3Storage(ctx, storage.S3Config{
		Endpoint:       cfg.S3Endpoint,
		Region:         cfg.S3Region,
		Bucket:         cfg.S3Bucket,
		AccessKeyID:    cfg.S3AccessKeyID,
		SecretAccessKey: cfg.S3SecretAccessKey,
		UseSSL:         cfg.S3UseSSL,
		ForcePathStyle: cfg.S3ForcePathStyle,
	})
	if err != nil {
		logger.Error("failed to create S3 storage", "error", err)
		os.Exit(1)
	}

	lockMgr := wopi.NewLockManager(cfg.LockExpiration)
	tokenValidator := middleware.NewTokenValidator(cfg.AccessTokenSecret)

	h := &handlers.Handler{
		Storage:     s3Store,
		LockManager: lockMgr,
		Logger:      logger,
		BaseURL:     cfg.BaseURL,
	}

	mux := http.NewServeMux()

	// Health check (no auth required)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Token generation endpoint (for testing/integration)
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		userID := r.URL.Query().Get("user_id")
		fileID := r.URL.Query().Get("file_id")
		if userID == "" || fileID == "" {
			http.Error(w, "user_id and file_id required", http.StatusBadRequest)
			return
		}
		token := tokenValidator.GenerateToken(userID, fileID)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"%s","access_token_ttl":%d}`, token, middleware.TokenTTL())
	})

	// WOPI endpoints (with auth middleware)
	authMiddleware := middleware.WOPIAuth(tokenValidator)
	logMiddleware := middleware.RequestLogger(logger)

	// CheckFileInfo: GET /wopi/files/{file_id}
	mux.Handle("GET /wopi/files/{file_id}", logMiddleware(authMiddleware(http.HandlerFunc(h.CheckFileInfo))))

	// File operations: POST /wopi/files/{file_id} (dispatched by X-WOPI-Override)
	mux.Handle("POST /wopi/files/{file_id}", logMiddleware(authMiddleware(http.HandlerFunc(h.FilesHandler))))

	// Contents: GET and POST /wopi/files/{file_id}/contents
	mux.Handle("GET /wopi/files/{file_id}/contents", logMiddleware(authMiddleware(http.HandlerFunc(h.ContentsHandler))))
	mux.Handle("POST /wopi/files/{file_id}/contents", logMiddleware(authMiddleware(http.HandlerFunc(h.ContentsHandler))))

	addr := fmt.Sprintf(":%d", cfg.Port)
	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh

		logger.Info("shutting down server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("server shutdown error", "error", err)
		}
	}()

	logger.Info("starting WOPI server", "addr", addr, "base_url", cfg.BaseURL)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}

	logger.Info("server stopped")
}
