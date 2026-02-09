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

	"github.com/dmorris/wopi/internal/attrstore"
	"github.com/dmorris/wopi/internal/config"
	"github.com/dmorris/wopi/internal/handlers"
	"github.com/dmorris/wopi/internal/middleware"
	"github.com/dmorris/wopi/internal/platform"
	"github.com/dmorris/wopi/internal/storage"
	"github.com/dmorris/wopi/internal/tdf"
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

	// Warn about insecure defaults.
	if cfg.AccessTokenSecret == "change-me-in-production" {
		if !cfg.OIDCEnabled {
			logger.Error("WOPI_ACCESS_TOKEN_SECRET is at its default value and the /token endpoint is exposed — tokens can be forged by anyone. Set a strong random secret.")
			os.Exit(1)
		}
		logger.Warn("WOPI_ACCESS_TOKEN_SECRET is at its default value — set a strong random secret before deploying to production")
	}
	if cfg.TDFInsecureSkipVerify {
		logger.Warn("TDF_INSECURE_SKIP_VERIFY is enabled — TLS certificate verification is disabled for the OpenTDF SDK connection")
	}

	ctx := context.Background()
	s3Cfg := storage.S3Config{
		Endpoint:       cfg.S3Endpoint,
		Region:         cfg.S3Region,
		Bucket:         cfg.S3Bucket,
		AccessKeyID:    cfg.S3AccessKeyID,
		SecretAccessKey: cfg.S3SecretAccessKey,
		UseSSL:         cfg.S3UseSSL,
		ForcePathStyle: cfg.S3ForcePathStyle,
	}
	if cfg.S3BearerAuthEnabled {
		s3Cfg.BearerAuth = &storage.BearerAuthConfig{
			TokenURL:     cfg.S3BearerTokenURL,
			ClientID:     cfg.S3BearerClientID,
			ClientSecret: cfg.S3BearerClientSecret,
			Logger:       logger,
		}
		logger.Info("S3 bearer auth enabled", "token_url", cfg.S3BearerTokenURL, "client_id", cfg.S3BearerClientID)
	}
	s3Store, err := storage.NewS3Storage(ctx, s3Cfg)
	if err != nil {
		logger.Error("failed to create S3 storage", "error", err)
		os.Exit(1)
	}

	lockMgr := wopi.NewLockManager(cfg.LockExpiration)
	tokenValidator := middleware.NewTokenValidator(cfg.AccessTokenSecret)
	attrStore := attrstore.New()

	var platformClient *platform.Client
	if cfg.PlatformEndpoint != "" && cfg.S3BearerAuthEnabled {
		platformClient = platform.NewClient(platform.ClientConfig{
			Endpoint:     cfg.PlatformEndpoint,
			TokenURL:     cfg.S3BearerTokenURL,
			ClientID:     cfg.S3BearerClientID,
			ClientSecret: cfg.S3BearerClientSecret,
		})
		logger.Info("platform client enabled", "endpoint", cfg.PlatformEndpoint)
	}

	// Create per-user token store when both OIDC and S3 bearer auth are
	// enabled so that each user's own token is forwarded to s4proxy.
	var tokenStore *middleware.TokenStore
	if cfg.OIDCEnabled && cfg.S3BearerAuthEnabled {
		tokenStore = middleware.NewTokenStore(cfg.S3BearerTokenURL, cfg.OIDCClientID, cfg.OIDCClientSecret)
		logger.Info("per-user token flow enabled")
	}

	// Create TDF decryptor when the platform endpoint is configured and
	// fulfillable obligation FQNs are specified. This allows the WOPI
	// server to decrypt TDF files that s4proxy refused to decrypt.
	var tdfDecryptor *tdf.Decryptor
	if cfg.PlatformEndpoint != "" && cfg.S3BearerAuthEnabled && len(cfg.TDFFulfillableObligationFQNs) > 0 {
		tdfDecryptor, err = tdf.NewDecryptor(tdf.Config{
			PlatformEndpoint:       cfg.PlatformEndpoint,
			ClientID:               cfg.S3BearerClientID,
			ClientSecret:           cfg.S3BearerClientSecret,
			FulfillableObligations: cfg.TDFFulfillableObligationFQNs,
			InsecureSkipVerify:     cfg.TDFInsecureSkipVerify,
			Logger:                 logger,
		})
		if err != nil {
			logger.Error("failed to create TDF decryptor", "error", err)
			os.Exit(1)
		}
		logger.Info("TDF client-side decryption enabled",
			"platform", cfg.PlatformEndpoint,
			"fulfillable_obligations", cfg.TDFFulfillableObligationFQNs,
		)
	}

	h := &handlers.Handler{
		Storage:              s3Store,
		LockManager:          lockMgr,
		Logger:               logger,
		BaseURL:              cfg.BaseURL,
		WOPIClientURL:        cfg.WOPIClientURL,
		WOPIClientEditorPath: cfg.WOPIClientEditorPath,
		WOPISrcBaseURL:       cfg.WOPISrcBaseURL,
		TokenValidator:       tokenValidator,
		PlatformClient:       platformClient,
		AttrStore:            attrStore,
		TokenStore:           tokenStore,
		TDFDecryptor:         tdfDecryptor,
	}

	mux := http.NewServeMux()

	// Optionally set up OIDC middleware
	var oidcMw *middleware.OIDCMiddleware
	if cfg.OIDCEnabled {
		sessions, err := middleware.NewSessionManager(cfg.SessionSecret, 8*time.Hour, true)
		if err != nil {
			logger.Error("failed to create session manager", "error", err)
			os.Exit(1)
		}

		oidcMw, err = middleware.NewOIDCMiddleware(ctx, middleware.OIDCConfig{
			IssuerURL:    cfg.OIDCIssuerURL,
			ClientID:     cfg.OIDCClientID,
			ClientSecret: cfg.OIDCClientSecret,
			RedirectURL:  cfg.OIDCRedirectURL,
		}, sessions, logger, tokenStore)
		if err != nil {
			logger.Error("failed to create OIDC middleware", "error", err)
			os.Exit(1)
		}

		// Register OIDC callback and logout
		mux.HandleFunc("GET /auth/callback", oidcMw.CallbackHandler)
		mux.HandleFunc("GET /auth/logout", oidcMw.LogoutHandler)

		logger.Info("OIDC authentication enabled", "issuer", cfg.OIDCIssuerURL, "client_id", cfg.OIDCClientID)
	}

	// Browser UI routes — protected by OIDC when enabled
	if oidcMw != nil {
		mux.Handle("GET /{$}", oidcMw.Protect(http.HandlerFunc(h.ServeUI)))
		mux.Handle("GET /api/files", oidcMw.Protect(http.HandlerFunc(h.ListFiles)))
		mux.Handle("GET /api/files/browse", oidcMw.Protect(http.HandlerFunc(h.ListFilesInFolder)))
		mux.Handle("POST /api/files/upload", oidcMw.Protect(http.HandlerFunc(h.UploadFile)))
		mux.Handle("DELETE /api/files", oidcMw.Protect(http.HandlerFunc(h.DeleteFileAPI)))
		mux.Handle("GET /api/attributes", oidcMw.Protect(http.HandlerFunc(h.GetAttributes)))
		mux.Handle("GET /api/editor", oidcMw.Protect(http.HandlerFunc(h.GetEditorURL)))
		mux.Handle("GET /api/files/info", oidcMw.Protect(http.HandlerFunc(h.GetFileInfoAPI)))
		mux.Handle("GET /api/files/download", oidcMw.Protect(http.HandlerFunc(h.DownloadFile)))
	} else {
		mux.HandleFunc("GET /{$}", h.ServeUI)
		mux.HandleFunc("GET /api/files", h.ListFiles)
		mux.HandleFunc("GET /api/files/browse", h.ListFilesInFolder)
		mux.HandleFunc("POST /api/files/upload", h.UploadFile)
		mux.HandleFunc("DELETE /api/files", h.DeleteFileAPI)
		mux.HandleFunc("GET /api/attributes", h.GetAttributes)
		mux.HandleFunc("GET /api/editor", h.GetEditorURL)
		mux.HandleFunc("GET /api/files/info", h.GetFileInfoAPI)
		mux.HandleFunc("GET /api/files/download", h.DownloadFile)
	}

	// WOPI discovery endpoint (no auth required — used by integrators)
	mux.HandleFunc("GET /hosting/discovery", h.Discovery)

	// Health check (no auth required)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Token generation endpoint — disabled when OIDC is enabled.
	// Rate-limited to 10 requests per minute per IP to prevent abuse.
	if !cfg.OIDCEnabled {
		tokenRL := middleware.NewRateLimiter(10, 1*time.Minute)
		tokenHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		mux.Handle("POST /token", middleware.RateLimit(tokenRL)(tokenHandler))
	}

	// WOPI endpoints (with HMAC auth middleware — unchanged)
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
	var handler http.Handler = mux
	handler = middleware.CSRFProtect(handler)
	handler = middleware.SecureHeaders(handler)
	server := &http.Server{
		Addr:         addr,
		Handler:      handler,
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

	logger.Info("starting WOPI server", "addr", addr, "base_url", cfg.BaseURL, "wopi_client", cfg.WOPIClientURL, "oidc_enabled", cfg.OIDCEnabled)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}

	logger.Info("server stopped")
}
