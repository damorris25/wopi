package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all configuration for the WOPI server.
type Config struct {
	// Server settings
	Port    int
	BaseURL string // External URL used to construct WOPISrc values

	// S3-compatible storage settings
	S3Endpoint        string
	S3Region          string
	S3Bucket          string
	S3AccessKeyID     string
	S3SecretAccessKey string
	S3UseSSL         bool
	S3ForcePathStyle bool // Required for most S3-compatible stores (MinIO, etc.)

	// S3 proxy bearer auth — when set, the WOPI server authenticates to
	// the S3 endpoint using OIDC bearer tokens instead of static credentials.
	S3BearerAuthEnabled bool
	S3BearerTokenURL    string // OIDC token endpoint for client credentials grant
	S3BearerClientID    string
	S3BearerClientSecret string

	// WOPI settings
	AccessTokenSecret string        // Secret used to sign/verify access tokens
	LockExpiration    time.Duration // Lock TTL (default 30 minutes per WOPI spec)

	// WOPI client (editor) settings
	WOPIClientURL        string // Base URL of the WOPI client (e.g., http://localhost:9980)
	WOPIClientEditorPath string // Path appended to base URL (default: /browser/dist/cool.html)
	WOPISrcBaseURL       string // Base URL used in WOPISrc for Collabora callbacks (defaults to BaseURL)

	// OIDC settings (enabled when OIDC_ENABLED=true)
	OIDCEnabled      bool
	OIDCIssuerURL    string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string

	// Session settings
	SessionSecret string

	// OpenTDF Platform endpoint (for attribute entitlements)
	PlatformEndpoint string

	// TDF fulfillable obligation FQNs — when set (along with PlatformEndpoint
	// and S3BearerAuth), the WOPI server decrypts TDF files client-side using
	// the OpenTDF SDK, declaring these obligations as fulfillable.
	TDFFulfillableObligationFQNs []string

	// TDFInsecureSkipVerify disables TLS certificate verification for the
	// OpenTDF SDK connection. For development with self-signed certs only.
	TDFInsecureSkipVerify bool
}

// LoadFromEnv loads configuration from environment variables.
func LoadFromEnv() (*Config, error) {
	port := 8080
	if v := os.Getenv("WOPI_PORT"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid WOPI_PORT: %w", err)
		}
		port = p
	}

	useSSL := true
	if v := os.Getenv("S3_USE_SSL"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("invalid S3_USE_SSL: %w", err)
		}
		useSSL = b
	}

	forcePathStyle := true
	if v := os.Getenv("S3_FORCE_PATH_STYLE"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("invalid S3_FORCE_PATH_STYLE: %w", err)
		}
		forcePathStyle = b
	}

	cfg := &Config{
		Port:              port,
		BaseURL:           getEnvOrDefault("WOPI_BASE_URL", fmt.Sprintf("http://localhost:%d", port)),
		S3Endpoint:        getEnvOrDefault("S3_ENDPOINT", "http://localhost:9000"),
		S3Region:          getEnvOrDefault("S3_REGION", "us-east-1"),
		S3Bucket:          getEnvOrDefault("S3_BUCKET", "wopi-documents"),
		S3AccessKeyID:     getEnvOrDefault("S3_ACCESS_KEY_ID", "minioadmin"),
		S3SecretAccessKey: getEnvOrDefault("S3_SECRET_ACCESS_KEY", "minioadmin"),
		S3UseSSL:          useSSL,
		S3ForcePathStyle:  forcePathStyle,
		AccessTokenSecret: getEnvOrDefault("WOPI_ACCESS_TOKEN_SECRET", "change-me-in-production"),
		LockExpiration:    30 * time.Minute,
	}

	clientURL := getEnvOrDefault("WOPI_CLIENT_URL", "")
	if clientURL == "" {
		clientURL = getEnvOrDefault("COLLABORA_URL", "http://localhost:9980")
	}
	cfg.WOPIClientURL = clientURL
	cfg.WOPIClientEditorPath = getEnvOrDefault("WOPI_CLIENT_EDITOR_PATH", "/browser/dist/cool.html")
	cfg.WOPISrcBaseURL = getEnvOrDefault("WOPI_SRC_BASE_URL", "")

	if cfg.S3Bucket == "" {
		return nil, fmt.Errorf("S3_BUCKET is required")
	}

	// S3 bearer auth settings
	s3BearerAuth := false
	if v := os.Getenv("S3_BEARER_AUTH_ENABLED"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("invalid S3_BEARER_AUTH_ENABLED: %w", err)
		}
		s3BearerAuth = b
	}
	cfg.S3BearerAuthEnabled = s3BearerAuth
	cfg.S3BearerTokenURL = getEnvOrDefault("S3_BEARER_TOKEN_URL", "")
	cfg.S3BearerClientID = getEnvOrDefault("S3_BEARER_CLIENT_ID", "")
	cfg.S3BearerClientSecret = getEnvOrDefault("S3_BEARER_CLIENT_SECRET", "")

	if cfg.S3BearerAuthEnabled {
		if cfg.S3BearerTokenURL == "" {
			return nil, fmt.Errorf("S3_BEARER_TOKEN_URL is required when S3 bearer auth is enabled")
		}
		if cfg.S3BearerClientID == "" {
			return nil, fmt.Errorf("S3_BEARER_CLIENT_ID is required when S3 bearer auth is enabled")
		}
		if cfg.S3BearerClientSecret == "" {
			return nil, fmt.Errorf("S3_BEARER_CLIENT_SECRET is required when S3 bearer auth is enabled")
		}
	}

	// OIDC settings
	oidcEnabled := false
	if v := os.Getenv("OIDC_ENABLED"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("invalid OIDC_ENABLED: %w", err)
		}
		oidcEnabled = b
	}
	cfg.OIDCEnabled = oidcEnabled
	cfg.OIDCIssuerURL = getEnvOrDefault("OIDC_ISSUER_URL", "")
	cfg.OIDCClientID = getEnvOrDefault("OIDC_CLIENT_ID", "")
	cfg.OIDCClientSecret = getEnvOrDefault("OIDC_CLIENT_SECRET", "")
	cfg.OIDCRedirectURL = getEnvOrDefault("OIDC_REDIRECT_URL", "")
	cfg.SessionSecret = getEnvOrDefault("SESSION_SECRET", "")

	cfg.PlatformEndpoint = getEnvOrDefault("PLATFORM_ENDPOINT", "")

	if v := os.Getenv("TDF_INSECURE_SKIP_VERIFY"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("invalid TDF_INSECURE_SKIP_VERIFY: %w", err)
		}
		cfg.TDFInsecureSkipVerify = b
	}

	if v := os.Getenv("TDF_FULFILLABLE_OBLIGATION_FQNS"); v != "" {
		for _, fqn := range strings.Split(v, ",") {
			if fqn = strings.TrimSpace(fqn); fqn != "" {
				cfg.TDFFulfillableObligationFQNs = append(cfg.TDFFulfillableObligationFQNs, fqn)
			}
		}
	}

	if cfg.OIDCEnabled {
		if cfg.OIDCIssuerURL == "" {
			return nil, fmt.Errorf("OIDC_ISSUER_URL is required when OIDC is enabled")
		}
		if cfg.OIDCClientID == "" {
			return nil, fmt.Errorf("OIDC_CLIENT_ID is required when OIDC is enabled")
		}
		if cfg.OIDCClientSecret == "" {
			return nil, fmt.Errorf("OIDC_CLIENT_SECRET is required when OIDC is enabled")
		}
		if cfg.OIDCRedirectURL == "" {
			return nil, fmt.Errorf("OIDC_REDIRECT_URL is required when OIDC is enabled")
		}
		if cfg.SessionSecret == "" {
			return nil, fmt.Errorf("SESSION_SECRET is required when OIDC is enabled")
		}
	}

	return cfg, nil
}

func getEnvOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
