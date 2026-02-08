package config

import (
	"fmt"
	"os"
	"strconv"
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
	S3UseSSL          bool
	S3ForcePathStyle  bool // Required for most S3-compatible stores (MinIO, etc.)

	// WOPI settings
	AccessTokenSecret string        // Secret used to sign/verify access tokens
	LockExpiration    time.Duration // Lock TTL (default 30 minutes per WOPI spec)
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

	if cfg.S3Bucket == "" {
		return nil, fmt.Errorf("S3_BUCKET is required")
	}

	return cfg, nil
}

func getEnvOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
