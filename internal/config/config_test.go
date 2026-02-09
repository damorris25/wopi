package config

import (
	"os"
	"testing"
)

// setEnv is a helper that sets an env var for the duration of a test and
// restores the original value when the test ends.
func setEnv(t *testing.T, key, value string) {
	t.Helper()
	old, existed := os.LookupEnv(key)
	os.Setenv(key, value)
	t.Cleanup(func() {
		if existed {
			os.Setenv(key, old)
		} else {
			os.Unsetenv(key)
		}
	})
}

// clearEnv unsets an env var for the test and restores the original value.
func clearEnv(t *testing.T, key string) {
	t.Helper()
	old, existed := os.LookupEnv(key)
	os.Unsetenv(key)
	t.Cleanup(func() {
		if existed {
			os.Setenv(key, old)
		}
	})
}

func TestLoadFromEnv_Defaults(t *testing.T) {
	// Clear vars that would override defaults.
	for _, k := range []string{
		"WOPI_PORT", "S3_USE_SSL", "S3_FORCE_PATH_STYLE",
		"S3_BEARER_AUTH_ENABLED", "OIDC_ENABLED",
		"TDF_FULFILLABLE_OBLIGATION_FQNS",
	} {
		clearEnv(t, k)
	}

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Port != 8080 {
		t.Errorf("expected default port 8080, got %d", cfg.Port)
	}
	if !cfg.S3UseSSL {
		t.Error("expected S3UseSSL default true")
	}
	if !cfg.S3ForcePathStyle {
		t.Error("expected S3ForcePathStyle default true")
	}
	if cfg.S3BearerAuthEnabled {
		t.Error("expected S3BearerAuthEnabled default false")
	}
	if cfg.OIDCEnabled {
		t.Error("expected OIDCEnabled default false")
	}
	if len(cfg.TDFFulfillableObligationFQNs) != 0 {
		t.Errorf("expected empty TDFFulfillableObligationFQNs, got %v", cfg.TDFFulfillableObligationFQNs)
	}
}

func TestLoadFromEnv_CustomPort(t *testing.T) {
	setEnv(t, "WOPI_PORT", "9090")
	clearEnv(t, "S3_BEARER_AUTH_ENABLED")
	clearEnv(t, "OIDC_ENABLED")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Port != 9090 {
		t.Errorf("expected port 9090, got %d", cfg.Port)
	}
}

func TestLoadFromEnv_InvalidPort(t *testing.T) {
	setEnv(t, "WOPI_PORT", "notanumber")

	_, err := LoadFromEnv()
	if err == nil {
		t.Fatal("expected error for invalid port")
	}
}

func TestLoadFromEnv_InvalidBool(t *testing.T) {
	setEnv(t, "S3_USE_SSL", "notabool")

	_, err := LoadFromEnv()
	if err == nil {
		t.Fatal("expected error for invalid S3_USE_SSL")
	}
}

func TestLoadFromEnv_S3BearerAuth_MissingTokenURL(t *testing.T) {
	setEnv(t, "S3_BEARER_AUTH_ENABLED", "true")
	setEnv(t, "S3_BEARER_TOKEN_URL", "")
	setEnv(t, "S3_BEARER_CLIENT_ID", "client")
	setEnv(t, "S3_BEARER_CLIENT_SECRET", "secret")
	clearEnv(t, "OIDC_ENABLED")

	_, err := LoadFromEnv()
	if err == nil {
		t.Fatal("expected error for missing S3_BEARER_TOKEN_URL")
	}
}

func TestLoadFromEnv_S3BearerAuth_MissingClientID(t *testing.T) {
	setEnv(t, "S3_BEARER_AUTH_ENABLED", "true")
	setEnv(t, "S3_BEARER_TOKEN_URL", "https://example.com/token")
	clearEnv(t, "S3_BEARER_CLIENT_ID")
	setEnv(t, "S3_BEARER_CLIENT_SECRET", "secret")
	clearEnv(t, "OIDC_ENABLED")

	_, err := LoadFromEnv()
	if err == nil {
		t.Fatal("expected error for missing S3_BEARER_CLIENT_ID")
	}
}

func TestLoadFromEnv_S3BearerAuth_MissingClientSecret(t *testing.T) {
	setEnv(t, "S3_BEARER_AUTH_ENABLED", "true")
	setEnv(t, "S3_BEARER_TOKEN_URL", "https://example.com/token")
	setEnv(t, "S3_BEARER_CLIENT_ID", "client")
	clearEnv(t, "S3_BEARER_CLIENT_SECRET")
	clearEnv(t, "OIDC_ENABLED")

	_, err := LoadFromEnv()
	if err == nil {
		t.Fatal("expected error for missing S3_BEARER_CLIENT_SECRET")
	}
}

func TestLoadFromEnv_OIDC_MissingIssuerURL(t *testing.T) {
	clearEnv(t, "S3_BEARER_AUTH_ENABLED")
	setEnv(t, "OIDC_ENABLED", "true")
	clearEnv(t, "OIDC_ISSUER_URL")
	setEnv(t, "OIDC_CLIENT_ID", "client")
	setEnv(t, "OIDC_CLIENT_SECRET", "secret")
	setEnv(t, "OIDC_REDIRECT_URL", "https://example.com/callback")
	setEnv(t, "SESSION_SECRET", "secret")

	_, err := LoadFromEnv()
	if err == nil {
		t.Fatal("expected error for missing OIDC_ISSUER_URL")
	}
}

func TestLoadFromEnv_OIDC_MissingSessionSecret(t *testing.T) {
	clearEnv(t, "S3_BEARER_AUTH_ENABLED")
	setEnv(t, "OIDC_ENABLED", "true")
	setEnv(t, "OIDC_ISSUER_URL", "https://example.com")
	setEnv(t, "OIDC_CLIENT_ID", "client")
	setEnv(t, "OIDC_CLIENT_SECRET", "secret")
	setEnv(t, "OIDC_REDIRECT_URL", "https://example.com/callback")
	clearEnv(t, "SESSION_SECRET")

	_, err := LoadFromEnv()
	if err == nil {
		t.Fatal("expected error for missing SESSION_SECRET")
	}
}

func TestLoadFromEnv_TDFFulfillableObligationFQNs(t *testing.T) {
	setEnv(t, "TDF_FULFILLABLE_OBLIGATION_FQNS",
		"https://example.com/obl/no-download,https://example.com/obl/no-copy,https://example.com/obl/no-print")
	clearEnv(t, "S3_BEARER_AUTH_ENABLED")
	clearEnv(t, "OIDC_ENABLED")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.TDFFulfillableObligationFQNs) != 3 {
		t.Fatalf("expected 3 FQNs, got %d: %v", len(cfg.TDFFulfillableObligationFQNs), cfg.TDFFulfillableObligationFQNs)
	}
	expected := []string{
		"https://example.com/obl/no-download",
		"https://example.com/obl/no-copy",
		"https://example.com/obl/no-print",
	}
	for i, want := range expected {
		if cfg.TDFFulfillableObligationFQNs[i] != want {
			t.Errorf("FQN[%d] = %q, want %q", i, cfg.TDFFulfillableObligationFQNs[i], want)
		}
	}
}

func TestLoadFromEnv_TDFFulfillableObligationFQNs_Whitespace(t *testing.T) {
	setEnv(t, "TDF_FULFILLABLE_OBLIGATION_FQNS", "  https://a , https://b , ")
	clearEnv(t, "S3_BEARER_AUTH_ENABLED")
	clearEnv(t, "OIDC_ENABLED")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.TDFFulfillableObligationFQNs) != 2 {
		t.Fatalf("expected 2 FQNs (trimmed empties), got %d: %v", len(cfg.TDFFulfillableObligationFQNs), cfg.TDFFulfillableObligationFQNs)
	}
	if cfg.TDFFulfillableObligationFQNs[0] != "https://a" {
		t.Errorf("FQN[0] = %q, want %q", cfg.TDFFulfillableObligationFQNs[0], "https://a")
	}
	if cfg.TDFFulfillableObligationFQNs[1] != "https://b" {
		t.Errorf("FQN[1] = %q, want %q", cfg.TDFFulfillableObligationFQNs[1], "https://b")
	}
}

func TestLoadFromEnv_TDFFulfillableObligationFQNs_Empty(t *testing.T) {
	clearEnv(t, "TDF_FULFILLABLE_OBLIGATION_FQNS")
	clearEnv(t, "S3_BEARER_AUTH_ENABLED")
	clearEnv(t, "OIDC_ENABLED")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.TDFFulfillableObligationFQNs) != 0 {
		t.Errorf("expected 0 FQNs when unset, got %d", len(cfg.TDFFulfillableObligationFQNs))
	}
}

func TestLoadFromEnv_PlatformEndpoint(t *testing.T) {
	setEnv(t, "PLATFORM_ENDPOINT", "https://platform.example.com")
	clearEnv(t, "S3_BEARER_AUTH_ENABLED")
	clearEnv(t, "OIDC_ENABLED")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PlatformEndpoint != "https://platform.example.com" {
		t.Errorf("PlatformEndpoint = %q, want %q", cfg.PlatformEndpoint, "https://platform.example.com")
	}
}

func TestLoadFromEnv_WOPISrcBaseURL(t *testing.T) {
	setEnv(t, "WOPI_SRC_BASE_URL", "http://internal:8080")
	clearEnv(t, "S3_BEARER_AUTH_ENABLED")
	clearEnv(t, "OIDC_ENABLED")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.WOPISrcBaseURL != "http://internal:8080" {
		t.Errorf("WOPISrcBaseURL = %q, want %q", cfg.WOPISrcBaseURL, "http://internal:8080")
	}
}

func TestLoadFromEnv_S3BoolOverrides(t *testing.T) {
	setEnv(t, "S3_USE_SSL", "false")
	setEnv(t, "S3_FORCE_PATH_STYLE", "false")
	clearEnv(t, "S3_BEARER_AUTH_ENABLED")
	clearEnv(t, "OIDC_ENABLED")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.S3UseSSL {
		t.Error("expected S3UseSSL false")
	}
	if cfg.S3ForcePathStyle {
		t.Error("expected S3ForcePathStyle false")
	}
}
