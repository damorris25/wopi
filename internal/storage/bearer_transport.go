package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// bearerTokenKeyType is the unexported type for the context key.
type bearerTokenKeyType struct{}

// BearerTokenContextKey is the context key used to inject a per-request bearer
// token. When set, BearerTokenTransport.RoundTrip uses it instead of the
// service-account token from client_credentials.
var BearerTokenContextKey = bearerTokenKeyType{}

// WithBearerToken returns a child context carrying a bearer token that
// BearerTokenTransport will use in preference to the service account token.
func WithBearerToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, BearerTokenContextKey, token)
}

// BearerTokenTransport is an http.RoundTripper that injects an OIDC bearer
// token into every outgoing request. It obtains the token using the OAuth2
// client credentials grant and caches it until close to expiry.
type BearerTokenTransport struct {
	// TokenURL is the OIDC token endpoint (e.g. Keycloak's /protocol/openid-connect/token).
	TokenURL string
	// ClientID and ClientSecret for the client credentials grant.
	ClientID     string
	ClientSecret string

	// Base is the underlying transport. If nil, http.DefaultTransport is used.
	Base http.RoundTripper

	// Logger is optional; when set, RoundTrip logs which token source is used.
	Logger *slog.Logger

	mu          sync.Mutex
	cachedToken string
	expiry      time.Time
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func (t *BearerTokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Check context for a per-request user token.
	var token string
	if userToken, ok := req.Context().Value(BearerTokenContextKey).(string); ok && userToken != "" {
		token = userToken
		if t.Logger != nil {
			t.Logger.Info("S3 request using per-user token", "method", req.Method, "url", req.URL.String())
		}
	} else {
		// Fall back to service-account token via client_credentials.
		var err error
		token, err = t.getToken()
		if err != nil {
			return nil, fmt.Errorf("obtain bearer token: %w", err)
		}
		if t.Logger != nil {
			t.Logger.Info("S3 request using service-account token", "method", req.Method, "url", req.URL.String())
		}
	}

	// Clone the request to avoid mutating the original.
	r2 := req.Clone(req.Context())
	r2.Header.Set("Authorization", "Bearer "+token)
	return t.base().RoundTrip(r2)
}

func (t *BearerTokenTransport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

func (t *BearerTokenTransport) getToken() (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Return cached token if still valid with 30-second buffer.
	if t.cachedToken != "" && time.Now().Before(t.expiry.Add(-30*time.Second)) {
		return t.cachedToken, nil
	}

	// Request a new token via client credentials grant.
	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {t.ClientID},
		"client_secret": {t.ClientSecret},
	}

	resp, err := (&http.Client{Transport: t.base()}).Post(
		t.TokenURL,
		"application/x-www-form-urlencoded",
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("parse token response: %w", err)
	}

	t.cachedToken = tr.AccessToken
	if tr.ExpiresIn > 0 {
		t.expiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	} else {
		// Default to 5 minutes if not specified.
		t.expiry = time.Now().Add(5 * time.Minute)
	}

	return t.cachedToken, nil
}
