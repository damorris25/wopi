package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// UserToken holds a user's OAuth2 tokens.
type UserToken struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// TokenStore is an in-memory concurrent-safe store for per-user OAuth2 tokens
// with transparent refresh via Keycloak's refresh_token grant.
type TokenStore struct {
	mu           sync.RWMutex
	tokens       map[string]*UserToken
	tokenURL     string // Keycloak token endpoint
	clientID     string
	clientSecret string
}

// NewTokenStore creates a TokenStore that can refresh expired tokens against
// the given OIDC token endpoint.
func NewTokenStore(tokenURL, clientID, clientSecret string) *TokenStore {
	return &TokenStore{
		tokens:       make(map[string]*UserToken),
		tokenURL:     tokenURL,
		clientID:     clientID,
		clientSecret: clientSecret,
	}
}

// Store saves a user's tokens under the given key.
func (ts *TokenStore) Store(key string, token *UserToken) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.tokens[key] = token
}

// GetToken returns a valid access token for key. If the token is expired it
// attempts a refresh via the refresh_token grant. Returns ("", false) when
// there is no entry or refresh fails.
func (ts *TokenStore) GetToken(ctx context.Context, key string) (string, bool) {
	ts.mu.RLock()
	tok, ok := ts.tokens[key]
	if !ok {
		ts.mu.RUnlock()
		return "", false
	}
	// Copy values under read lock so we can release it.
	accessToken := tok.AccessToken
	refreshToken := tok.RefreshToken
	expiresAt := tok.ExpiresAt
	ts.mu.RUnlock()

	// Still valid (with 30-second buffer).
	if time.Now().Before(expiresAt.Add(-30 * time.Second)) {
		return accessToken, true
	}

	// Attempt refresh.
	newTok, err := ts.refresh(ctx, refreshToken)
	if err != nil {
		return "", false
	}

	ts.mu.Lock()
	ts.tokens[key] = newTok
	ts.mu.Unlock()

	return newTok.AccessToken, true
}

// Delete removes a token entry.
func (ts *TokenStore) Delete(key string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	delete(ts.tokens, key)
}

// GetEntry returns a copy of the stored UserToken for key, or nil if not found.
// Unlike GetToken, it does not attempt refresh.
func (ts *TokenStore) GetEntry(key string) *UserToken {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	tok, ok := ts.tokens[key]
	if !ok {
		return nil
	}
	// Return a copy.
	cp := *tok
	return &cp
}

// TokenStoreKey builds a composite key for WOPI sessions: "userID:fileID".
func TokenStoreKey(userID, fileID string) string {
	return userID + ":" + fileID
}

type refreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

func (ts *TokenStore) refresh(ctx context.Context, refreshToken string) (*UserToken, error) {
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {ts.clientID},
		"client_secret": {ts.clientSecret},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("refresh request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read refresh response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("refresh endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var rr refreshResponse
	if err := json.Unmarshal(body, &rr); err != nil {
		return nil, fmt.Errorf("parse refresh response: %w", err)
	}

	expiresIn := time.Duration(rr.ExpiresIn) * time.Second
	if expiresIn == 0 {
		expiresIn = 5 * time.Minute
	}

	return &UserToken{
		AccessToken:  rr.AccessToken,
		RefreshToken: rr.RefreshToken,
		ExpiresAt:    time.Now().Add(expiresIn),
	}, nil
}
