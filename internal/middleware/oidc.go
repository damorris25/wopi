package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCContextKey is the type for OIDC-related context keys.
type OIDCContextKey string

const (
	// OIDCUserIDKey is the context key for the OIDC user's subject ID.
	OIDCUserIDKey OIDCContextKey = "oidc_user_id"
	// OIDCEmailKey is the context key for the OIDC user's email.
	OIDCEmailKey OIDCContextKey = "oidc_email"
	// OIDCNameKey is the context key for the OIDC user's display name.
	OIDCNameKey OIDCContextKey = "oidc_name"
	// OIDCAccessTokenKey is the context key for the user's OAuth2 access token.
	OIDCAccessTokenKey OIDCContextKey = "oidc_access_token"

	oidcStateCookieName = "oidc_state"
)

// OIDCConfig holds OIDC provider configuration.
type OIDCConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

// OIDCMiddleware handles OIDC authentication for browser-facing routes.
type OIDCMiddleware struct {
	provider   *oidc.Provider
	verifier   *oidc.IDTokenVerifier
	oauth2Cfg  oauth2.Config
	sessions   *SessionManager
	logger     *slog.Logger
	tokenStore *TokenStore
}

// NewOIDCMiddleware initialises the OIDC provider by performing discovery
// against the issuer URL. tokenStore is optional; when non-nil, user tokens
// are captured at login and injected into request context.
func NewOIDCMiddleware(ctx context.Context, cfg OIDCConfig, sessions *SessionManager, logger *slog.Logger, tokenStore ...*TokenStore) (*OIDCMiddleware, error) {
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})

	oauth2Cfg := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile", "offline_access"},
	}

	var ts *TokenStore
	if len(tokenStore) > 0 {
		ts = tokenStore[0]
	}

	return &OIDCMiddleware{
		provider:   provider,
		verifier:   verifier,
		oauth2Cfg:  oauth2Cfg,
		sessions:   sessions,
		logger:     logger,
		tokenStore: ts,
	}, nil
}

// Protect returns middleware that requires a valid session. If there is no
// session, API requests receive a 401 and browser requests are redirected to
// the identity provider.
func (om *OIDCMiddleware) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := om.sessions.GetSession(r)
		if err == nil {
			// Valid session — populate context and continue.
			ctx := context.WithValue(r.Context(), OIDCUserIDKey, sess.UserID)
			ctx = context.WithValue(ctx, OIDCEmailKey, sess.Email)
			ctx = context.WithValue(ctx, OIDCNameKey, sess.DisplayName)
			if om.tokenStore != nil {
				if token, ok := om.tokenStore.GetToken(r.Context(), sess.UserID); ok {
					ctx = context.WithValue(ctx, OIDCAccessTokenKey, token)
				} else {
					// Token store is configured but has no entry for this user
					// (e.g. server was restarted). Clear the stale session so
					// the user re-authenticates and we capture fresh tokens.
					if om.logger != nil {
						om.logger.Info("no token in store for user, forcing re-login", "user_id", sess.UserID)
					}
					om.sessions.ClearSession(w)
					err = fmt.Errorf("token store miss")
					// Fall through to the "no valid session" handling below.
				}
			}
			if err == nil {
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		// No valid session.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "authentication required"})
			return
		}

		// Browser request — redirect to IdP.
		state, err := randomState()
		if err != nil {
			om.logger.Error("failed to generate OIDC state", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     oidcStateCookieName,
			Value:    state,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   300, // 5 minutes
		})

		http.Redirect(w, r, om.oauth2Cfg.AuthCodeURL(state), http.StatusFound)
	})
}

// CallbackHandler handles the OAuth2 authorization code callback.
func (om *OIDCMiddleware) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	// Validate state
	stateCookie, err := r.Cookie(oidcStateCookieName)
	if err != nil {
		http.Error(w, "missing state cookie", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("state") != stateCookie.Value {
		http.Error(w, "invalid state parameter", http.StatusBadRequest)
		return
	}

	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	// Exchange code for tokens
	oauth2Token, err := om.oauth2Cfg.Exchange(r.Context(), code)
	if err != nil {
		om.logger.Error("token exchange failed", "error", err)
		http.Error(w, "token exchange failed", http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in response", http.StatusInternalServerError)
		return
	}

	idToken, err := om.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		om.logger.Error("ID token verification failed", "error", err)
		http.Error(w, "invalid id_token", http.StatusInternalServerError)
		return
	}

	// Extract claims
	var claims struct {
		Sub               string `json:"sub"`
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
		Name              string `json:"name"`
	}
	if err := idToken.Claims(&claims); err != nil {
		om.logger.Error("failed to parse claims", "error", err)
		http.Error(w, "failed to parse claims", http.StatusInternalServerError)
		return
	}

	displayName := claims.Name
	if displayName == "" {
		displayName = claims.PreferredUsername
	}

	sess := &SessionData{
		UserID:      claims.Sub,
		Email:       claims.Email,
		DisplayName: displayName,
		ExpiresAt:   time.Now().Add(8 * time.Hour),
	}

	if err := om.sessions.SetSession(w, sess); err != nil {
		om.logger.Error("failed to set session", "error", err)
		http.Error(w, "failed to create session", http.StatusInternalServerError)
		return
	}

	// Stash user's OAuth2 tokens for per-user S3 authorization.
	if om.tokenStore != nil {
		om.tokenStore.Store(claims.Sub, &UserToken{
			AccessToken:  oauth2Token.AccessToken,
			RefreshToken: oauth2Token.RefreshToken,
			ExpiresAt:    oauth2Token.Expiry,
		})
		if om.logger != nil {
			om.logger.Info("stored user token",
				"user_id", claims.Sub,
				"has_refresh", oauth2Token.RefreshToken != "",
				"expires_at", oauth2Token.Expiry)
		}
	}

	om.logger.Info("OIDC login successful", "user_id", claims.Sub, "email", claims.Email)
	http.Redirect(w, r, "/", http.StatusFound)
}

// LogoutHandler clears the local session and token store entry, then redirects
// the user to the OIDC provider's end-session endpoint so the IdP session is
// also terminated. This forces a fresh login on the next visit.
func (om *OIDCMiddleware) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Read user ID before clearing the session so we can remove stored tokens.
	var userID string
	if sess, err := om.sessions.GetSession(r); err == nil {
		userID = sess.UserID
	}

	om.sessions.ClearSession(w)

	if userID != "" && om.tokenStore != nil {
		om.tokenStore.Delete(userID)
	}

	// Discover the end-session endpoint from the provider metadata.
	var providerClaims struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := om.provider.Claims(&providerClaims); err == nil && providerClaims.EndSessionEndpoint != "" {
		// Redirect to IdP logout with a post-logout redirect back to our app.
		redirectURL := providerClaims.EndSessionEndpoint +
			"?client_id=" + om.oauth2Cfg.ClientID +
			"&post_logout_redirect_uri=" + url.QueryEscape(om.oauth2Cfg.RedirectURL[:strings.LastIndex(om.oauth2Cfg.RedirectURL, "/")+1])
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	// Fallback: just redirect to home (will trigger re-login via Protect).
	http.Redirect(w, r, "/", http.StatusFound)
}

func randomState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
