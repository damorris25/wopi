package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// mockOIDCDiscovery returns a test HTTP server that serves OIDC discovery
// responses.
func mockOIDCDiscovery(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/auth",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/jwks",
			"userinfo_endpoint":      srv.URL + "/userinfo",
		})
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"keys":[]}`))
	})

	srv = httptest.NewServer(mux)
	return srv
}

func newTestOIDCMiddleware(t *testing.T, issuerURL string) (*OIDCMiddleware, *SessionManager) {
	t.Helper()

	sm, err := NewSessionManager("test-secret-for-oidc-tests!!", 1*time.Hour, false)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}

	om, err := NewOIDCMiddleware(context.Background(), OIDCConfig{
		IssuerURL:    issuerURL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  "http://localhost/auth/callback",
	}, sm, nil)
	if err != nil {
		t.Fatalf("NewOIDCMiddleware: %v", err)
	}

	return om, sm
}

func TestProtect_APIWithoutSession_Returns401(t *testing.T) {
	srv := mockOIDCDiscovery(t)
	defer srv.Close()

	om, _ := newTestOIDCMiddleware(t, srv.URL)

	handler := om.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/files", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}

	var body map[string]string
	json.NewDecoder(w.Body).Decode(&body)
	if body["error"] != "authentication required" {
		t.Errorf("error = %q, want %q", body["error"], "authentication required")
	}
}

func TestProtect_BrowserWithoutSession_Redirects(t *testing.T) {
	srv := mockOIDCDiscovery(t)
	defer srv.Close()

	om, _ := newTestOIDCMiddleware(t, srv.URL)

	handler := om.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusFound)
	}

	loc := w.Header().Get("Location")
	if loc == "" {
		t.Fatal("expected Location header for redirect")
	}

	// Should have set a state cookie
	cookies := w.Result().Cookies()
	foundState := false
	for _, c := range cookies {
		if c.Name == oidcStateCookieName {
			foundState = true
			break
		}
	}
	if !foundState {
		t.Error("expected state cookie to be set")
	}
}

func TestProtect_WithValidSession_PassesThrough(t *testing.T) {
	srv := mockOIDCDiscovery(t)
	defer srv.Close()

	om, sm := newTestOIDCMiddleware(t, srv.URL)

	var gotUserID, gotEmail, gotName string
	handler := om.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID, _ = r.Context().Value(OIDCUserIDKey).(string)
		gotEmail, _ = r.Context().Value(OIDCEmailKey).(string)
		gotName, _ = r.Context().Value(OIDCNameKey).(string)
		w.WriteHeader(http.StatusOK)
	}))

	// Create a session cookie
	sessW := httptest.NewRecorder()
	sm.SetSession(sessW, &SessionData{
		UserID:      "sub-123",
		Email:       "test@example.com",
		DisplayName: "Test User",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	})

	req := httptest.NewRequest("GET", "/", nil)
	for _, c := range sessW.Result().Cookies() {
		req.AddCookie(c)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if gotUserID != "sub-123" {
		t.Errorf("UserID = %q, want %q", gotUserID, "sub-123")
	}
	if gotEmail != "test@example.com" {
		t.Errorf("Email = %q, want %q", gotEmail, "test@example.com")
	}
	if gotName != "Test User" {
		t.Errorf("Name = %q, want %q", gotName, "Test User")
	}
}

func TestCallback_InvalidState_Returns400(t *testing.T) {
	srv := mockOIDCDiscovery(t)
	defer srv.Close()

	om, _ := newTestOIDCMiddleware(t, srv.URL)

	req := httptest.NewRequest("GET", "/auth/callback?state=bad&code=test", nil)
	req.AddCookie(&http.Cookie{Name: oidcStateCookieName, Value: "good"})

	w := httptest.NewRecorder()
	om.CallbackHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestCallback_MissingCode_Returns400(t *testing.T) {
	srv := mockOIDCDiscovery(t)
	defer srv.Close()

	om, _ := newTestOIDCMiddleware(t, srv.URL)

	req := httptest.NewRequest("GET", "/auth/callback?state=valid", nil)
	req.AddCookie(&http.Cookie{Name: oidcStateCookieName, Value: "valid"})

	w := httptest.NewRecorder()
	om.CallbackHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestCallback_MissingStateCookie_Returns400(t *testing.T) {
	srv := mockOIDCDiscovery(t)
	defer srv.Close()

	om, _ := newTestOIDCMiddleware(t, srv.URL)

	req := httptest.NewRequest("GET", "/auth/callback?state=test&code=test", nil)
	w := httptest.NewRecorder()
	om.CallbackHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestContextValues_SetCorrectly(t *testing.T) {
	srv := mockOIDCDiscovery(t)
	defer srv.Close()

	om, sm := newTestOIDCMiddleware(t, srv.URL)

	results := make(map[string]string)
	handler := om.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v, ok := r.Context().Value(OIDCUserIDKey).(string); ok {
			results["user_id"] = v
		}
		if v, ok := r.Context().Value(OIDCEmailKey).(string); ok {
			results["email"] = v
		}
		if v, ok := r.Context().Value(OIDCNameKey).(string); ok {
			results["name"] = v
		}
		w.WriteHeader(http.StatusOK)
	}))

	sessW := httptest.NewRecorder()
	sm.SetSession(sessW, &SessionData{
		UserID:      "uid-456",
		Email:       "alice@example.com",
		DisplayName: "Alice",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	})

	req := httptest.NewRequest("GET", "/api/files", nil)
	for _, c := range sessW.Result().Cookies() {
		req.AddCookie(c)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	expected := map[string]string{
		"user_id": "uid-456",
		"email":   "alice@example.com",
		"name":    "Alice",
	}

	for k, want := range expected {
		if got := results[k]; got != want {
			t.Errorf("context[%s] = %q, want %q", k, got, want)
		}
	}
}

func TestNewOIDCMiddleware_BadIssuer(t *testing.T) {
	sm, _ := NewSessionManager("secret", 1*time.Hour, false)
	_, err := NewOIDCMiddleware(context.Background(), OIDCConfig{
		IssuerURL:    "http://127.0.0.1:1/nonexistent",
		ClientID:     "test",
		ClientSecret: "test",
		RedirectURL:  "http://localhost/callback",
	}, sm, nil)
	if err == nil {
		t.Fatal("expected error for bad issuer URL")
	}
	fmt.Printf("got expected error: %v\n", err)
}
