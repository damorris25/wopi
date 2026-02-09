package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionRoundTrip(t *testing.T) {
	sm, err := NewSessionManager("test-secret-32-bytes-long!!", 1*time.Hour, false)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}

	original := &SessionData{
		UserID:      "user-123",
		Email:       "user@example.com",
		DisplayName: "Test User",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}

	// Set session
	w := httptest.NewRecorder()
	if err := sm.SetSession(w, original); err != nil {
		t.Fatalf("SetSession: %v", err)
	}

	// Read session back
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no cookie set")
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookies[0])

	got, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}

	if got.UserID != original.UserID {
		t.Errorf("UserID = %q, want %q", got.UserID, original.UserID)
	}
	if got.Email != original.Email {
		t.Errorf("Email = %q, want %q", got.Email, original.Email)
	}
	if got.DisplayName != original.DisplayName {
		t.Errorf("DisplayName = %q, want %q", got.DisplayName, original.DisplayName)
	}
}

func TestSessionExpired(t *testing.T) {
	sm, err := NewSessionManager("test-secret", 1*time.Hour, false)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}

	expired := &SessionData{
		UserID:    "user-123",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}

	w := httptest.NewRecorder()
	if err := sm.SetSession(w, expired); err != nil {
		t.Fatalf("SetSession: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(w.Result().Cookies()[0])

	_, err = sm.GetSession(req)
	if err == nil {
		t.Fatal("expected error for expired session, got nil")
	}
}

func TestSessionTampered(t *testing.T) {
	sm, err := NewSessionManager("test-secret", 1*time.Hour, false)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}

	data := &SessionData{
		UserID:    "user-123",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	w := httptest.NewRecorder()
	if err := sm.SetSession(w, data); err != nil {
		t.Fatalf("SetSession: %v", err)
	}

	cookie := w.Result().Cookies()[0]
	// Tamper with the cookie value
	cookie.Value = cookie.Value[:len(cookie.Value)-4] + "XXXX"

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookie)

	_, err = sm.GetSession(req)
	if err == nil {
		t.Fatal("expected error for tampered cookie, got nil")
	}
}

func TestSessionMissingCookie(t *testing.T) {
	sm, err := NewSessionManager("test-secret", 1*time.Hour, false)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	_, err = sm.GetSession(req)
	if err == nil {
		t.Fatal("expected error for missing cookie, got nil")
	}
}

func TestSessionCookieProperties(t *testing.T) {
	sm, err := NewSessionManager("test-secret", 2*time.Hour, true)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}

	data := &SessionData{
		UserID:    "user-123",
		ExpiresAt: time.Now().Add(2 * time.Hour),
	}

	w := httptest.NewRecorder()
	if err := sm.SetSession(w, data); err != nil {
		t.Fatalf("SetSession: %v", err)
	}

	cookie := w.Result().Cookies()[0]
	if cookie.Name != "wopi_session" {
		t.Errorf("cookie name = %q, want %q", cookie.Name, "wopi_session")
	}
	if !cookie.HttpOnly {
		t.Error("expected HttpOnly cookie")
	}
	if !cookie.Secure {
		t.Error("expected Secure cookie")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", cookie.SameSite)
	}
}

func TestClearSession(t *testing.T) {
	sm, err := NewSessionManager("test-secret", 1*time.Hour, false)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}

	w := httptest.NewRecorder()
	sm.ClearSession(w)

	cookie := w.Result().Cookies()[0]
	if cookie.MaxAge != -1 {
		t.Errorf("MaxAge = %d, want -1", cookie.MaxAge)
	}
}

func TestNewSessionManagerEmptySecret(t *testing.T) {
	_, err := NewSessionManager("", 1*time.Hour, false)
	if err == nil {
		t.Fatal("expected error for empty secret, got nil")
	}
}
