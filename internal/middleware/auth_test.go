package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTokenValidator_GenerateAndValidate(t *testing.T) {
	tv := NewTokenValidator("test-secret")

	token := tv.GenerateToken("user1", "file1")
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	userID, valid := tv.ValidateToken(token, "file1")
	if !valid {
		t.Fatal("expected token to be valid")
	}
	if userID != "user1" {
		t.Fatalf("expected user ID %q, got %q", "user1", userID)
	}
}

func TestTokenValidator_WrongFile(t *testing.T) {
	tv := NewTokenValidator("test-secret")

	token := tv.GenerateToken("user1", "file1")
	_, valid := tv.ValidateToken(token, "file2")
	if valid {
		t.Fatal("expected token to be invalid for wrong file")
	}
}

func TestTokenValidator_WrongSecret(t *testing.T) {
	tv1 := NewTokenValidator("secret-1")
	tv2 := NewTokenValidator("secret-2")

	token := tv1.GenerateToken("user1", "file1")
	_, valid := tv2.ValidateToken(token, "file1")
	if valid {
		t.Fatal("expected token from different secret to be invalid")
	}
}

func TestTokenValidator_ExpiredToken(t *testing.T) {
	tv := NewTokenValidator("test-secret")

	// Create token with timestamp 11 hours ago
	expired := time.Now().Add(-11 * time.Hour).Unix()
	token := tv.GenerateTokenWithTimestamp("user1", "file1", expired)

	_, valid := tv.ValidateToken(token, "file1")
	if valid {
		t.Fatal("expected expired token to be invalid")
	}
}

func TestTokenValidator_MalformedToken(t *testing.T) {
	tv := NewTokenValidator("test-secret")

	tests := []string{
		"",
		"invalid",
		"a:b",
		"a:b:c:d",
		"notahexsig:user:12345",
	}

	for _, token := range tests {
		_, valid := tv.ValidateToken(token, "file1")
		if valid {
			t.Fatalf("expected malformed token %q to be invalid", token)
		}
	}
}

func TestExtractFileID(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/wopi/files/doc1.docx", "doc1.docx"},
		{"/wopi/files/folder|doc.xlsx", "folder|doc.xlsx"},
		{"/wopi/files/doc1.docx/contents", "doc1.docx"},
		{"/wopi/files/", ""},
		{"/wopi/files/abc/contents", "abc"},
	}

	for _, tt := range tests {
		got := extractFileID(tt.path)
		if got != tt.expected {
			t.Errorf("extractFileID(%q) = %q, want %q", tt.path, got, tt.expected)
		}
	}
}

func TestWOPIAuth_MissingToken(t *testing.T) {
	tv := NewTokenValidator("test-secret")
	handler := WOPIAuth(tv)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/wopi/files/test.docx", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestWOPIAuth_ValidToken(t *testing.T) {
	tv := NewTokenValidator("test-secret")
	token := tv.GenerateToken("user1", "test.docx")

	var gotUserID, gotFileID string
	handler := WOPIAuth(tv)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID = r.Context().Value(UserIDKey).(string)
		gotFileID = r.Context().Value(FileIDKey).(string)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/wopi/files/test.docx?access_token="+token, nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if gotUserID != "user1" {
		t.Fatalf("expected user ID %q, got %q", "user1", gotUserID)
	}
	if gotFileID != "test.docx" {
		t.Fatalf("expected file ID %q, got %q", "test.docx", gotFileID)
	}
}

func TestWOPIAuth_BearerToken(t *testing.T) {
	tv := NewTokenValidator("test-secret")
	token := tv.GenerateToken("user1", "test.docx")

	handler := WOPIAuth(tv)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/wopi/files/test.docx", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with bearer token, got %d", rec.Code)
	}
}

func TestWOPIAuth_InvalidToken(t *testing.T) {
	tv := NewTokenValidator("test-secret")
	handler := WOPIAuth(tv)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/wopi/files/test.docx?access_token=bad-token", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid token, got %d", rec.Code)
	}
}

func TestTokenValidator_Base64Encoded(t *testing.T) {
	tv := NewTokenValidator("test-secret")

	token := tv.GenerateToken("admin@example.com", "docs|report.docx")

	// Token should not contain the raw user ID.
	if strings.Contains(token, "admin@example.com") {
		t.Errorf("token should not contain plaintext user ID, got %q", token)
	}

	// Token should still validate correctly.
	userID, valid := tv.ValidateToken(token, "docs|report.docx")
	if !valid {
		t.Fatal("expected base64-encoded token to be valid")
	}
	if userID != "admin@example.com" {
		t.Fatalf("expected user ID %q, got %q", "admin@example.com", userID)
	}
}

func TestTokenValidator_RawTokenRejected(t *testing.T) {
	tv := NewTokenValidator("test-secret")

	// A raw (non-base64) token in the old format should be rejected.
	rawToken := "fakesig:user1:9999999999"
	_, valid := tv.ValidateToken(rawToken, "file1")
	if valid {
		t.Fatal("expected raw (non-base64) token to be rejected")
	}
}

func TestTokenValidator_URLSafe(t *testing.T) {
	tv := NewTokenValidator("test-secret")

	token := tv.GenerateToken("user+special/chars", "file|with|pipes")

	// Token should be URL-safe (no +, /, or = characters).
	if strings.ContainsAny(token, "+/=") {
		t.Errorf("token should be URL-safe, got %q", token)
	}

	// Should still validate.
	userID, valid := tv.ValidateToken(token, "file|with|pipes")
	if !valid {
		t.Fatal("expected URL-safe token to be valid")
	}
	if userID != "user+special/chars" {
		t.Fatalf("expected user ID %q, got %q", "user+special/chars", userID)
	}
}
