package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type contextKey string

const (
	// UserIDKey is the context key for the authenticated user ID.
	UserIDKey contextKey = "user_id"
	// FileIDKey is the context key for the file ID extracted from the URL.
	FileIDKey contextKey = "file_id"
)

// TokenValidator validates WOPI access tokens.
type TokenValidator struct {
	secret []byte
}

// NewTokenValidator creates a new TokenValidator with the given signing secret.
func NewTokenValidator(secret string) *TokenValidator {
	return &TokenValidator{secret: []byte(secret)}
}

// GenerateToken creates an access token for a given user and file.
// Token format: hex(HMAC-SHA256(secret, userID:fileID:timestamp)):userID:timestamp
func (tv *TokenValidator) GenerateToken(userID, fileID string) string {
	timestamp := time.Now().Unix()
	return tv.GenerateTokenWithTimestamp(userID, fileID, timestamp)
}

// GenerateTokenWithTimestamp creates a token with a specific timestamp (useful for testing).
// The token is base64url-encoded to prevent user IDs from being visible in
// URL query parameters, server logs, and browser history.
func (tv *TokenValidator) GenerateTokenWithTimestamp(userID, fileID string, timestamp int64) string {
	payload := fmt.Sprintf("%s:%s:%d", userID, fileID, timestamp)
	mac := hmac.New(sha256.New, tv.secret)
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	raw := fmt.Sprintf("%s:%s:%d", sig, userID, timestamp)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// ValidateToken verifies a token and returns the user ID if valid.
func (tv *TokenValidator) ValidateToken(token, fileID string) (userID string, valid bool) {
	// Decode base64url envelope.
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", false
	}

	parts := strings.SplitN(string(raw), ":", 3)
	if len(parts) != 3 {
		return "", false
	}

	sig := parts[0]
	userID = parts[1]
	tsStr := parts[2]

	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return "", false
	}

	// Check expiry (10 hours as recommended by WOPI spec)
	if time.Since(time.Unix(ts, 0)) > 10*time.Hour {
		return "", false
	}

	payload := fmt.Sprintf("%s:%s:%d", userID, fileID, ts)
	mac := hmac.New(sha256.New, tv.secret)
	mac.Write([]byte(payload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return "", false
	}

	return userID, true
}

// TokenTTL returns the access_token_ttl value in milliseconds since epoch,
// representing the token expiration time (10 hours from now).
func TokenTTL() int64 {
	return time.Now().Add(10 * time.Hour).UnixMilli()
}

// WOPIAuth is middleware that validates WOPI access tokens.
func WOPIAuth(validator *TokenValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.URL.Query().Get("access_token")
			if token == "" {
				// Also check Authorization header
				authHeader := r.Header.Get("Authorization")
				if strings.HasPrefix(authHeader, "Bearer ") {
					token = strings.TrimPrefix(authHeader, "Bearer ")
				}
			}

			if token == "" {
				http.Error(w, "missing access token", http.StatusUnauthorized)
				return
			}

			// Extract file ID from URL path
			fileID := extractFileID(r.URL.Path)
			if fileID == "" {
				http.Error(w, "invalid file path", http.StatusBadRequest)
				return
			}

			userID, valid := validator.ValidateToken(token, fileID)
			if !valid {
				http.Error(w, "invalid access token", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), UserIDKey, userID)
			ctx = context.WithValue(ctx, FileIDKey, fileID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequestLogger logs incoming WOPI requests.
func RequestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			ww := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
			next.ServeHTTP(ww, r)

			logger.Info("wopi request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", ww.statusCode,
				"duration_ms", time.Since(start).Milliseconds(),
				"override", r.Header.Get("X-WOPI-Override"),
			)
		})
	}
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// extractFileID pulls the file_id from /wopi/files/{file_id} or
// /wopi/files/{file_id}/contents paths.
func extractFileID(path string) string {
	path = strings.TrimPrefix(path, "/wopi/files/")
	if path == "" {
		return ""
	}
	// Remove /contents suffix if present
	path = strings.TrimSuffix(path, "/contents")
	return path
}
