package middleware

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const sessionCookieName = "wopi_session"

// SessionData holds the authenticated user's session information.
type SessionData struct {
	UserID      string    `json:"user_id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// SessionManager manages encrypted cookie-based sessions using AES-256-GCM.
type SessionManager struct {
	gcm    cipher.AEAD
	maxAge time.Duration
	secure bool
}

// NewSessionManager creates a SessionManager that encrypts session data with
// a key derived from secret. maxAge controls session lifetime.
func NewSessionManager(secret string, maxAge time.Duration, secure bool) (*SessionManager, error) {
	if secret == "" {
		return nil, errors.New("session secret must not be empty")
	}

	// Derive a 32-byte key from the secret using SHA-256.
	hash := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	return &SessionManager{
		gcm:    gcm,
		maxAge: maxAge,
		secure: secure,
	}, nil
}

// SetSession encrypts data and stores it in a cookie on w.
func (sm *SessionManager) SetSession(w http.ResponseWriter, data *SessionData) error {
	plaintext, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	nonce := make([]byte, sm.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := sm.gcm.Seal(nonce, nonce, plaintext, nil)
	encoded := base64.URLEncoding.EncodeToString(ciphertext)

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    encoded,
		Path:     "/",
		HttpOnly: true,
		Secure:   sm.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sm.maxAge.Seconds()),
	})
	return nil
}

// GetSession reads and decrypts the session cookie from the request.
func (sm *SessionManager) GetSession(r *http.Request) (*SessionData, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, fmt.Errorf("no session cookie: %w", err)
	}

	ciphertext, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil, fmt.Errorf("decode cookie: %w", err)
	}

	nonceSize := sm.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := sm.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt session: %w", err)
	}

	var data SessionData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}

	if time.Now().After(data.ExpiresAt) {
		return nil, errors.New("session expired")
	}

	return &data, nil
}

// ClearSession expires the session cookie.
func (sm *SessionManager) ClearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   sm.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}
