package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiter_AllowsWithinLimit(t *testing.T) {
	rl := NewRateLimiter(3, 1*time.Minute)

	for i := range 3 {
		if !rl.Allow("1.2.3.4") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
}

func TestRateLimiter_BlocksOverLimit(t *testing.T) {
	rl := NewRateLimiter(2, 1*time.Minute)

	rl.Allow("1.2.3.4")
	rl.Allow("1.2.3.4")

	if rl.Allow("1.2.3.4") {
		t.Fatal("third request should be blocked")
	}
}

func TestRateLimiter_SeparateIPs(t *testing.T) {
	rl := NewRateLimiter(1, 1*time.Minute)

	if !rl.Allow("1.1.1.1") {
		t.Fatal("first IP first request should be allowed")
	}
	if !rl.Allow("2.2.2.2") {
		t.Fatal("second IP first request should be allowed")
	}
	if rl.Allow("1.1.1.1") {
		t.Fatal("first IP second request should be blocked")
	}
}

func TestRateLimiter_WindowExpiry(t *testing.T) {
	rl := NewRateLimiter(1, 50*time.Millisecond)

	if !rl.Allow("1.2.3.4") {
		t.Fatal("first request should be allowed")
	}
	if rl.Allow("1.2.3.4") {
		t.Fatal("second request should be blocked")
	}

	time.Sleep(60 * time.Millisecond)

	if !rl.Allow("1.2.3.4") {
		t.Fatal("request after window should be allowed")
	}
}

func TestRateLimit_Middleware(t *testing.T) {
	rl := NewRateLimiter(1, 1*time.Minute)
	handler := RateLimit(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request — allowed.
	req := httptest.NewRequest(http.MethodPost, "/token", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	// Second request — blocked.
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}
}
