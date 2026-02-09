package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestTokenStore_StoreAndGet(t *testing.T) {
	ts := NewTokenStore("http://unused", "cid", "csecret")
	ts.Store("user1", &UserToken{
		AccessToken:  "tok-abc",
		RefreshToken: "ref-abc",
		ExpiresAt:    time.Now().Add(10 * time.Minute),
	})

	got, ok := ts.GetToken(context.Background(), "user1")
	if !ok {
		t.Fatal("expected token to be found")
	}
	if got != "tok-abc" {
		t.Errorf("token = %q, want %q", got, "tok-abc")
	}
}

func TestTokenStore_MissingKey(t *testing.T) {
	ts := NewTokenStore("http://unused", "cid", "csecret")

	_, ok := ts.GetToken(context.Background(), "nonexistent")
	if ok {
		t.Error("expected ok=false for missing key")
	}
}

func TestTokenStore_Delete(t *testing.T) {
	ts := NewTokenStore("http://unused", "cid", "csecret")
	ts.Store("user1", &UserToken{
		AccessToken:  "tok",
		RefreshToken: "ref",
		ExpiresAt:    time.Now().Add(10 * time.Minute),
	})

	ts.Delete("user1")

	_, ok := ts.GetToken(context.Background(), "user1")
	if ok {
		t.Error("expected ok=false after delete")
	}
}

func TestTokenStore_ExpiredTriggersRefresh(t *testing.T) {
	refreshSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.FormValue("grant_type") != "refresh_token" {
			t.Errorf("grant_type = %q, want %q", r.FormValue("grant_type"), "refresh_token")
		}
		if r.FormValue("refresh_token") != "old-refresh" {
			t.Errorf("refresh_token = %q, want %q", r.FormValue("refresh_token"), "old-refresh")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "new-access-tok",
			"refresh_token": "new-refresh-tok",
			"expires_in":    300,
		})
	}))
	defer refreshSrv.Close()

	ts := NewTokenStore(refreshSrv.URL, "cid", "csecret")
	ts.Store("user1", &UserToken{
		AccessToken:  "expired-tok",
		RefreshToken: "old-refresh",
		ExpiresAt:    time.Now().Add(-1 * time.Minute), // already expired
	})

	got, ok := ts.GetToken(context.Background(), "user1")
	if !ok {
		t.Fatal("expected token after refresh")
	}
	if got != "new-access-tok" {
		t.Errorf("token = %q, want %q", got, "new-access-tok")
	}
}

func TestTokenStore_RefreshFailure_ReturnsFalse(t *testing.T) {
	refreshSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer refreshSrv.Close()

	ts := NewTokenStore(refreshSrv.URL, "cid", "csecret")
	ts.Store("user1", &UserToken{
		AccessToken:  "expired-tok",
		RefreshToken: "bad-refresh",
		ExpiresAt:    time.Now().Add(-1 * time.Minute),
	})

	_, ok := ts.GetToken(context.Background(), "user1")
	if ok {
		t.Error("expected ok=false when refresh fails")
	}
}

func TestTokenStore_ConcurrentAccess(t *testing.T) {
	ts := NewTokenStore("http://unused", "cid", "csecret")

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := "user"
			ts.Store(key, &UserToken{
				AccessToken:  "tok",
				RefreshToken: "ref",
				ExpiresAt:    time.Now().Add(10 * time.Minute),
			})
			ts.GetToken(context.Background(), key)
			ts.Delete(key)
		}(i)
	}
	wg.Wait()
}

func TestTokenStoreKey(t *testing.T) {
	got := TokenStoreKey("user-123", "file-456")
	if got != "user-123:file-456" {
		t.Errorf("TokenStoreKey = %q, want %q", got, "user-123:file-456")
	}
}
