package storage

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestBearerTokenTransport_InjectsHeader(t *testing.T) {
	// Mock token endpoint
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"test-jwt-token","expires_in":300,"token_type":"Bearer"}`))
	}))
	defer tokenServer.Close()

	// Mock S3 endpoint that verifies the Authorization header
	var gotAuth string
	s3Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer s3Server.Close()

	transport := &BearerTokenTransport{
		TokenURL:     tokenServer.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	client := &http.Client{Transport: transport}
	resp, err := client.Get(s3Server.URL + "/test")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if gotAuth != "Bearer test-jwt-token" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer test-jwt-token")
	}
}

func TestBearerTokenTransport_CachesToken(t *testing.T) {
	var callCount atomic.Int32
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"cached-token","expires_in":300,"token_type":"Bearer"}`))
	}))
	defer tokenServer.Close()

	s3Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer s3Server.Close()

	transport := &BearerTokenTransport{
		TokenURL:     tokenServer.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}
	client := &http.Client{Transport: transport}

	// Make multiple requests — token should only be fetched once.
	for i := 0; i < 5; i++ {
		resp, err := client.Get(s3Server.URL + "/test")
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		resp.Body.Close()
	}

	if got := callCount.Load(); got != 1 {
		t.Errorf("token endpoint called %d times, want 1", got)
	}
}

func TestBearerTokenTransport_TokenEndpointError(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	defer tokenServer.Close()

	transport := &BearerTokenTransport{
		TokenURL:     tokenServer.URL,
		ClientID:     "bad-client",
		ClientSecret: "bad-secret",
	}
	client := &http.Client{Transport: transport}

	_, err := client.Get("http://localhost:1/should-not-reach")
	if err == nil {
		t.Fatal("expected error when token endpoint returns 401")
	}
	fmt.Printf("got expected error: %v\n", err)
}

func TestBearerTokenTransport_ContextOverride(t *testing.T) {
	// Token endpoint should NOT be called when a context token is set.
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("token endpoint should not be called when context token is set")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer tokenServer.Close()

	var gotAuth string
	s3Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer s3Server.Close()

	transport := &BearerTokenTransport{
		TokenURL:     tokenServer.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	ctx := WithBearerToken(context.Background(), "user-jwt-token")
	req, _ := http.NewRequestWithContext(ctx, "GET", s3Server.URL+"/test", nil)

	client := &http.Client{Transport: transport}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if gotAuth != "Bearer user-jwt-token" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer user-jwt-token")
	}
}

func TestBearerTokenTransport_FallbackToServiceAccount(t *testing.T) {
	// When no context token is set, should fall back to client_credentials.
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"service-account-token","expires_in":300,"token_type":"Bearer"}`))
	}))
	defer tokenServer.Close()

	var gotAuth string
	s3Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer s3Server.Close()

	transport := &BearerTokenTransport{
		TokenURL:     tokenServer.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	// No context token set — should use service account.
	req, _ := http.NewRequestWithContext(context.Background(), "GET", s3Server.URL+"/test", nil)

	client := &http.Client{Transport: transport}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if gotAuth != "Bearer service-account-token" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer service-account-token")
	}
}

func TestBearerTokenTransport_SendsClientCredentials(t *testing.T) {
	var gotGrantType, gotClientID, gotClientSecret string
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		gotGrantType = r.FormValue("grant_type")
		gotClientID = r.FormValue("client_id")
		gotClientSecret = r.FormValue("client_secret")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"tok","expires_in":60}`))
	}))
	defer tokenServer.Close()

	s3Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer s3Server.Close()

	transport := &BearerTokenTransport{
		TokenURL:     tokenServer.URL,
		ClientID:     "my-client",
		ClientSecret: "my-secret",
	}
	client := &http.Client{Transport: transport}
	resp, err := client.Get(s3Server.URL + "/test")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if gotGrantType != "client_credentials" {
		t.Errorf("grant_type = %q, want %q", gotGrantType, "client_credentials")
	}
	if gotClientID != "my-client" {
		t.Errorf("client_id = %q, want %q", gotClientID, "my-client")
	}
	if gotClientSecret != "my-secret" {
		t.Errorf("client_secret = %q, want %q", gotClientSecret, "my-secret")
	}
}
