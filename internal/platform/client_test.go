package platform

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestClient(tokenServer, platformServer *httptest.Server) *Client {
	return &Client{
		endpoint:   platformServer.URL,
		httpClient: &http.Client{Transport: &tokenTransport{tokenURL: tokenServer.URL, clientID: "test", clientSecret: "secret"}},
	}
}

func newTokenServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "test-token", "expires_in": 300})
	}))
}

func TestListAttributeValues_Success(t *testing.T) {
	tokenServer := newTokenServer()
	defer tokenServer.Close()

	platformServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/policy.attributes.AttributesService/ListAttributes" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Connect-Protocol-Version") != "1" {
			t.Error("missing Connect-Protocol-Version header")
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("wrong Authorization header: %s", r.Header.Get("Authorization"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(listAttributesResponse{
			Attributes: []attributeDef{
				{
					FQN:    "https://example.com/attr/attr1",
					Name:   "attr1",
					Active: true,
					Values: []attributeValue{
						{FQN: "https://example.com/attr/attr1/value/v1"},
						{FQN: "https://example.com/attr/attr1/value/v2"},
					},
				},
				{
					FQN:    "https://example.com/attr/attr2",
					Name:   "attr2",
					Active: false, // inactive — should be skipped
					Values: []attributeValue{
						{FQN: "https://example.com/attr/attr2/value/v1"},
					},
				},
			},
		})
	}))
	defer platformServer.Close()

	client := newTestClient(tokenServer, platformServer)
	fqns, err := client.ListAttributeValues(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fqns) != 2 {
		t.Fatalf("expected 2 FQNs, got %d: %v", len(fqns), fqns)
	}
	if fqns[0] != "https://example.com/attr/attr1/value/v1" {
		t.Errorf("unexpected FQN[0]: %s", fqns[0])
	}
}

func TestListAttributeValues_Empty(t *testing.T) {
	tokenServer := newTokenServer()
	defer tokenServer.Close()

	platformServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(listAttributesResponse{})
	}))
	defer platformServer.Close()

	client := newTestClient(tokenServer, platformServer)
	fqns, err := client.ListAttributeValues(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fqns) != 0 {
		t.Errorf("expected 0 FQNs, got %d", len(fqns))
	}
}

func TestGetEntitlements_Success(t *testing.T) {
	tokenServer := newTokenServer()
	defer tokenServer.Close()

	platformServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/authorization.AuthorizationService/GetEntitlements" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Connect-Protocol-Version") != "1" {
			t.Error("missing Connect-Protocol-Version header")
		}

		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"entitlements":[{"entityId":"e1","attributeValueFqns":["https://example.com/attr/a/value/v1","https://example.com/attr/b/value/v2"]}]}`))
	}))
	defer platformServer.Close()

	client := newTestClient(tokenServer, platformServer)
	fqns, err := client.GetEntitlements(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fqns) != 2 {
		t.Fatalf("expected 2 FQNs, got %d", len(fqns))
	}
}

func TestGetEntitlements_ServerError(t *testing.T) {
	tokenServer := newTokenServer()
	defer tokenServer.Close()

	platformServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer platformServer.Close()

	client := newTestClient(tokenServer, platformServer)
	_, err := client.GetEntitlements(context.Background(), "alice@example.com")
	if err == nil {
		t.Fatal("expected error for server error response")
	}
}
