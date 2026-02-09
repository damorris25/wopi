package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ClientConfig holds the settings needed to connect to the OpenTDF platform.
type ClientConfig struct {
	Endpoint     string // e.g. https://platform.opentdf.local:8443
	TokenURL     string // Keycloak token endpoint
	ClientID     string // Service account client ID
	ClientSecret string // Service account client secret
}

// Client communicates with the OpenTDF platform to retrieve attributes.
type Client struct {
	endpoint   string
	httpClient *http.Client
}

// tokenTransport is an http.RoundTripper that injects a cached OIDC bearer
// token into every outgoing request (client credentials grant).
type tokenTransport struct {
	tokenURL     string
	clientID     string
	clientSecret string
	base         http.RoundTripper

	mu          sync.Mutex
	cachedToken string
	expiry      time.Time
}

type tokenResp struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

func (t *tokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tok, err := t.getToken()
	if err != nil {
		return nil, fmt.Errorf("obtain bearer token: %w", err)
	}
	r2 := req.Clone(req.Context())
	r2.Header.Set("Authorization", "Bearer "+tok)
	return t.transport().RoundTrip(r2)
}

func (t *tokenTransport) transport() http.RoundTripper {
	if t.base != nil {
		return t.base
	}
	return http.DefaultTransport
}

func (t *tokenTransport) getToken() (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.cachedToken != "" && time.Now().Before(t.expiry.Add(-30*time.Second)) {
		return t.cachedToken, nil
	}

	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {t.clientID},
		"client_secret": {t.clientSecret},
	}

	resp, err := (&http.Client{Transport: t.transport(), Timeout: 30 * time.Second}).Post(
		t.tokenURL,
		"application/x-www-form-urlencoded",
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB limit
	if err != nil {
		return "", fmt.Errorf("read token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tr tokenResp
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("parse token response: %w", err)
	}

	t.cachedToken = tr.AccessToken
	if tr.ExpiresIn > 0 {
		t.expiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	} else {
		t.expiry = time.Now().Add(5 * time.Minute)
	}
	return t.cachedToken, nil
}

// NewClient creates a platform Client that authenticates using the given
// service account credentials.
func NewClient(cfg ClientConfig) *Client {
	transport := &tokenTransport{
		tokenURL:     cfg.TokenURL,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
	}
	return &Client{
		endpoint:   strings.TrimRight(cfg.Endpoint, "/"),
		httpClient: &http.Client{Transport: transport, Timeout: 30 * time.Second},
	}
}

// connectPost sends a POST request to a Connect-protocol endpoint.
func (c *Client) connectPost(ctx context.Context, path string, reqBody any) ([]byte, error) {
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+path, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connect-Protocol-Version", "1")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MB limit
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("endpoint returned %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// listAttributesResponse is the Connect-protocol response for ListAttributes.
type listAttributesResponse struct {
	Attributes []attributeDef `json:"attributes"`
}

type attributeDef struct {
	FQN    string           `json:"fqn"`
	Name   string           `json:"name"`
	Active bool             `json:"active"`
	Values []attributeValue `json:"values"`
}

type attributeValue struct {
	FQN    string `json:"fqn"`
	Active bool   `json:"active"`
}

// ListAttributeValues returns all active attribute value FQNs from the platform.
func (c *Client) ListAttributeValues(ctx context.Context) ([]string, error) {
	respBody, err := c.connectPost(ctx, "/policy.attributes.AttributesService/ListAttributes", struct{}{})
	if err != nil {
		return nil, fmt.Errorf("list attributes: %w", err)
	}

	var listResp listAttributesResponse
	if err := json.Unmarshal(respBody, &listResp); err != nil {
		return nil, fmt.Errorf("parse attributes response: %w", err)
	}

	var fqns []string
	for _, attr := range listResp.Attributes {
		if !attr.Active {
			continue
		}
		for _, v := range attr.Values {
			// Skip FQNs with empty value components (e.g. ".../value/")
			if v.FQN == "" || strings.HasSuffix(v.FQN, "/") {
				continue
			}
			fqns = append(fqns, v.FQN)
		}
	}

	return fqns, nil
}

// ObligationSet holds the set of active obligation value FQNs for a resource.
type ObligationSet struct {
	NoDownload bool
	NoCopy     bool
	NoPrint    bool
}

// obligationTrigger represents a trigger in the ListObligationTriggers response.
type obligationTrigger struct {
	ObligationValue struct {
		FQN string `json:"fqn"`
	} `json:"obligationValue"`
	Action struct {
		Name string `json:"name"`
	} `json:"action"`
	AttributeValue struct {
		FQN string `json:"fqn"`
	} `json:"attributeValue"`
}

type listTriggersResponse struct {
	Triggers []obligationTrigger `json:"triggers"`
}

// GetObligations returns the set of document-control obligations that apply
// to the given attribute value FQNs. It queries the platform for all
// obligation triggers and matches them against the file's attributes.
func (c *Client) GetObligations(ctx context.Context, attrFQNs []string) (*ObligationSet, error) {
	if len(attrFQNs) == 0 {
		return &ObligationSet{}, nil
	}

	respBody, err := c.connectPost(ctx, "/policy.obligations.Service/ListObligationTriggers", struct{}{})
	if err != nil {
		return nil, fmt.Errorf("list obligation triggers: %w", err)
	}

	var listResp listTriggersResponse
	if err := json.Unmarshal(respBody, &listResp); err != nil {
		return nil, fmt.Errorf("parse obligation triggers: %w", err)
	}

	// Build lookup set of the file's attribute FQNs.
	attrSet := make(map[string]struct{}, len(attrFQNs))
	for _, fqn := range attrFQNs {
		attrSet[fqn] = struct{}{}
	}

	result := &ObligationSet{}
	for _, t := range listResp.Triggers {
		if _, ok := attrSet[t.AttributeValue.FQN]; !ok {
			continue
		}
		switch {
		case strings.HasSuffix(t.ObligationValue.FQN, "/no-download"):
			result.NoDownload = true
		case strings.HasSuffix(t.ObligationValue.FQN, "/no-copy"):
			result.NoCopy = true
		case strings.HasSuffix(t.ObligationValue.FQN, "/no-print"):
			result.NoPrint = true
		}
	}

	return result, nil
}

// GetEntitlements returns the attribute value FQNs the given user is entitled to.
func (c *Client) GetEntitlements(ctx context.Context, userEmail string) ([]string, error) {
	type entityDetails struct {
		ID        string `json:"id"`
		EmailAddr string `json:"emailAddress,omitempty"`
		Category  string `json:"category"`
	}
	type entityAction struct {
		Standard string `json:"standard"`
	}
	type entityChain struct {
		ID       string          `json:"id"`
		Actions  []entityAction  `json:"actions"`
		Entities []entityDetails `json:"entities"`
	}
	type entitlementRequest struct {
		Entities []entityChain `json:"entities"`
	}

	reqBody := entitlementRequest{
		Entities: []entityChain{
			{
				ID:      "e1",
				Actions: []entityAction{{Standard: "TRANSMIT"}},
				Entities: []entityDetails{
					{
						ID:        userEmail,
						EmailAddr: userEmail,
						Category:  "subjectMapping",
					},
				},
			},
		},
	}

	respBody, err := c.connectPost(ctx, "/authorization.AuthorizationService/GetEntitlements", reqBody)
	if err != nil {
		return nil, fmt.Errorf("get entitlements: %w", err)
	}

	type entitlementItem struct {
		EntityID           string   `json:"entityId"`
		AttributeValueFQNs []string `json:"attributeValueFqns"`
	}
	type entitlementResponse struct {
		Entitlements []entitlementItem `json:"entitlements"`
	}

	var entResp entitlementResponse
	if err := json.Unmarshal(respBody, &entResp); err != nil {
		return nil, fmt.Errorf("parse entitlements response: %w", err)
	}

	seen := make(map[string]struct{})
	var fqns []string
	for _, item := range entResp.Entitlements {
		for _, fqn := range item.AttributeValueFQNs {
			if _, ok := seen[fqn]; !ok {
				seen[fqn] = struct{}{}
				fqns = append(fqns, fqn)
			}
		}
	}

	return fqns, nil
}
