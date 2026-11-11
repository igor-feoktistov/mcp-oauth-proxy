// Package graph resolves Entra ID group membership through Microsoft Graph.
//
// Two flows are supported, selected by graph.flow.
//
// app_permission calls Graph as the proxy itself using the client credentials
// grant. No delegated Graph consent is needed, the inbound token's audience is
// irrelevant, and one credential serves every client application — but it
// requires an application permission, and it can only read its own tenant.
//
// obo exchanges the caller's access token for a Graph token using the
// On-Behalf-Of flow. It consumes a delegated permission, reads the directory
// with the caller's own rights, and works across tenants because the exchange
// happens at the caller's own token endpoint.
package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/example/mcp-oauth-proxy/internal/config"
)

// tokenSource issues application tokens for Microsoft Graph and caches them
// until shortly before they expire.
type tokenSource struct {
	endpoint   string
	cred       *config.Credential
	httpClient *http.Client
	now        func() time.Time

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

// expiryMargin renews a Graph token before it actually expires so that an
// in-flight request never fails on a token that lapsed mid-call.
const expiryMargin = 2 * time.Minute

func newTokenSource(endpoint string, cred *config.Credential, hc *http.Client, now func() time.Time) *tokenSource {
	return &tokenSource{endpoint: endpoint, cred: cred, httpClient: hc, now: now}
}

// Token returns a cached or freshly minted Graph access token.
func (t *tokenSource) Token(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.token != "" && t.now().Before(t.expiresAt) {
		return t.token, nil
	}

	form := url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {t.cred.ClientID},
		"scope":      {t.cred.Scope},
	}
	if err := t.authenticate(form); err != nil {
		return "", err
	}

	tr, err := t.post(ctx, t.endpoint, form)
	if err != nil {
		return "", err
	}

	lifetime := time.Duration(tr.ExpiresIn) * time.Second
	if lifetime <= expiryMargin {
		// Very short lifetime: cache for half of it rather than not at all.
		lifetime /= 2
	} else {
		lifetime -= expiryMargin
	}
	t.token = tr.AccessToken
	t.expiresAt = t.now().Add(lifetime)
	return t.token, nil
}

// oboGrantType is the RFC 7523 JWT bearer grant Entra ID uses for the
// On-Behalf-Of exchange.
const oboGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// exchange performs the On-Behalf-Of exchange, trading the caller's own access
// token for one scoped to Microsoft Graph.
//
// The result is deliberately not cached. It is only ever requested on a
// membership cache miss, and caching it would mean holding a user-scoped
// credential well past the point the proxy has any use for it.
func (t *tokenSource) exchange(ctx context.Context, endpoint, assertion string) (string, error) {
	if assertion == "" {
		return "", fmt.Errorf("on-behalf-of exchange requires the caller's access token")
	}
	form := url.Values{
		"grant_type":          {oboGrantType},
		"client_id":           {t.cred.ClientID},
		"assertion":           {assertion},
		"scope":               {t.cred.Scope},
		"requested_token_use": {"on_behalf_of"},
	}
	if err := t.authenticate(form); err != nil {
		return "", err
	}
	tr, err := t.post(ctx, endpoint, form)
	if err != nil {
		return "", err
	}
	return tr.AccessToken, nil
}

// forget drops the cached token so the next call re-authenticates. It is used
// when Graph rejects the token with 401, which can happen after a credential
// rotation.
func (t *tokenSource) forget() {
	t.mu.Lock()
	t.token = ""
	t.expiresAt = time.Time{}
	t.mu.Unlock()
}

// authenticate adds the proxy's own credential to a token request. Both flows
// authenticate the client the same way; they differ only in the grant.
func (t *tokenSource) authenticate(form url.Values) error {
	switch t.cred.Type {
	case config.CredentialFederated:
		// The projected service account token is short lived and is rotated in
		// place by the kubelet, so it must be read on every exchange.
		assertion, err := os.ReadFile(t.cred.TokenFile)
		if err != nil {
			return fmt.Errorf("read federated token file: %w", err)
		}
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", strings.TrimSpace(string(assertion)))
	case config.CredentialSecret:
		form.Set("client_secret", t.cred.Secret())
	default:
		return fmt.Errorf("unsupported credential type %q", t.cred.Type)
	}
	return nil
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func (t *tokenSource) post(ctx context.Context, endpoint string, form url.Values) (*tokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request graph token: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read graph token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPError{
			Status:     resp.StatusCode,
			RetryAfter: retryAfter(resp.Header, t.now()),
			Message:    tokenErrorMessage(body),
		}
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("parse graph token response: %w", err)
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("graph token response contained no access_token")
	}
	return &tr, nil
}

func tokenErrorMessage(body []byte) string {
	var e struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		// error_description embeds a correlation id and a newline-separated trace.
		desc, _, _ := strings.Cut(e.Description, "\n")
		if desc != "" {
			return e.Error + ": " + desc
		}
		return e.Error
	}
	return strings.TrimSpace(string(body))
}
