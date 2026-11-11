package graph

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/example/mcp-oauth-proxy/internal/config"
)

const testTenant = "11111111-1111-1111-1111-111111111111"

// graphStub serves the Entra token endpoint and the membership endpoint.
type graphStub struct {
	pages      [][]Group
	status     int
	retryAfter string
	tokenCalls int
	dataCalls  int
	requests   []string
}

func (g *graphStub) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /"+testTenant+"/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		g.tokenCalls++
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "client_credentials" {
			t.Errorf("grant_type = %q, want client_credentials", r.Form.Get("grant_type"))
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"token_type":"Bearer","expires_in":3600,"access_token":"app-token"}`)
	})
	mux.HandleFunc("/v1.0/", func(w http.ResponseWriter, r *http.Request) {
		g.dataCalls++
		g.requests = append(g.requests, r.URL.RequestURI())
		if r.Header.Get("Authorization") != "Bearer app-token" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":{"code":"InvalidAuthenticationToken","message":"nope"}}`)
			return
		}
		if g.status != 0 {
			if g.retryAfter != "" {
				w.Header().Set("Retry-After", g.retryAfter)
			}
			w.WriteHeader(g.status)
			fmt.Fprint(w, `{"error":{"code":"TooManyRequests","message":"slow down"}}`)
			return
		}

		page := 0
		fmt.Sscanf(r.URL.Query().Get("page"), "%d", &page)
		var items []string
		if page < len(g.pages) {
			for _, grp := range g.pages[page] {
				items = append(items, fmt.Sprintf(`{"id":%q,"displayName":%q}`, grp.ID, grp.DisplayName))
			}
		}
		body := `{"value":[` + strings.Join(items, ",") + `]`
		if page+1 < len(g.pages) {
			body += fmt.Sprintf(`,"@odata.nextLink":"http://%s%s?page=%d"`, r.Host, r.URL.Path, page+1)
		}
		body += "}"
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func clientFor(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	g := &config.Graph{
		BaseURL: srv.URL,
		Timeout: 5 * time.Second,
		Credential: config.Credential{
			Type:     config.CredentialSecret,
			ClientID: "app-id",
			TenantID: testTenant,
			Scope:    srv.URL + "/.default",
		},
	}
	return NewClient(srv.URL, g)
}

func TestTransitiveMemberOfFollowsPagination(t *testing.T) {
	stub := &graphStub{pages: [][]Group{
		{{ID: "g1", DisplayName: "one"}},
		{{ID: "g2", DisplayName: "two"}},
		{{ID: "g3", DisplayName: "three"}},
	}}
	c := clientFor(t, stub.server(t))

	groups, err := c.TransitiveMemberOf(context.Background(), Caller{UserID: "user-1"})
	if err != nil {
		t.Fatalf("TransitiveMemberOf: %v", err)
	}
	if len(groups) != 3 {
		t.Fatalf("got %d groups, want 3 across all pages: %v", len(groups), groups)
	}
	if stub.dataCalls != 3 {
		t.Errorf("data calls = %d, want 3", stub.dataCalls)
	}
}

// The request must be restricted to microsoft.graph.group: the memberOf
// endpoints also return directory roles and administrative units, and a
// directory role name must never be mistaken for a group.
func TestTransitiveMemberOfRequestsOnlyGroups(t *testing.T) {
	stub := &graphStub{pages: [][]Group{{{ID: "g1"}}}}
	c := clientFor(t, stub.server(t))

	if _, err := c.TransitiveMemberOf(context.Background(), Caller{UserID: "user-1"}); err != nil {
		t.Fatal(err)
	}
	if len(stub.requests) == 0 {
		t.Fatal("no request was recorded")
	}
	req := stub.requests[0]
	if !strings.Contains(req, "/transitiveMemberOf/microsoft.graph.group") {
		t.Errorf("request %q should target transitiveMemberOf/microsoft.graph.group", req)
	}
}

func TestGraphTokenIsCachedAcrossCalls(t *testing.T) {
	stub := &graphStub{pages: [][]Group{{{ID: "g1"}}}}
	c := clientFor(t, stub.server(t))

	for i := 0; i < 3; i++ {
		if _, err := c.TransitiveMemberOf(context.Background(), Caller{UserID: "user-1"}); err != nil {
			t.Fatal(err)
		}
	}
	if stub.tokenCalls != 1 {
		t.Errorf("token calls = %d, want 1; the application token should be reused", stub.tokenCalls)
	}
}

func TestThrottledResponseSurfacesRetryAfter(t *testing.T) {
	stub := &graphStub{status: http.StatusTooManyRequests, retryAfter: "120"}
	c := clientFor(t, stub.server(t))

	_, err := c.TransitiveMemberOf(context.Background(), Caller{UserID: "user-1"})
	var he *HTTPError
	if !errors.As(err, &he) {
		t.Fatalf("error = %v, want an *HTTPError", err)
	}
	if !he.Throttled() {
		t.Errorf("Throttled() = false for status %d", he.Status)
	}
	if he.RetryAfter != 2*time.Minute {
		t.Errorf("RetryAfter = %v, want 2m", he.RetryAfter)
	}
}

func TestRetryAfterAcceptsHTTPDate(t *testing.T) {
	now := time.Now().UTC()
	h := http.Header{}
	h.Set("Retry-After", now.Add(90*time.Second).Format(http.TimeFormat))

	got := retryAfter(h, now)
	if got < 80*time.Second || got > 95*time.Second {
		t.Errorf("retryAfter = %v, want roughly 90s", got)
	}
}

func TestEmptyUserIDIsRejected(t *testing.T) {
	stub := &graphStub{}
	c := clientFor(t, stub.server(t))
	if _, err := c.TransitiveMemberOf(context.Background(), Caller{}); err == nil {
		t.Error("expected an error for an empty user object id")
	}
}

const callerTenant = "22222222-2222-2222-2222-222222222222"

// oboStub serves the On-Behalf-Of token exchange and the /me membership
// endpoint, recording what the exchange was asked for.
type oboStub struct {
	form      url.Values
	tokenPath string
	requests  []string
}

func (o *oboStub) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	exchange := func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		o.form = r.Form
		o.tokenPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"token_type":"Bearer","expires_in":3600,"access_token":"obo-token"}`)
	}
	// Both tenants are registered so that a request sent to the wrong one is a
	// visible assertion failure rather than a 404.
	mux.HandleFunc("POST /"+callerTenant+"/oauth2/v2.0/token", exchange)
	mux.HandleFunc("POST /"+testTenant+"/oauth2/v2.0/token", exchange)
	mux.HandleFunc("/v1.0/", func(w http.ResponseWriter, r *http.Request) {
		o.requests = append(o.requests, r.URL.RequestURI())
		// The directory must be read with the exchanged token, never with the
		// proxy's own application token or the caller's original one.
		if got := r.Header.Get("Authorization"); got != "Bearer obo-token" {
			t.Errorf("Authorization = %q, want the exchanged token", got)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"value":[{"id":"g1","displayName":"admins"}]}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func oboClientFor(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	// Federated rather than secret, so the client credential can be asserted
	// without a test-only setter on config.Credential.
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("client-assertion-jwt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	g := &config.Graph{
		Flow:    config.GraphFlowOBO,
		BaseURL: srv.URL,
		Timeout: 5 * time.Second,
		Credential: config.Credential{
			Type:      config.CredentialFederated,
			ClientID:  "api-app-id",
			TenantID:  testTenant,
			TokenFile: tokenFile,
			Scope:     srv.URL + "/.default",
		},
	}
	return NewClient(srv.URL, g)
}

func TestOBOExchangesCallerTokenForGraphToken(t *testing.T) {
	stub := &oboStub{}
	c := oboClientFor(t, stub.server(t))

	groups, err := c.TransitiveMemberOf(context.Background(), Caller{
		TenantID:  callerTenant,
		UserID:    "user-1",
		Assertion: "caller-access-token",
	})
	if err != nil {
		t.Fatalf("TransitiveMemberOf: %v", err)
	}
	if len(groups) != 1 || groups[0].ID != "g1" {
		t.Fatalf("groups = %v", groups)
	}

	want := map[string]string{
		"grant_type":          oboGrantType,
		"requested_token_use": "on_behalf_of",
		"assertion":           "caller-access-token",
		"client_id":           "api-app-id",
		// The proxy still authenticates as itself; OBO only changes the grant.
		"client_assertion":      "client-assertion-jwt",
		"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
	}
	for k, v := range want {
		if got := stub.form.Get(k); got != v {
			t.Errorf("exchange %s = %q, want %q", k, got, v)
		}
	}

	// /me, not /users/{id}: the exchanged token already identifies the user,
	// and the caller's own rights are what permit the read.
	if len(stub.requests) != 1 || !strings.HasPrefix(stub.requests[0], "/v1.0/me/transitiveMemberOf") {
		t.Errorf("requests = %v, want /v1.0/me/transitiveMemberOf", stub.requests)
	}
}

// The exchange must happen at the caller's own tenant, which is what lets this
// flow serve tenants the proxy's own credential could never read.
func TestOBOExchangesAtCallerTenant(t *testing.T) {
	stub := &oboStub{}
	c := oboClientFor(t, stub.server(t))

	if _, err := c.TransitiveMemberOf(context.Background(), Caller{
		TenantID: callerTenant, UserID: "user-1", Assertion: "caller-access-token",
	}); err != nil {
		t.Fatalf("TransitiveMemberOf: %v", err)
	}
	if want := "/" + callerTenant + "/oauth2/v2.0/token"; stub.tokenPath != want {
		t.Errorf("exchange endpoint = %q, want %q (the caller's tenant, not the credential's)", stub.tokenPath, want)
	}
}

func TestOBORequiresTheCallerToken(t *testing.T) {
	stub := &oboStub{}
	c := oboClientFor(t, stub.server(t))

	_, err := c.TransitiveMemberOf(context.Background(), Caller{TenantID: callerTenant, UserID: "user-1"})
	if err == nil {
		t.Fatal("expected an error when no caller token is available to exchange")
	}
}

// A display-name lookup is a directory read, so under this flow it is made with
// the caller's exchanged token like every other Graph call.
func TestOBOLooksUpDisplayNamesWithTheExchangedToken(t *testing.T) {
	stub := &oboStub{}
	c := oboClientFor(t, stub.server(t))

	got, err := c.GroupsByDisplayName(context.Background(),
		Caller{TenantID: callerTenant, UserID: "user-1", Assertion: "caller-token"}, "admins")
	if err != nil {
		t.Fatalf("GroupsByDisplayName: %v", err)
	}
	if len(got) != 1 || got[0].DisplayName != "admins" {
		t.Fatalf("groups = %+v", got)
	}
	if stub.form.Get("assertion") != "caller-token" {
		t.Errorf("assertion = %q, want the caller's token", stub.form.Get("assertion"))
	}
	if want := "/" + callerTenant + "/oauth2/v2.0/token"; stub.tokenPath != want {
		t.Errorf("exchanged at %q, want the caller's tenant %q", stub.tokenPath, want)
	}
	if len(stub.requests) != 1 || !strings.Contains(stub.requests[0], "/v1.0/groups") {
		t.Errorf("graph requests = %v, want a single /v1.0/groups call", stub.requests)
	}
}

// Without a caller there is nothing to exchange, so the lookup must fail rather
// than fall back to an application token this flow does not have.
func TestOBODisplayNameLookupRequiresACaller(t *testing.T) {
	stub := &oboStub{}
	c := oboClientFor(t, stub.server(t))

	_, err := c.GroupsByDisplayName(context.Background(), Caller{}, "admins")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "token to exchange") {
		t.Errorf("error = %v", err)
	}
}
