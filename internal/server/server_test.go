package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/example/mcp-oauth-proxy/internal/config"
	"github.com/example/mcp-oauth-proxy/internal/graph"
	"github.com/example/mcp-oauth-proxy/internal/testsupport"
)

type harness struct {
	entra    *testsupport.Entra
	dir      *testsupport.Directory
	proxy    *httptest.Server
	metrics  *httptest.Server
	upstream *httptest.Server
	received chan *http.Request
}

func newHarness(t *testing.T, upstream http.Handler, mutate ...func(*config.Config)) *harness {
	t.Helper()

	h := &harness{
		entra:    testsupport.NewEntra(t),
		dir:      testsupport.NewDirectory(),
		received: make(chan *http.Request, 8),
	}

	if upstream == nil {
		upstream = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			clone := r.Clone(context.Background())
			clone.Body = io.NopCloser(strings.NewReader(string(body)))
			select {
			case h.received <- clone:
			default:
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`))
		})
	}
	h.upstream = httptest.NewServer(upstream)
	t.Cleanup(h.upstream.Close)

	cfgYAML := `
server:
  listenAddr: ":0"
  metricsAddr: ":0"
  maxBodyBytes: 1048576
  maxGroupsHeaderBytes: 2048
upstream:
  url: ` + h.upstream.URL + `
log:
  level: error
  format: text
authorization:
  oauth2:
    resource: https://mcp.contoso.com/mcp
    resourceName: Contoso MCP
    scopesSupported: ["` + testsupport.Audience + `/mcp.access"]
    allowGroups: ["` + testsupport.GroupAdmins + `"]
    oauth2Client:
      - authority: ` + h.entra.URL + `
        tenantID: ` + testsupport.Tenant + `
        clientID: 22222222-2222-2222-2222-222222222222
        audience: ["` + testsupport.Audience + `"]
        acceptV1Tokens: true
        clockSkew: 30s
        jwksRefreshInterval: 1h
        jwksTimeout: 5s
    graph:
      cacheTTL: 1m
      negativeCacheTTL: 1s
      credential:
        type: secret
        clientID: 44444444-4444-4444-4444-444444444444
        clientSecretEnv: MCP_TEST_GRAPH_SECRET
  policy:
    defaultEffect: allow
`
	t.Setenv("MCP_TEST_GRAPH_SECRET", "not-used-the-directory-is-faked")

	cfg, err := config.Parse([]byte(cfgYAML), t.TempDir())
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	for _, m := range mutate {
		m(cfg)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	factory := func(string, *config.Graph) graph.GroupLister { return h.dir }

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	srv, err := newWithGraph(ctx, cfg, factory, logger)
	if err != nil {
		t.Fatalf("build server: %v", err)
	}
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("start server: %v", err)
	}

	h.proxy = httptest.NewServer(srv.Handler())
	t.Cleanup(h.proxy.Close)
	h.metrics = httptest.NewServer(srv.MetricsHandler())
	t.Cleanup(h.metrics.Close)
	return h
}

func (h *harness) do(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	resp, err := h.proxy.Client().Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func (h *harness) post(t *testing.T, token, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.proxy.URL+"/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return h.do(t, req)
}

const initializeBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`

// An unauthenticated call must return the RFC 9728 challenge that tells the MCP
// client where to find the protected resource metadata.
func TestUnauthenticatedRequestReturnsDiscoveryChallenge(t *testing.T) {
	h := newHarness(t, nil)

	resp := h.post(t, "", initializeBody)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	want := `resource_metadata="https://mcp.contoso.com/.well-known/oauth-protected-resource/mcp"`
	if !strings.Contains(challenge, want) {
		t.Errorf("WWW-Authenticate = %q, want it to contain %s", challenge, want)
	}
}

func TestProtectedResourceMetadataIsPublic(t *testing.T) {
	h := newHarness(t, nil)

	for _, path := range []string{
		"/.well-known/oauth-protected-resource",
		"/.well-known/oauth-protected-resource/mcp",
	} {
		req, _ := http.NewRequest(http.MethodGet, h.proxy.URL+path, nil)
		resp := h.do(t, req)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", path, resp.StatusCode)
		}
		var doc protectedResourceMetadata
		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
			t.Fatalf("%s: decode: %v", path, err)
		}
		if doc.Resource != "https://mcp.contoso.com/mcp" {
			t.Errorf("%s: resource = %q", path, doc.Resource)
		}
		wantAS := h.entra.URL + "/" + testsupport.Tenant + "/v2.0"
		if len(doc.AuthorizationServers) != 1 || doc.AuthorizationServers[0] != wantAS {
			t.Errorf("%s: authorization_servers = %v, want [%s]", path, doc.AuthorizationServers, wantAS)
		}
	}
}

// The proxy must terminate the token and present the identity to the upstream
// MCP server as headers; forwarding the token itself is forbidden by the spec.
func TestValidTokenIsProxiedWithoutTokenPassthrough(t *testing.T) {
	h := newHarness(t, nil)

	resp := h.post(t, h.entra.Token(t), initializeBody)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}

	select {
	case got := <-h.received:
		if a := got.Header.Get("Authorization"); a != "" {
			t.Errorf("upstream received Authorization header %q, want it stripped", a)
		}
		if user := got.Header.Get("X-Mcp-User"); user != "igor@contoso.com" {
			t.Errorf("X-Mcp-User = %q", user)
		}
		if groups := got.Header.Get("X-Mcp-Groups"); !strings.Contains(groups, strings.ToLower(testsupport.GroupAdmins)) {
			t.Errorf("X-Mcp-Groups = %q, want it to carry the directory groups", groups)
		}
		if m := got.Header.Get("X-Mcp-Matched-Group"); m != strings.ToLower(testsupport.GroupAdmins) {
			t.Errorf("X-Mcp-Matched-Group = %q", m)
		}
		body, _ := io.ReadAll(got.Body)
		if string(body) != initializeBody {
			t.Errorf("upstream body = %s, want it unchanged", body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream never received the request")
	}
}

// A client must not be able to assert its own identity to the upstream server.
func TestSpoofedIdentityHeadersAreStripped(t *testing.T) {
	h := newHarness(t, nil)

	req, _ := http.NewRequest(http.MethodPost, h.proxy.URL+"/mcp", strings.NewReader(initializeBody))
	req.Header.Set("Authorization", "Bearer "+h.entra.Token(t))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Mcp-User", "attacker@evil.example")
	req.Header.Set("X-Mcp-Groups", testsupport.GroupOutsider)
	req.Header.Set("X-Forwarded-User", "attacker@evil.example")
	h.do(t, req)

	select {
	case got := <-h.received:
		if user := got.Header.Get("X-Mcp-User"); user != "igor@contoso.com" {
			t.Errorf("X-Mcp-User = %q, want the validated identity", user)
		}
		if groups := got.Header.Get("X-Mcp-Groups"); strings.Contains(groups, testsupport.GroupOutsider) {
			t.Errorf("X-Mcp-Groups = %q, want the spoofed value dropped", groups)
		}
		if fwd := got.Header.Get("X-Forwarded-User"); fwd == "attacker@evil.example" {
			t.Error("X-Forwarded-User was forwarded unchanged")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream never received the request")
	}
}

// Group membership is the only gate, so a user outside every allowed group must
// be refused even with a perfectly valid token.
func TestUserOutsideAllowedGroupsIsRejected(t *testing.T) {
	h := newHarness(t, nil, func(c *config.Config) {
		c.Authorization.OAuth2.AllowGroups = []string{testsupport.GroupOutsider}
	})

	resp := h.post(t, h.entra.Token(t), initializeBody)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

// When the directory cannot be reached the proxy must fail closed, and report a
// retryable 503 rather than a final 403.
func TestDirectoryOutageFailsClosed(t *testing.T) {
	h := newHarness(t, nil)
	h.dir.SetError(errors.New("graph is unreachable"))

	resp := h.post(t, h.entra.Token(t), initializeBody)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	select {
	case <-h.received:
		t.Fatal("the request reached the upstream MCP server despite an unresolvable identity")
	default:
	}
}

func TestToolPolicyDeniesCall(t *testing.T) {
	h := newHarness(t, nil, func(c *config.Config) {
		c.Authorization.Policy = config.Policy{
			DefaultEffect: "deny",
			Rules: []config.Rule{
				{Name: "handshake", Effect: "allow", Methods: []string{"initialize", "ping", "notifications/*"}},
				{Name: "readers", Effect: "allow", Methods: []string{"tools/list"}, Groups: []string{testsupport.GroupAdmins}},
			},
		}
	})

	if resp := h.post(t, h.entra.Token(t), initializeBody); resp.StatusCode != http.StatusOK {
		t.Fatalf("initialize status = %d, want 200", resp.StatusCode)
	}

	body := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"reboot"}}`
	resp := h.post(t, h.entra.Token(t), body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("tools/call status = %d, want 403", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("WWW-Authenticate"), "insufficient_scope") {
		t.Errorf("WWW-Authenticate = %q", resp.Header.Get("WWW-Authenticate"))
	}
}

// Policy rules name group object ids, so a rule written against a group the
// user is not in must not match.
func TestPolicyMatchesOnGroupObjectID(t *testing.T) {
	h := newHarness(t, nil, func(c *config.Config) {
		c.Authorization.Policy = config.Policy{
			DefaultEffect: "deny",
			Rules: []config.Rule{
				{Name: "outsiders-only", Effect: "allow", Methods: []string{"*"}, Groups: []string{testsupport.GroupOutsider}},
			},
		}
	})

	resp := h.post(t, h.entra.Token(t), initializeBody)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

// A display-name alias must behave exactly like the object id it names, in both
// allowGroups and a policy rule. It is translated on first use rather than at
// startup, so that the On-Behalf-Of flow can borrow a caller's token for the
// lookup; the answer is then cached for the life of the process.
func TestDisplayNameAliasResolvesOnFirstUse(t *testing.T) {
	h := newHarness(t, nil, aliasPolicy)

	if got := h.dir.NameCallCount(); got != 0 {
		t.Errorf("directory was consulted %d times at startup, want 0", got)
	}

	for i := 0; i < 2; i++ {
		if resp := h.post(t, h.entra.Token(t), initializeBody); resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i, resp.StatusCode)
		}
	}
	if got := h.dir.NameCallCount(); got != 1 {
		t.Errorf("display-name lookups = %d, want 1; the resolved name must be cached", got)
	}
}

// The alias is only honoured because the caller holds the object id it resolved
// to. A user who is not a member must not be let in by a rule written as a name.
func TestDisplayNameAliasDeniesNonMembers(t *testing.T) {
	h := newHarness(t, nil, aliasPolicy)
	h.dir.SetMembers(testsupport.UserObjectID)

	if resp := h.post(t, h.entra.Token(t), initializeBody); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

// A name that cannot be resolved must fail the request closed, never quietly
// stop matching, which would silently widen or narrow the policy. A directory
// that is merely unreachable is worth retrying, so it stays a 503.
func TestUnreachableDirectoryFailsClosedAsRetryable(t *testing.T) {
	h := newHarness(t, nil, aliasPolicy)
	h.dir.SetNameError(errors.New("graph is down"))

	if resp := h.post(t, h.entra.Token(t), initializeBody); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

// A group name that does not exist is a fault in this server's own
// configuration. Retrying can never fix it, so it must not be reported as a
// temporary outage, and the response has to name the group at fault.
func TestMisspelledGroupNameIsAServerError(t *testing.T) {
	h := newHarness(t, nil, func(c *config.Config) {
		c.Authorization.OAuth2.AllowGroups = []string{"name:mcp-opperators"}
		c.Authorization.Policy = config.Policy{DefaultEffect: "allow"}
	})

	resp := h.post(t, h.entra.Token(t), initializeBody)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; a misspelled group name is not a transient outage", resp.StatusCode)
	}
	body := readBody(t, resp)
	for _, want := range []string{"mcp-opperators", "no group with this display name"} {
		if !strings.Contains(body, want) {
			t.Errorf("body should mention %q, got: %s", want, body)
		}
	}
}

func TestAmbiguousGroupNameIsAServerError(t *testing.T) {
	h := newHarness(t, nil, func(c *config.Config) {
		c.Authorization.OAuth2.AllowGroups = []string{"name:ambiguous"}
		c.Authorization.Policy = config.Policy{DefaultEffect: "allow"}
	})

	resp := h.post(t, h.entra.Token(t), initializeBody)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
	if body := readBody(t, resp); !strings.Contains(body, "more than one group") {
		t.Errorf("body should explain the ambiguity, got: %s", body)
	}
}

// A name that will never resolve must not cost a directory call on every
// request, or a single typo turns into sustained load against Graph.
func TestPermanentlyBadGroupNameIsNotRetriedPerRequest(t *testing.T) {
	h := newHarness(t, nil, func(c *config.Config) {
		c.Authorization.OAuth2.AllowGroups = []string{"name:mcp-opperators"}
		c.Authorization.Policy = config.Policy{DefaultEffect: "allow"}
	})

	for i := 0; i < 4; i++ {
		if resp := h.post(t, h.entra.Token(t), initializeBody); resp.StatusCode != http.StatusInternalServerError {
			t.Fatalf("request %d: status = %d, want 500", i, resp.StatusCode)
		}
	}
	if got := h.dir.NameCallCount(); got != 1 {
		t.Errorf("display-name lookups = %d, want 1 within the negative cache window", got)
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

func aliasPolicy(c *config.Config) {
	c.Authorization.OAuth2.AllowGroups = []string{"name:mcp-admins"}
	c.Authorization.Policy = config.Policy{
		DefaultEffect: "deny",
		Rules: []config.Rule{
			{Name: "admins", Effect: "allow", Methods: []string{"*"}, Groups: []string{"name:mcp-admins"}},
		},
	}
}

// One denied call must reject the whole batch, otherwise a client could smuggle
// a forbidden method alongside a permitted one.
func TestDeniedCallRejectsWholeBatch(t *testing.T) {
	h := newHarness(t, nil, func(c *config.Config) {
		c.Authorization.Policy = config.Policy{
			DefaultEffect: "deny",
			Rules: []config.Rule{
				{Name: "ping-only", Effect: "allow", Methods: []string{"ping"}},
			},
		}
	})

	body := `[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"reboot"}}]`
	if resp := h.post(t, h.entra.Token(t), body); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	select {
	case <-h.received:
		t.Fatal("a batch containing a denied call reached the upstream server")
	default:
	}
}

// Transitive membership can run to hundreds of groups; the forwarded header
// must stay inside the buffers an ingress controller will accept.
func TestLargeGroupMembershipIsTruncated(t *testing.T) {
	var many []graph.Group
	many = append(many, graph.Group{ID: testsupport.GroupAdmins, DisplayName: "mcp-admins"})
	for i := 0; i < 400; i++ {
		many = append(many, graph.Group{ID: fmt.Sprintf("ffffffff-0000-0000-0000-%012d", i)})
	}

	h := newHarness(t, nil, func(c *config.Config) {
		c.Server.MaxGroupsHeaderBytes = 512
	})
	h.dir.SetMembers(testsupport.UserObjectID, many...)

	if resp := h.post(t, h.entra.Token(t), initializeBody); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	select {
	case got := <-h.received:
		groups := got.Header.Get("X-Mcp-Groups")
		if len(groups) > 512 {
			t.Errorf("X-Mcp-Groups is %d bytes, want at most 512", len(groups))
		}
		if got.Header.Get("X-Mcp-Groups-Truncated") != "true" {
			t.Error("truncation was not signalled to the upstream server")
		}
		// The group that actually granted access must always be reported.
		if m := got.Header.Get("X-Mcp-Matched-Group"); m != strings.ToLower(testsupport.GroupAdmins) {
			t.Errorf("X-Mcp-Matched-Group = %q", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream never received the request")
	}
}

// Membership must be cached, otherwise every single MCP call would become a
// directory round trip.
func TestMembershipIsCachedAcrossRequests(t *testing.T) {
	h := newHarness(t, nil)

	token := h.entra.Token(t)
	for i := 0; i < 5; i++ {
		if resp := h.post(t, token, initializeBody); resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d", i, resp.StatusCode)
		}
	}
	if got := h.dir.CallCount(); got != 1 {
		t.Errorf("directory calls = %d, want 1", got)
	}
}

// Directory lookups are the one dependency that can silently degrade, so their
// cache behaviour has to be visible to an operator.
func TestGraphCacheIsExported(t *testing.T) {
	h := newHarness(t, nil)

	token := h.entra.Token(t)
	for i := 0; i < 3; i++ {
		if resp := h.post(t, token, initializeBody); resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d", i, resp.StatusCode)
		}
	}

	req, _ := http.NewRequest(http.MethodGet, h.metrics.URL+"/metrics", nil)
	resp, err := h.metrics.Client().Do(req)
	if err != nil {
		t.Fatalf("scrape: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	want := `mcp_proxy_graph_lookups_total{result="hit"} 2`
	if !strings.Contains(string(body), want) {
		t.Errorf("metrics do not report the directory cache hits\nwant: %s\ngot:\n%s", want, body)
	}
	if !strings.Contains(string(body), `mcp_proxy_graph_lookups_total{result="miss"`) {
		t.Error("metrics do not report directory cache misses")
	}
}

func TestExpiredTokenIsRejected(t *testing.T) {
	h := newHarness(t, nil)

	token := h.entra.Token(t, func(c jwt.MapClaims) {
		c["exp"] = time.Now().Add(-time.Hour).Unix()
		c["nbf"] = time.Now().Add(-2 * time.Hour).Unix()
		c["iat"] = time.Now().Add(-2 * time.Hour).Unix()
	})
	resp := h.post(t, token, initializeBody)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("WWW-Authenticate"), "invalid_token") {
		t.Errorf("WWW-Authenticate = %q", resp.Header.Get("WWW-Authenticate"))
	}
}

func TestOversizedBodyIsRejected(t *testing.T) {
	h := newHarness(t, nil, func(c *config.Config) { c.Server.MaxBodyBytes = 128 })

	big := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + strings.Repeat("a", 500) + `"}}`
	if resp := h.post(t, h.entra.Token(t), big); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
}

// SSE frames must reach the client as they are produced, not when the upstream
// response finally closes.
func TestServerSentEventsAreStreamed(t *testing.T) {
	release := make(chan struct{})
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("event: message\ndata: {\"first\":true}\n\n"))
		w.(http.Flusher).Flush()
		<-release
		_, _ = w.Write([]byte("event: message\ndata: {\"second\":true}\n\n"))
		w.(http.Flusher).Flush()
	})

	h := newHarness(t, upstream)
	req, _ := http.NewRequest(http.MethodGet, h.proxy.URL+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+h.entra.Token(t))
	req.Header.Set("Accept", "text/event-stream")

	resp, err := h.proxy.Client().Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	defer close(release)

	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type = %q", ct)
	}
	if buf := resp.Header.Get("X-Accel-Buffering"); buf != "no" {
		t.Errorf("X-Accel-Buffering = %q, want no", buf)
	}

	reader := bufio.NewReader(resp.Body)
	done := make(chan string, 1)
	go func() {
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if strings.HasPrefix(line, "data:") {
				done <- strings.TrimSpace(line)
				return
			}
		}
	}()

	select {
	case line := <-done:
		if !strings.Contains(line, "first") {
			t.Errorf("first frame = %q", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the first SSE frame was buffered instead of streamed")
	}
}

func TestHealthAndReadiness(t *testing.T) {
	h := newHarness(t, nil)

	for _, path := range []string{"/healthz", "/readyz"} {
		req, _ := http.NewRequest(http.MethodGet, h.proxy.URL+path, nil)
		if resp := h.do(t, req); resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", path, resp.StatusCode)
		}
	}
}

func TestDCRShimReturnsStaticClient(t *testing.T) {
	h := newHarness(t, nil, func(c *config.Config) {
		c.Authorization.OAuth2.DCR.Enabled = true
		c.Authorization.OAuth2.DCR.StaticClientID = testsupport.ClientID
	})

	req, _ := http.NewRequest(http.MethodPost, h.proxy.URL+"/register",
		strings.NewReader(`{"client_name":"Test","redirect_uris":["http://localhost:1234/cb"]}`))
	req.Header.Set("Content-Type", "application/json")

	resp := h.do(t, req)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	var doc clientRegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc.ClientID != testsupport.ClientID {
		t.Errorf("client_id = %q", doc.ClientID)
	}
	if doc.TokenEndpointAuthMethod != "none" {
		t.Errorf("token_endpoint_auth_method = %q, want none for a public client", doc.TokenEndpointAuthMethod)
	}
}

func TestAuthorizationServerMetadataIsMirrored(t *testing.T) {
	h := newHarness(t, nil, func(c *config.Config) {
		c.Authorization.OAuth2.DCR.Enabled = true
		c.Authorization.OAuth2.DCR.StaticClientID = testsupport.ClientID
	})

	req, _ := http.NewRequest(http.MethodGet, h.proxy.URL+"/.well-known/oauth-authorization-server", nil)
	resp := h.do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Entra ID has no RFC 7591 endpoint, so the shim must advertise its own.
	if doc["registration_endpoint"] != "https://mcp.contoso.com/register" {
		t.Errorf("registration_endpoint = %v", doc["registration_endpoint"])
	}
}

func TestUpstreamFailureReturnsJSONRPCError(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("upstream response writer is not hijackable")
			return
		}
		conn, _, err := hj.Hijack()
		if err == nil {
			_ = conn.Close()
		}
	})

	h := newHarness(t, upstream)
	resp := h.post(t, h.entra.Token(t), initializeBody)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "upstream MCP server unavailable") {
		t.Errorf("body = %s", body)
	}
}

// Under the On-Behalf-Of flow the display-name lookup is a directory read like
// any other, so it is made with the caller's own token. Resolving lazily is
// what makes that possible: at startup no caller token exists to exchange.
func TestOBOFlowResolvesDisplayNameAliasesWithTheCallersToken(t *testing.T) {
	h := newHarness(t, nil, func(c *config.Config) {
		c.Authorization.OAuth2.Graph.Flow = config.GraphFlowOBO
		aliasPolicy(c)
	})

	token := h.entra.Token(t)
	if resp := h.post(t, token, initializeBody); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	caller, ok := h.dir.LastNameCaller()
	if !ok {
		t.Fatal("the display name was never looked up")
	}
	if caller.Assertion != token {
		t.Error("the lookup did not receive the caller's token to exchange")
	}
}
