package config

import (
	"strings"
	"testing"
	"time"
)

const validYAML = `
upstream:
  url: http://127.0.0.1:3000
authorization:
  oauth2:
    resource: https://mcp.example.com/mcp
    allowGroups:
      - 11111111-2222-3333-4444-555555555555
    oauth2Client:
      - tenantID: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
        clientID: 99999999-8888-7777-6666-555555555555
    graph:
      credential:
        type: federated
        clientID: 99999999-8888-7777-6666-555555555555
        tokenFile: /var/run/secrets/azure/tokens/azure-identity-token
`

func parse(t *testing.T, yaml string) (*Config, error) {
	t.Helper()
	return Parse([]byte(yaml), t.TempDir())
}

func mustParse(t *testing.T, yaml string) *Config {
	t.Helper()
	c, err := parse(t, yaml)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	return c
}

func TestParseAppliesDefaults(t *testing.T) {
	c := mustParse(t, validYAML)

	if c.Server.ListenAddr != defaultListenAddr {
		t.Errorf("listenAddr = %q, want %q", c.Server.ListenAddr, defaultListenAddr)
	}
	if c.Server.MaxGroupsHeaderBytes != 2048 {
		t.Errorf("maxGroupsHeaderBytes = %d, want 2048", c.Server.MaxGroupsHeaderBytes)
	}
	if c.Authorization.Policy.DefaultEffect != "deny" {
		t.Errorf("defaultEffect = %q, want deny; the policy must fail closed",
			c.Authorization.Policy.DefaultEffect)
	}

	cl := c.Authorization.OAuth2.OAuth2Clients[0]
	if cl.GroupsSource != GroupsSourceGraph {
		t.Errorf("groupsSource = %q, want %q", cl.GroupsSource, GroupsSourceGraph)
	}
	if cl.Issuer != "https://login.microsoftonline.com/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/v2.0" {
		t.Errorf("issuer = %q", cl.Issuer)
	}
	wantAud := []string{"99999999-8888-7777-6666-555555555555", "api://99999999-8888-7777-6666-555555555555"}
	if len(cl.Audience) != 2 || cl.Audience[0] != wantAud[0] || cl.Audience[1] != wantAud[1] {
		t.Errorf("audience = %v, want %v", cl.Audience, wantAud)
	}
	g := c.Authorization.OAuth2.Graph
	if g.CacheTTL != 10*time.Minute {
		t.Errorf("graph.cacheTTL = %v, want 10m", g.CacheTTL)
	}
	if g.FailureMode != FailureModeClosed {
		t.Errorf("graph.failureMode = %q, want %q; an unreachable directory must not grant access",
			g.FailureMode, FailureModeClosed)
	}
	// The one credential can only read its own directory, so it must land in
	// the tenant whose users it is expected to resolve.
	if g.Credential.TenantID != cl.TenantID {
		t.Errorf("graph.credential.tenantID = %q, want it to default to the application tenant %q",
			g.Credential.TenantID, cl.TenantID)
	}
}

// allowGroups is the only coarse gate once delegated scopes are no longer
// consulted, so an empty list must be rejected rather than admitting everyone.
func TestAllowGroupsIsMandatory(t *testing.T) {
	yaml := strings.Replace(validYAML, `    allowGroups:
      - 11111111-2222-3333-4444-555555555555
`, "", 1)

	_, err := parse(t, yaml)
	if err == nil {
		t.Fatal("expected an error when allowGroups is absent")
	}
	if !strings.Contains(err.Error(), "allowGroups is required") {
		t.Errorf("error = %v, want it to mention allowGroups", err)
	}
}

func TestRejectsMetaTenant(t *testing.T) {
	yaml := strings.Replace(validYAML,
		"tenantID: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		"tenantID: common", 1)

	_, err := parse(t, yaml)
	if err == nil {
		t.Fatal("expected an error for the common meta-tenant")
	}
	if !strings.Contains(err.Error(), "every Entra tenant") {
		t.Errorf("error = %v, want it to explain the multi-tenant risk", err)
	}
}

func TestAppOnlyRequiresRoles(t *testing.T) {
	yaml := strings.Replace(validYAML, "    allowGroups:", "    allowAppOnly: true\n    allowGroups:", 1)

	_, err := parse(t, yaml)
	if err == nil {
		t.Fatal("expected an error when allowAppOnly is set without allowRoles")
	}
	if !strings.Contains(err.Error(), "allowRoles is required") {
		t.Errorf("error = %v, want it to mention allowRoles", err)
	}
}

func TestSecretCredentialReadsEnv(t *testing.T) {
	yaml := strings.Replace(validYAML,
		`        type: federated
        clientID: 99999999-8888-7777-6666-555555555555
        tokenFile: /var/run/secrets/azure/tokens/azure-identity-token`,
		`        type: secret
        clientID: 99999999-8888-7777-6666-555555555555
        clientSecretEnv: TEST_GRAPH_SECRET`, 1)

	if _, err := parse(t, yaml); err == nil {
		t.Fatal("expected an error when the named environment variable is empty")
	}

	t.Setenv("TEST_GRAPH_SECRET", "s3cret")
	c := mustParse(t, yaml)
	if got := c.Authorization.OAuth2.Graph.Credential.Secret(); got != "s3cret" {
		t.Errorf("secret = %q, want s3cret", got)
	}
}

func TestRejectsUnknownFields(t *testing.T) {
	yaml := validYAML + "\nunknownTopLevel: true\n"
	if _, err := parse(t, yaml); err == nil {
		t.Fatal("expected an error for an unknown field; a typo must not be silently ignored")
	}
}

func TestScopesSupportedDefaultsToAppIDURI(t *testing.T) {
	c := mustParse(t, validYAML)
	want := "99999999-8888-7777-6666-555555555555/.default"
	got := c.Authorization.OAuth2.ScopesSupported
	if len(got) != 1 || got[0] != want {
		t.Errorf("scopesSupported = %v, want [%s]", got, want)
	}
}

// A single app-only Graph credential can only read its own directory, so a
// second tenant resolving groups from Graph would silently fail at request
// time. Catch it while the configuration is being loaded instead.
func TestRejectsGraphLookupInAnotherTenant(t *testing.T) {
	yaml := strings.Replace(validYAML,
		`      - tenantID: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
        clientID: 99999999-8888-7777-6666-555555555555`,
		`      - tenantID: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
        clientID: 99999999-8888-7777-6666-555555555555
      - tenantID: bbbbbbbb-cccc-dddd-eeee-ffffffffffff
        clientID: 88888888-7777-6666-5555-444444444444`, 1)

	_, err := parse(t, yaml)
	if err == nil {
		t.Fatal("expected an error when a second tenant resolves groups from the shared credential")
	}
	if !strings.Contains(err.Error(), "cannot read another tenant's directory") {
		t.Errorf("error = %v, want it to explain the credential's tenant limit", err)
	}

	// The same second tenant is fine once it reads groups from the token.
	ok := strings.Replace(yaml,
		`      - tenantID: bbbbbbbb-cccc-dddd-eeee-ffffffffffff
        clientID: 88888888-7777-6666-5555-444444444444`,
		`      - tenantID: bbbbbbbb-cccc-dddd-eeee-ffffffffffff
        clientID: 88888888-7777-6666-5555-444444444444
        groupsSource: jwt`, 1)
	if _, err := parse(t, ok); err != nil {
		t.Errorf("groupsSource: jwt should allow a second tenant: %v", err)
	}
}

// A multi-tenant app registration keeps one client id across tenants, so the
// same value is correct for every tenant under OBO.
const oboYAML = `
upstream:
  url: http://127.0.0.1:3000
authorization:
  oauth2:
    resource: https://mcp.example.com/mcp
    allowGroups:
      - 11111111-2222-3333-4444-555555555555
    oauth2Client:
      - tenantID: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
        clientID: 99999999-8888-7777-6666-555555555555
    graph:
      flow: obo
      credential:
        type: federated
        tokenFile: /var/run/secrets/azure/tokens/azure-identity-token
`

// On-Behalf-Of can only be performed by the application the inbound token was
// issued for, so the credential defaults to that application's client id
// rather than having to be repeated.
func TestOBOFlowDefaultsCredentialToTheAPIClientID(t *testing.T) {
	c, err := parse(t, oboYAML)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	g := c.Authorization.OAuth2.Graph
	if g.Flow != GraphFlowOBO {
		t.Errorf("flow = %q, want %q", g.Flow, GraphFlowOBO)
	}
	want := c.Authorization.OAuth2.OAuth2Clients[0].ClientID
	if g.Credential.ClientID != want {
		t.Errorf("credential.clientID = %q, want the API's client id %q", g.Credential.ClientID, want)
	}
}

func TestOBOFlowRejectsADifferentCredentialClientID(t *testing.T) {
	yaml := strings.Replace(oboYAML,
		`        type: federated`,
		`        type: federated
        clientID: 12121212-1212-1212-1212-121212121212`, 1)

	_, err := parse(t, yaml)
	if err == nil {
		t.Fatal("expected an error when the credential names a different application")
	}
	if !strings.Contains(err.Error(), "On-Behalf-Of exchange can only be performed by") {
		t.Errorf("error = %v, want it to explain the OBO client id constraint", err)
	}
}

// OBO exchanges at the caller's own tenant, so the single-tenant restriction of
// the shared application credential does not apply.
func TestOBOFlowAllowsASecondTenant(t *testing.T) {
	yaml := strings.Replace(oboYAML,
		`        clientID: 99999999-8888-7777-6666-555555555555`,
		`        clientID: 99999999-8888-7777-6666-555555555555
      - tenantID: bbbbbbbb-cccc-dddd-eeee-ffffffffffff
        clientID: 99999999-8888-7777-6666-555555555555`, 1)

	c, err := parse(t, yaml)
	if err != nil {
		t.Fatalf("a second tenant should be allowed under OBO: %v", err)
	}
	if n := len(c.Authorization.OAuth2.OAuth2Clients); n != 2 {
		t.Fatalf("oauth2Client count = %d, want 2", n)
	}
}

func TestRejectsUnknownGraphFlow(t *testing.T) {
	yaml := strings.Replace(validYAML,
		`    graph:
      credential:`,
		`    graph:
      flow: wishful
      credential:`, 1)

	_, err := parse(t, yaml)
	if err == nil || !strings.Contains(err.Error(), "graph.flow must be") {
		t.Errorf("expected a graph.flow error, got %v", err)
	}
}
