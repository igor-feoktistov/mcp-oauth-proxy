// Package config loads and validates the proxy configuration from a YAML file.
//
// Everything except credentials lives in the YAML document. Credentials are
// read from the environment (or a mounted file) so that they can be supplied
// by a Kubernetes Secret or by workload identity federation without ever being
// written into a ConfigMap.
package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ConfigFileEnv names the environment variable holding the path to the YAML document.
const ConfigFileEnv = "CONFIG_FILE"

const (
	defaultListenAddr  = ":8080"
	defaultMetricsAddr = ":9090"
	defaultAuthority   = "https://login.microsoftonline.com"
	defaultGraphURL    = "https://graph.microsoft.com"
	defaultUpstream    = "http://127.0.0.1:3000"
)

// Groups sources.
const (
	GroupsSourceGraph = "msgraph"
	GroupsSourceJWT   = "jwt"
)

// Graph credential types.
const (
	CredentialFederated = "federated"
	CredentialSecret    = "secret"
)

// How the proxy obtains its Microsoft Graph token.
const (
	// GraphFlowAppPermission calls Graph as the proxy itself using the client
	// credentials grant and an application permission.
	GraphFlowAppPermission = "app_permission"
	// GraphFlowOBO exchanges the caller's access token for a Graph token,
	// consuming a delegated permission and the caller's own directory rights.
	GraphFlowOBO = "obo"
)

// Behaviour when Microsoft Graph cannot be reached and the cache has no fresh entry.
const (
	FailureModeClosed = "closed" // reject the request
	FailureModeStale  = "stale"  // serve an expired cache entry if one exists
)

// Config is the fully resolved runtime configuration of the proxy.
type Config struct {
	Server        Server        `yaml:"server"`
	Upstream      Upstream      `yaml:"upstream"`
	Authorization Authorization `yaml:"authorization"`
	Log           Log           `yaml:"log"`

	dir string
}

// Dir returns the directory of the configuration file, used to resolve
// relative paths such as the policy rulesFile.
func (c *Config) Dir() string { return c.dir }

// Server holds the listener and HTTP front-end settings.
type Server struct {
	ListenAddr     string   `yaml:"listenAddr"`
	MetricsAddr    string   `yaml:"metricsAddr"`
	TLSCertFile    string   `yaml:"tlsCertFile"`
	TLSKeyFile     string   `yaml:"tlsKeyFile"`
	MaxBodyBytes   int64    `yaml:"maxBodyBytes"`
	AllowedOrigins []string `yaml:"allowedOrigins"`
	// MaxGroupsHeaderBytes bounds the X-Mcp-Groups header forwarded upstream.
	// Transitive membership can run to hundreds of groups, which would overflow
	// the default header buffers of most ingress controllers.
	MaxGroupsHeaderBytes int `yaml:"maxGroupsHeaderBytes"`
}

// Upstream describes the MCP server this proxy sits in front of.
type Upstream struct {
	URL     string        `yaml:"url"`
	Timeout time.Duration `yaml:"timeout"`

	parsed *url.URL
}

// ParsedURL returns the validated upstream URL.
func (u *Upstream) ParsedURL() *url.URL { return u.parsed }

// Authorization groups the supported authorization methods, mirroring the
// layout used by the flexpod-mcp project so operators can reuse their mental model.
type Authorization struct {
	OAuth2 OAuth2 `yaml:"oauth2"`
	Policy Policy `yaml:"policy"`
}

// OAuth2 is the resource-server configuration.
type OAuth2 struct {
	// Resource is the canonical URI of this MCP server (RFC 9728).
	Resource              string `yaml:"resource"`
	ResourceName          string `yaml:"resourceName"`
	ResourceDocumentation string `yaml:"resourceDocumentation"`

	// ScopesSupported is advertised in the protected resource metadata so that
	// clients know what to request. Entra ID requires at least one delegated
	// scope to exist on the app registration even though the proxy does not use
	// scopes for authorization decisions.
	ScopesSupported []string `yaml:"scopesSupported"`

	// AllowGroups is the mandatory coarse gate: a user must be a member of at
	// least one of these groups to reach the MCP server at all. Entries are
	// group object ids, or "name:<displayName>" aliases that are resolved to
	// object ids at startup.
	AllowGroups []string `yaml:"allowGroups"`

	// AllowRoles admits app-only (client credentials) callers, which have no
	// user and therefore no group membership.
	AllowRoles []string `yaml:"allowRoles"`

	// AllowAppOnly must be true for app-only tokens to be considered at all.
	AllowAppOnly bool `yaml:"allowAppOnly"`

	OAuth2Clients []OAuth2Client `yaml:"oauth2Client"`

	// Graph is shared by every oauth2Client that resolves groups from the
	// directory. The proxy calls Graph as itself rather than on behalf of the
	// caller, so one credential serves the whole deployment.
	Graph Graph `yaml:"graph"`

	UserLoginTransformer UserLoginTransformer `yaml:"userLoginTransformer"`

	// DCR is the dynamic client registration shim; Entra ID has no RFC 7591 endpoint.
	DCR DCR `yaml:"dynamicClientRegistration"`
}

// OAuth2Client describes one trusted Entra ID application registration.
type OAuth2Client struct {
	Issuer    string `yaml:"issuer"`
	Authority string `yaml:"authority"`
	TenantID  string `yaml:"tenantID"`
	ClientID  string `yaml:"clientID"`
	// Audience lists the acceptable `aud` values. Defaults to clientID and
	// api://<clientID>. Audience validation is never optional: it is what stops
	// a token minted for another API being replayed here (RFC 8707).
	Audience []string `yaml:"audience"`
	// AllowedClientIDs optionally restricts which client applications may call.
	AllowedClientIDs []string `yaml:"allowedClientIDs"`

	UserLoginClaim string `yaml:"userLoginClaim"`
	GroupsClaim    string `yaml:"groupsClaim"`
	GroupsSource   string `yaml:"groupsSource"`

	AcceptV1Tokens *bool         `yaml:"acceptV1Tokens"`
	ClockSkew      time.Duration `yaml:"clockSkew"`
	JWKSRefresh    time.Duration `yaml:"jwksRefreshInterval"`
	JWKSTimeout    time.Duration `yaml:"jwksTimeout"`
}

// Graph configures Microsoft Graph group resolution.
type Graph struct {
	// Flow selects how the proxy obtains a Graph token.
	//
	// app_permission (default) uses the client credentials grant and the
	// application permission GroupMember.Read.All. The proxy calls Graph as
	// itself, so the inbound token is irrelevant and one cache entry per user
	// serves every client application.
	//
	// obo exchanges the caller's own access token for a Graph token using the
	// On-Behalf-Of flow. It consumes a *delegated* GroupMember.Read.All, which
	// some tenants are far more willing to consent to than an application
	// permission, and it reads the directory with the caller's own rights.
	Flow    string        `yaml:"flow"`
	BaseURL string        `yaml:"baseURL"`
	Timeout time.Duration `yaml:"timeout"`
	// CacheTTL bounds how long a resolved membership is reused. It is
	// deliberately independent of the access token lifetime: it is the window
	// during which a group removal has not yet taken effect.
	CacheTTL time.Duration `yaml:"cacheTTL"`
	// NegativeCacheTTL caches lookup failures briefly so that a Graph outage
	// does not turn into a request storm.
	NegativeCacheTTL time.Duration `yaml:"negativeCacheTTL"`
	// MaxCacheEntries bounds memory use; least-recently-used entries are evicted.
	MaxCacheEntries int    `yaml:"maxCacheEntries"`
	FailureMode     string `yaml:"failureMode"`
	// StaleGracePeriod bounds how far past CacheTTL a stale entry may be served
	// when failureMode is "stale".
	StaleGracePeriod time.Duration `yaml:"staleGracePeriod"`

	Credential Credential `yaml:"credential"`
}

// Credential is the proxy's own Microsoft Graph credential. The proxy calls
// Graph as itself (client credentials), never on behalf of the caller, so no
// delegated Graph consent and no On-Behalf-Of exchange are required.
type Credential struct {
	Type     string `yaml:"type"`
	ClientID string `yaml:"clientID"`
	TenantID string `yaml:"tenantID"`
	// TokenFile holds the projected service account token used for workload
	// identity federation. Defaults to the AZURE_FEDERATED_TOKEN_FILE env var.
	TokenFile string `yaml:"tokenFile"`
	// ClientSecretEnv names the environment variable holding the client secret.
	// The secret itself is never stored in this file.
	ClientSecretEnv string `yaml:"clientSecretEnv"`
	// Scope requested from Entra ID; defaults to <graph baseURL>/.default.
	Scope string `yaml:"scope"`

	secret string
}

// Secret returns the resolved client secret, if any.
func (c *Credential) Secret() string { return c.secret }

// UserLoginTransformer optionally rewrites the login resolved from the token
// claims before it is logged and forwarded upstream.
type UserLoginTransformer struct {
	MatchRegexp   string `yaml:"matchRegexp"`
	ReplaceRegexp string `yaml:"replaceRegexp"`
}

// DCR configures the dynamic client registration shim.
type DCR struct {
	Enabled          bool   `yaml:"enabled"`
	StaticClientID   string `yaml:"staticClientID"`
	MirrorASMetadata *bool  `yaml:"mirrorAuthorizationServerMetadata"`
}

// Policy is the MCP tool authorization policy, evaluated first-match-wins.
type Policy struct {
	DefaultEffect string `yaml:"defaultEffect"`
	// RulesFile optionally loads rules from a second file so that the policy can
	// live in its own ConfigMap. Inline rules and a rules file are mutually exclusive.
	RulesFile string `yaml:"rulesFile"`
	Rules     []Rule `yaml:"rules"`
}

// RulesPath resolves the policy rules file against the configuration directory.
func (c *Config) RulesPath() string {
	f := c.Authorization.Policy.RulesFile
	if f == "" || filepath.IsAbs(f) {
		return f
	}
	return filepath.Join(c.dir, f)
}

// Rule grants or denies MCP methods and tools to members of the listed groups.
type Rule struct {
	Name    string   `yaml:"name"`
	Effect  string   `yaml:"effect"`
	Methods []string `yaml:"methods"`
	Tools   []string `yaml:"tools"`
	// Groups are group object ids or "name:<displayName>" aliases.
	Groups []string `yaml:"groups"`
	// Roles apply to app-only callers, which have no group membership.
	Roles []string `yaml:"roles"`
	// Unauthenticated marks a rule that also applies before a token is validated.
	AppOnly bool `yaml:"appOnly"`
}

// Log configures structured logging.
type Log struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// Load reads and validates the YAML configuration at path. When path is empty
// the CONFIG_FILE environment variable is consulted.
func Load(path string) (*Config, error) {
	if path == "" {
		path = os.Getenv(ConfigFileEnv)
	}
	if path == "" {
		return nil, fmt.Errorf("no configuration file supplied (use --config or %s)", ConfigFileEnv)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read configuration: %w", err)
	}
	return Parse(raw, filepath.Dir(path))
}

// Parse decodes and validates a YAML configuration document. dir is used to
// resolve a relative policy rulesFile.
func Parse(raw []byte, dir string) (*Config, error) {
	c := &Config{dir: dir}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("parse configuration: %w", err)
	}
	if err := c.applyDefaults(); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) applyDefaults() error {
	s := &c.Server
	if s.ListenAddr == "" {
		s.ListenAddr = defaultListenAddr
	}
	if s.MetricsAddr == "" {
		s.MetricsAddr = defaultMetricsAddr
	}
	if s.MaxBodyBytes == 0 {
		s.MaxBodyBytes = 4 << 20
	}
	if s.MaxGroupsHeaderBytes == 0 {
		s.MaxGroupsHeaderBytes = 2048
	}

	if c.Upstream.URL == "" {
		c.Upstream.URL = defaultUpstream
	}
	u, err := url.Parse(c.Upstream.URL)
	if err != nil {
		return fmt.Errorf("upstream.url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("upstream.url must be http or https, got %q", u.Scheme)
	}
	c.Upstream.parsed = u

	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	c.Log.Level = strings.ToLower(c.Log.Level)
	if c.Log.Format == "" {
		c.Log.Format = "json"
	}
	c.Log.Format = strings.ToLower(c.Log.Format)

	o := &c.Authorization.OAuth2
	if o.ResourceName == "" {
		o.ResourceName = "MCP Server"
	}
	if o.DCR.MirrorASMetadata == nil {
		t := true
		o.DCR.MirrorASMetadata = &t
	}

	for i := range o.OAuth2Clients {
		if err := o.OAuth2Clients[i].applyDefaults(); err != nil {
			return fmt.Errorf("authorization.oauth2.oauth2Client[%d]: %w", i, err)
		}
	}

	// For the application-permission flow the credential defaults to the first
	// application's tenant, which is the only tenant it could read anyway. For
	// On-Behalf-Of it defaults to the client id of the application resolving
	// groups, because only that application may exchange the inbound token.
	var defaultTenant, defaultClient string
	for i := range o.OAuth2Clients {
		if o.OAuth2Clients[i].GroupsSource != GroupsSourceGraph {
			continue
		}
		defaultTenant = o.OAuth2Clients[i].TenantID
		defaultClient = o.OAuth2Clients[i].ClientID
		break
	}
	if defaultTenant == "" && len(o.OAuth2Clients) > 0 {
		defaultTenant = o.OAuth2Clients[0].TenantID
	}
	if err := o.Graph.applyDefaults(defaultTenant, defaultClient); err != nil {
		return fmt.Errorf("authorization.oauth2.graph: %w", err)
	}

	p := &c.Authorization.Policy
	if p.DefaultEffect == "" {
		p.DefaultEffect = "deny"
	}
	p.DefaultEffect = strings.ToLower(p.DefaultEffect)
	for i := range p.Rules {
		if p.Rules[i].Effect == "" {
			p.Rules[i].Effect = "allow"
		}
		p.Rules[i].Effect = strings.ToLower(p.Rules[i].Effect)
	}
	return nil
}

func (cl *OAuth2Client) applyDefaults() error {
	if cl.Authority == "" {
		cl.Authority = defaultAuthority
	}
	cl.Authority = strings.TrimRight(cl.Authority, "/")

	if cl.TenantID == "" && cl.Issuer != "" {
		// Derive the tenant from an issuer of the form {authority}/{tid}/v2.0.
		parts := strings.Split(strings.Trim(strings.TrimSuffix(cl.Issuer, "/v2.0"), "/"), "/")
		if len(parts) > 0 {
			cl.TenantID = parts[len(parts)-1]
		}
	}
	if cl.Issuer == "" && cl.TenantID != "" {
		cl.Issuer = fmt.Sprintf("%s/%s/v2.0", cl.Authority, cl.TenantID)
	}

	if len(cl.Audience) == 0 && cl.ClientID != "" {
		cl.Audience = []string{cl.ClientID, "api://" + cl.ClientID}
	}
	if cl.UserLoginClaim == "" {
		cl.UserLoginClaim = "preferred_username"
	}
	if cl.GroupsClaim == "" {
		cl.GroupsClaim = "groups"
	}
	if cl.GroupsSource == "" {
		cl.GroupsSource = GroupsSourceGraph
	}
	if cl.AcceptV1Tokens == nil {
		t := true
		cl.AcceptV1Tokens = &t
	}
	if cl.ClockSkew == 0 {
		cl.ClockSkew = 60 * time.Second
	}
	if cl.JWKSRefresh == 0 {
		cl.JWKSRefresh = 15 * time.Minute
	}
	if cl.JWKSTimeout == 0 {
		cl.JWKSTimeout = 10 * time.Second
	}
	return nil
}

func (g *Graph) applyDefaults(tenantID, clientID string) error {
	if g.Flow == "" {
		g.Flow = GraphFlowAppPermission
	}
	g.Flow = strings.ToLower(g.Flow)
	if g.BaseURL == "" {
		g.BaseURL = defaultGraphURL
	}
	g.BaseURL = strings.TrimRight(g.BaseURL, "/")
	if _, err := url.Parse(g.BaseURL); err != nil {
		return fmt.Errorf("graph.baseURL: %w", err)
	}
	if g.Timeout == 0 {
		g.Timeout = 10 * time.Second
	}
	if g.CacheTTL == 0 {
		g.CacheTTL = 10 * time.Minute
	}
	if g.NegativeCacheTTL == 0 {
		g.NegativeCacheTTL = 30 * time.Second
	}
	if g.MaxCacheEntries == 0 {
		g.MaxCacheEntries = 10000
	}
	if g.FailureMode == "" {
		g.FailureMode = FailureModeClosed
	}
	g.FailureMode = strings.ToLower(g.FailureMode)
	if g.StaleGracePeriod == 0 {
		g.StaleGracePeriod = time.Hour
	}

	cr := &g.Credential
	if cr.Type == "" {
		cr.Type = CredentialFederated
	}
	cr.Type = strings.ToLower(cr.Type)
	if cr.TenantID == "" {
		cr.TenantID = tenantID
	}
	if cr.ClientID == "" && g.Flow == GraphFlowOBO {
		// On-Behalf-Of can only be performed by the application the inbound
		// token was issued for, so there is exactly one correct value.
		cr.ClientID = clientID
	}
	if cr.ClientID == "" {
		cr.ClientID = os.Getenv("AZURE_CLIENT_ID")
	}
	if cr.TokenFile == "" {
		cr.TokenFile = os.Getenv("AZURE_FEDERATED_TOKEN_FILE")
	}
	if cr.Scope == "" {
		cr.Scope = g.BaseURL + "/.default"
	}
	if cr.ClientSecretEnv != "" {
		cr.secret = os.Getenv(cr.ClientSecretEnv)
	}
	return nil
}

func (c *Config) validate() error {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	o := &c.Authorization.OAuth2

	if o.Resource == "" {
		add("authorization.oauth2.resource is required (canonical https URI of this MCP server)")
	} else if u, err := url.Parse(o.Resource); err != nil || u.Scheme == "" || u.Host == "" || u.Fragment != "" {
		add("authorization.oauth2.resource must be an absolute URI without a fragment")
	}

	if len(o.OAuth2Clients) == 0 {
		add("authorization.oauth2.oauth2Client must list at least one Entra ID application")
	}

	// AllowGroups is the only coarse gate once scopes are no longer consulted.
	// An empty list would admit every authenticated user in the tenant.
	if len(o.AllowGroups) == 0 {
		add("authorization.oauth2.allowGroups is required and must not be empty")
	}
	if o.AllowAppOnly && len(o.AllowRoles) == 0 {
		add("authorization.oauth2.allowRoles is required when allowAppOnly is true, because app-only tokens have no group membership")
	}
	if !o.AllowAppOnly && len(o.AllowRoles) > 0 {
		add("authorization.oauth2.allowRoles is set but allowAppOnly is false")
	}

	seen := map[string]int{}
	for i := range o.OAuth2Clients {
		cl := &o.OAuth2Clients[i]
		prefix := fmt.Sprintf("authorization.oauth2.oauth2Client[%d]", i)
		if cl.TenantID == "" {
			add("%s.tenantID is required", prefix)
		}
		if cl.ClientID == "" {
			add("%s.clientID is required", prefix)
		}
		if len(cl.Audience) == 0 {
			add("%s.audience is required", prefix)
		}
		switch cl.GroupsSource {
		case GroupsSourceGraph, GroupsSourceJWT:
		default:
			add("%s.groupsSource must be %q or %q, got %q", prefix, GroupsSourceGraph, GroupsSourceJWT, cl.GroupsSource)
		}
		if cl.GroupsSource == GroupsSourceGraph {
			switch o.Graph.Flow {
			case GraphFlowOBO:
				// On-Behalf-Of is performed by the application the inbound
				// token was issued for, so the exchange can only be done with
				// that application's own client id. The caller's tenant is
				// used for the exchange, so tenants other than the
				// credential's are fine here.
				if cl.ClientID != "" && o.Graph.Credential.ClientID != "" &&
					!strings.EqualFold(cl.ClientID, o.Graph.Credential.ClientID) {
					add("%s.clientID %q differs from authorization.oauth2.graph.credential.clientID %q; "+
						"the On-Behalf-Of exchange can only be performed by the application the inbound token was "+
						"issued for, so both must name the same application (or leave the credential's clientID unset)",
						prefix, cl.ClientID, o.Graph.Credential.ClientID)
				}
			default:
				// One shared app-only credential can only read its own
				// directory, so a tenant whose users live elsewhere has to
				// fall back to the groups claim.
				if cl.TenantID != "" && o.Graph.Credential.TenantID != "" &&
					!strings.EqualFold(cl.TenantID, o.Graph.Credential.TenantID) {
					add("%s.tenantID %q differs from authorization.oauth2.graph.credential.tenantID %q; "+
						"the shared Graph credential cannot read another tenant's directory, so set groupsSource: %s "+
						"for this application, or use graph.flow: %s which exchanges the caller's own token",
						prefix, cl.TenantID, o.Graph.Credential.TenantID, GroupsSourceJWT, GraphFlowOBO)
				}
			}
		}
		if cl.TenantID != "" {
			key := strings.ToLower(cl.TenantID)
			if prev, dup := seen[key]; dup {
				add("%s.tenantID duplicates oauth2Client[%d]", prefix, prev)
			}
			seen[key] = i
		}
		if isMultiTenantAlias(cl.TenantID) {
			add("%s.tenantID must be a concrete tenant id; %q would trust every Entra tenant", prefix, cl.TenantID)
		}
	}

	if c.Authorization.Policy.DefaultEffect != "allow" && c.Authorization.Policy.DefaultEffect != "deny" {
		add("authorization.policy.defaultEffect must be allow or deny, got %q", c.Authorization.Policy.DefaultEffect)
	}
	if c.Authorization.Policy.RulesFile != "" && len(c.Authorization.Policy.Rules) > 0 {
		add("authorization.policy: rulesFile and inline rules are mutually exclusive")
	}

	if (c.Server.TLSCertFile == "") != (c.Server.TLSKeyFile == "") {
		add("server.tlsCertFile and server.tlsKeyFile must be set together")
	}
	if c.Server.MaxBodyBytes <= 0 {
		add("server.maxBodyBytes must be positive")
	}
	if o.DCR.Enabled && o.DCR.StaticClientID == "" {
		add("authorization.oauth2.dynamicClientRegistration.staticClientID is required when the shim is enabled")
	}

	if o.UsesGraph() {
		if err := o.Graph.validate(); err != nil {
			add("authorization.oauth2.graph: %s", err)
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("invalid configuration:\n  - %s", strings.Join(problems, "\n  - "))
	}

	if len(o.ScopesSupported) == 0 {
		o.ScopesSupported = defaultScopes(o.OAuth2Clients[0].Audience[0])
	}
	return nil
}

// UsesGraph reports whether any configured application resolves groups from the
// directory, and therefore whether the Graph credential is required at all.
func (o *OAuth2) UsesGraph() bool {
	for i := range o.OAuth2Clients {
		if o.OAuth2Clients[i].GroupsSource == GroupsSourceGraph {
			return true
		}
	}
	return false
}

func (g *Graph) validate() error {
	switch g.Flow {
	case GraphFlowAppPermission, GraphFlowOBO:
	default:
		return fmt.Errorf("graph.flow must be %q or %q", GraphFlowAppPermission, GraphFlowOBO)
	}
	switch g.FailureMode {
	case FailureModeClosed, FailureModeStale:
	default:
		return fmt.Errorf("failureMode must be %q or %q, got %q", FailureModeClosed, FailureModeStale, g.FailureMode)
	}
	cr := &g.Credential
	if cr.ClientID == "" {
		return fmt.Errorf("credential.clientID is required (set it, or AZURE_CLIENT_ID)")
	}
	if cr.TenantID == "" {
		return fmt.Errorf("credential.tenantID is required")
	}
	switch cr.Type {
	case CredentialFederated:
		if cr.TokenFile == "" {
			return fmt.Errorf("credential.tokenFile is required for workload identity federation (set it, or AZURE_FEDERATED_TOKEN_FILE)")
		}
	case CredentialSecret:
		if cr.ClientSecretEnv == "" {
			return fmt.Errorf("credential.clientSecretEnv is required for a secret credential")
		}
		if cr.secret == "" {
			return fmt.Errorf("environment variable %s named by credential.clientSecretEnv is empty", cr.ClientSecretEnv)
		}
	default:
		return fmt.Errorf("credential.type must be %q or %q, got %q", CredentialFederated, CredentialSecret, cr.Type)
	}
	return nil
}

// isMultiTenantAlias reports whether the tenant identifier is an Entra meta-tenant.
// Accepting one would mean trusting every tenant in the world, so it is rejected.
func isMultiTenantAlias(tenant string) bool {
	switch strings.ToLower(tenant) {
	case "common", "organizations", "consumers":
		return true
	}
	return false
}

// ClientFor returns the trusted application registration for a tenant id.
func (o *OAuth2) ClientFor(tenantID string) *OAuth2Client {
	for i := range o.OAuth2Clients {
		if strings.EqualFold(o.OAuth2Clients[i].TenantID, tenantID) {
			return &o.OAuth2Clients[i]
		}
	}
	return nil
}

// OpenIDConfigurationURL is the Entra ID v2 discovery document for the client's tenant.
func (cl *OAuth2Client) OpenIDConfigurationURL() string {
	return fmt.Sprintf("%s/%s/v2.0/.well-known/openid-configuration", cl.Authority, cl.TenantID)
}

// TokenEndpoint is the Entra ID v2 token endpoint used for the client credentials grant.
func (cl *OAuth2Client) TokenEndpoint() string {
	return fmt.Sprintf("%s/%s/oauth2/v2.0/token", cl.Authority, cl.TenantID)
}

// AuthorizationServer is the issuer identifier advertised to MCP clients.
func (o *OAuth2) AuthorizationServer() string {
	if len(o.OAuth2Clients) == 0 {
		return ""
	}
	return o.OAuth2Clients[0].Issuer
}

// defaultScopes derives a scopes_supported value. Entra ID ignores the RFC 8707
// resource parameter, so clients must request `<app-id-uri>/<scope>`.
func defaultScopes(audience string) []string {
	return []string{strings.TrimRight(audience, "/") + "/.default"}
}
