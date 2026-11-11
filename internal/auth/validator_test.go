package auth_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/example/mcp-oauth-proxy/internal/auth"
	"github.com/example/mcp-oauth-proxy/internal/config"
	"github.com/example/mcp-oauth-proxy/internal/graph"
	"github.com/example/mcp-oauth-proxy/internal/testsupport"
)

func logger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// groupSourceFunc adapts a function to auth.GroupSource.
type groupSourceFunc func(ctx context.Context, caller graph.Caller) ([]graph.Group, error)

func (f groupSourceFunc) Groups(ctx context.Context, caller graph.Caller) ([]graph.Group, error) {
	return f(ctx, caller)
}

type fixture struct {
	entra     *testsupport.Entra
	validator *auth.Validator
	dir       *testsupport.Directory
}

type options struct {
	allowGroups  []string
	allowRoles   []string
	allowAppOnly bool
	groupsSource string
	transformer  config.UserLoginTransformer
	groupSource  auth.GroupSource
	clientIDs    []string
}

func newFixture(t *testing.T, opt options) *fixture {
	t.Helper()
	entra := testsupport.NewEntra(t)
	dir := testsupport.NewDirectory()

	if opt.groupsSource == "" {
		opt.groupsSource = config.GroupsSourceGraph
	}
	if len(opt.allowGroups) == 0 {
		opt.allowGroups = []string{testsupport.GroupAdmins}
	}

	cl := &config.OAuth2Client{
		Authority:        entra.URL,
		TenantID:         testsupport.Tenant,
		ClientID:         "22222222-2222-2222-2222-222222222222",
		Audience:         []string{testsupport.Audience},
		AllowedClientIDs: opt.clientIDs,
		UserLoginClaim:   "preferred_username",
		GroupsClaim:      "groups",
		GroupsSource:     opt.groupsSource,
		ClockSkew:        time.Minute,
		JWKSRefresh:      time.Hour,
		JWKSTimeout:      5 * time.Second,
	}
	accept := true
	cl.AcceptV1Tokens = &accept

	keys := auth.NewKeySet(cl.OpenIDConfigurationURL(), cl.JWKSTimeout, cl.JWKSRefresh, logger())
	if err := keys.Prime(context.Background()); err != nil {
		t.Fatalf("prime keys: %v", err)
	}

	var src auth.GroupSource = opt.groupSource
	if src == nil && opt.groupsSource == config.GroupsSourceGraph {
		src = groupSourceFunc(func(ctx context.Context, caller graph.Caller) ([]graph.Group, error) {
			return dir.TransitiveMemberOf(ctx, caller)
		})
	}

	oauth2 := &config.OAuth2{
		AllowGroups:          opt.allowGroups,
		AllowRoles:           opt.allowRoles,
		AllowAppOnly:         opt.allowAppOnly,
		UserLoginTransformer: opt.transformer,
	}
	v, err := auth.NewValidator(oauth2,
		map[string]*auth.TenantRuntime{
			strings.ToLower(testsupport.Tenant): auth.NewTenantRuntime(cl, keys, src),
		},
		opt.allowGroups, graph.NewAliases(dir, opt.allowGroups, graph.AliasOptions{NegativeTTL: time.Minute}), logger())
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}
	return &fixture{entra: entra, validator: v, dir: dir}
}

func (f *fixture) validate(t *testing.T, mutate ...func(jwt.MapClaims)) (*auth.Principal, *auth.Error) {
	t.Helper()
	return f.validator.Validate(context.Background(), f.entra.Token(t, mutate...))
}

func TestValidTokenResolvesGroupsFromDirectory(t *testing.T) {
	f := newFixture(t, options{})

	p, authErr := f.validate(t)
	if authErr != nil {
		t.Fatalf("validate: %v", authErr)
	}
	if p.Username != "igor@contoso.com" {
		t.Errorf("username = %q", p.Username)
	}
	if !p.HasGroup(testsupport.GroupAdmins) {
		t.Errorf("groups = %v, want the admins group from the directory", p.Groups)
	}
	if p.MatchedGroup != strings.ToLower(testsupport.GroupAdmins) {
		t.Errorf("matchedGroup = %q", p.MatchedGroup)
	}
	if f.dir.CallCount() != 1 {
		t.Errorf("directory calls = %d, want 1", f.dir.CallCount())
	}
}

// The groups claim must be ignored when the directory is the source of truth,
// otherwise a token with a forged-looking claim could influence the decision.
func TestGroupsClaimIsIgnoredWhenGraphIsTheSource(t *testing.T) {
	f := newFixture(t, options{})

	p, authErr := f.validate(t, func(c jwt.MapClaims) {
		c["groups"] = []string{testsupport.GroupOutsider}
	})
	if authErr != nil {
		t.Fatalf("validate: %v", authErr)
	}
	for _, g := range p.Groups {
		if strings.EqualFold(g, testsupport.GroupOutsider) {
			t.Fatalf("groups = %v, the token claim must not be consulted", p.Groups)
		}
	}
}

func TestUserOutsideAllowGroupsIsDenied(t *testing.T) {
	f := newFixture(t, options{allowGroups: []string{testsupport.GroupOutsider}})

	_, authErr := f.validate(t)
	if authErr == nil {
		t.Fatal("expected a denial for a user outside every allowed group")
	}
	if authErr.Status != 403 {
		t.Errorf("status = %d, want 403", authErr.Status)
	}
}

// A directory outage must fail closed, and must be reported as retryable
// rather than as a final authorization denial.
func TestDirectoryFailureFailsClosed(t *testing.T) {
	f := newFixture(t, options{
		groupSource: groupSourceFunc(func(context.Context, graph.Caller) ([]graph.Group, error) {
			return nil, errors.New("graph is unreachable")
		}),
	})

	_, authErr := f.validate(t)
	if authErr == nil {
		t.Fatal("expected a failure when group membership cannot be resolved")
	}
	if authErr.Status != 503 {
		t.Errorf("status = %d, want 503 so clients retry instead of giving up", authErr.Status)
	}
}

// Dropping delegated scopes from the model must not relax audience binding:
// the aud check is what stops a token minted for another API being replayed.
func TestWrongAudienceIsRejected(t *testing.T) {
	f := newFixture(t, options{})

	_, authErr := f.validate(t, func(c jwt.MapClaims) { c["aud"] = "api://some-other-api" })
	if authErr == nil {
		t.Fatal("expected a token for another audience to be rejected")
	}
	if authErr.Code != auth.CodeInvalidToken {
		t.Errorf("code = %q, want %q", authErr.Code, auth.CodeInvalidToken)
	}
}

func TestTokenWithoutScopesIsStillAccepted(t *testing.T) {
	f := newFixture(t, options{})

	// Scopes play no part in the decision; group membership alone governs access.
	if _, authErr := f.validate(t, func(c jwt.MapClaims) { delete(c, "scp") }); authErr != nil {
		t.Fatalf("validate: %v", authErr)
	}
}

func TestUntrustedTenantIsRejected(t *testing.T) {
	f := newFixture(t, options{})

	_, authErr := f.validate(t, func(c jwt.MapClaims) {
		c["tid"] = "99999999-9999-9999-9999-999999999999"
	})
	if authErr == nil {
		t.Fatal("expected a token from an unconfigured tenant to be rejected")
	}
	if !strings.Contains(authErr.Description, "untrusted tenant") {
		t.Errorf("description = %q", authErr.Description)
	}
}

func TestExpiredTokenIsRejected(t *testing.T) {
	f := newFixture(t, options{})

	_, authErr := f.validate(t, func(c jwt.MapClaims) {
		c["exp"] = time.Now().Add(-2 * time.Hour).Unix()
		c["nbf"] = time.Now().Add(-3 * time.Hour).Unix()
		c["iat"] = time.Now().Add(-3 * time.Hour).Unix()
	})
	if authErr == nil || !strings.Contains(authErr.Description, "expired") {
		t.Fatalf("authErr = %v, want an expiry failure", authErr)
	}
}

func TestTokenSignedByUnknownKeyIsRejected(t *testing.T) {
	f := newFixture(t, options{})
	other := testsupport.NewEntra(t)

	// Same claims, different signing key: the signature check must catch it.
	raw := other.Sign(t, f.entra.Claims())
	if _, authErr := f.validator.Validate(context.Background(), raw); authErr == nil {
		t.Fatal("expected a token signed by an unknown key to be rejected")
	}
}

func TestUnsignedTokenIsRejected(t *testing.T) {
	f := newFixture(t, options{})

	tok := jwt.NewWithClaims(jwt.SigningMethodNone, f.entra.Claims())
	raw, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, authErr := f.validator.Validate(context.Background(), raw); authErr == nil {
		t.Fatal("expected an alg=none token to be rejected")
	}
}

func TestDisallowedClientIsRejected(t *testing.T) {
	f := newFixture(t, options{clientIDs: []string{"44444444-4444-4444-4444-444444444444"}})

	_, authErr := f.validate(t)
	if authErr == nil || authErr.Status != 403 {
		t.Fatalf("authErr = %v, want a 403 for an unlisted client application", authErr)
	}
}

func TestAppOnlyTokenRejectedByDefault(t *testing.T) {
	f := newFixture(t, options{})

	_, authErr := f.validate(t, appOnly)
	if authErr == nil {
		t.Fatal("expected an app-only token to be rejected when allowAppOnly is false")
	}
	if !strings.Contains(authErr.Description, "app-only") {
		t.Errorf("description = %q", authErr.Description)
	}
}

// App-only callers have no user and therefore no group membership, so they are
// authorized on an application role instead.
func TestAppOnlyTokenAcceptedWithRole(t *testing.T) {
	f := newFixture(t, options{allowAppOnly: true, allowRoles: []string{"Mcp.Invoke"}})

	p, authErr := f.validate(t, appOnly, func(c jwt.MapClaims) {
		c["roles"] = []string{"Mcp.Invoke"}
	})
	if authErr != nil {
		t.Fatalf("validate: %v", authErr)
	}
	if !p.AppOnly {
		t.Error("principal should be marked app-only")
	}
	if f.dir.CallCount() != 0 {
		t.Errorf("directory calls = %d, want 0; an app-only token has no user to look up", f.dir.CallCount())
	}
}

func TestAppOnlyTokenWithoutRoleIsRejected(t *testing.T) {
	f := newFixture(t, options{allowAppOnly: true, allowRoles: []string{"Mcp.Invoke"}})

	_, authErr := f.validate(t, appOnly)
	if authErr == nil || authErr.Status != 403 {
		t.Fatalf("authErr = %v, want a 403 for a missing app role", authErr)
	}
}

func TestGroupsClaimSourceUsesToken(t *testing.T) {
	f := newFixture(t, options{
		groupsSource: config.GroupsSourceJWT,
		allowGroups:  []string{testsupport.GroupReaders},
	})

	p, authErr := f.validate(t, func(c jwt.MapClaims) {
		c["groups"] = []string{testsupport.GroupReaders}
	})
	if authErr != nil {
		t.Fatalf("validate: %v", authErr)
	}
	if !p.HasGroup(testsupport.GroupReaders) {
		t.Errorf("groups = %v", p.Groups)
	}
	if f.dir.CallCount() != 0 {
		t.Errorf("directory calls = %d, want 0 when groupsSource is jwt", f.dir.CallCount())
	}
}

func TestUserLoginTransformer(t *testing.T) {
	f := newFixture(t, options{
		transformer: config.UserLoginTransformer{
			MatchRegexp:   `^([^@]+)@(.*)$`,
			ReplaceRegexp: `a-${1}@${2}`,
		},
	})

	p, authErr := f.validate(t)
	if authErr != nil {
		t.Fatalf("validate: %v", authErr)
	}
	if p.Username != "a-igor@contoso.com" {
		t.Errorf("username = %q, want a-igor@contoso.com", p.Username)
	}
}

func TestBearerToken(t *testing.T) {
	cases := []struct {
		header string
		want   string
		ok     bool
	}{
		{"Bearer abc.def.ghi", "abc.def.ghi", true},
		{"bearer abc", "abc", true},
		{"", "", false},
		{"Basic dXNlcjpwYXNz", "", false},
		{"Bearer ", "", false},
	}
	for _, tc := range cases {
		got, err := auth.BearerToken(tc.header)
		if tc.ok != (err == nil) {
			t.Errorf("BearerToken(%q) error = %v, wantOK %v", tc.header, err, tc.ok)
			continue
		}
		if got != tc.want {
			t.Errorf("BearerToken(%q) = %q, want %q", tc.header, got, tc.want)
		}
	}
}

// appOnly turns the default delegated claim set into a client-credentials one.
func appOnly(c jwt.MapClaims) {
	delete(c, "scp")
	delete(c, "preferred_username")
	delete(c, "name")
	delete(c, "oid")
	c["idtyp"] = "app"
	c["appid"] = testsupport.ClientID
}
