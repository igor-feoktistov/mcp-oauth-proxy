package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/example/mcp-oauth-proxy/internal/config"
	"github.com/example/mcp-oauth-proxy/internal/graph"
)

// Error codes from RFC 6750 used in the WWW-Authenticate challenge.
const (
	CodeInvalidRequest    = "invalid_request"
	CodeInvalidToken      = "invalid_token"
	CodeInsufficientScope = "insufficient_scope"
	CodeServerError       = "server_error"
)

// Error is an authentication/authorization failure carrying an RFC 6750 error code.
type Error struct {
	Code        string
	Description string
	Status      int
	cause       error
}

func (e *Error) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %s (%v)", e.Code, e.Description, e.cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

func (e *Error) Unwrap() error { return e.cause }

func invalidToken(desc string, cause error) *Error {
	return &Error{Code: CodeInvalidToken, Description: desc, Status: 401, cause: cause}
}

func forbidden(desc string, cause error) *Error {
	return &Error{Code: CodeInsufficientScope, Description: desc, Status: 403, cause: cause}
}

// unavailable is returned when membership cannot be determined. It is a 503
// rather than a 403 so that clients retry instead of treating the denial as final.
func unavailable(desc string, cause error) *Error {
	return &Error{Code: CodeServerError, Description: desc, Status: 503, cause: cause}
}

// misconfigured is returned when the server's own configuration is at fault. It
// is a 500 rather than a 503 because no amount of retrying will fix it, and a
// 503 would have clients retry a broken configuration indefinitely.
func misconfigured(desc string, cause error) *Error {
	return &Error{Code: CodeServerError, Description: desc, Status: 500, cause: cause}
}

// Principal is the validated caller identity.
type Principal struct {
	Subject     string
	ObjectID    string
	TenantID    string
	ClientID    string
	Username    string
	DisplayName string
	Roles       []string
	// Groups holds group object ids, sourced from Microsoft Graph (or, when
	// groupsSource is "jwt", from the token's groups claim).
	Groups []string
	// GroupNames carries display names for logging only. It is never used for
	// an authorization decision.
	GroupNames   []string
	MatchedGroup string
	Audience     string
	Issuer       string
	TokenID      string
	ExpiresAt    time.Time
	AppOnly      bool
}

// HasRole reports whether the principal holds the application role.
func (p *Principal) HasRole(r string) bool { return containsFold(p.Roles, r) }

// HasGroup reports whether the principal is a member of the group object id.
func (p *Principal) HasGroup(g string) bool { return containsFold(p.Groups, g) }

// Identity returns the most human-readable identifier available.
func (p *Principal) Identity() string {
	switch {
	case p.Username != "":
		return p.Username
	case p.ObjectID != "":
		return p.ObjectID
	default:
		return p.Subject
	}
}

type entraClaims struct {
	jwt.RegisteredClaims
	TenantID   string         `json:"tid"`
	ObjectID   string         `json:"oid"`
	Scope      string         `json:"scp"`
	Roles      []string       `json:"roles"`
	AppID      string         `json:"appid"`
	Authorized string         `json:"azp"`
	UPN        string         `json:"upn"`
	Username   string         `json:"preferred_username"`
	Name       string         `json:"name"`
	Version    string         `json:"ver"`
	UniqueName string         `json:"unique_name"`
	IDType     string         `json:"idtyp"`
	Extra      map[string]any `json:"-"`
}

// GroupSource resolves a user's group object ids.
type GroupSource interface {
	Groups(ctx context.Context, caller graph.Caller) ([]graph.Group, error)
}

// TenantRuntime is the per-tenant validation state built from one oauth2Client entry.
type TenantRuntime struct {
	cfg    *config.OAuth2Client
	keys   *KeySet
	parser *jwt.Parser
	groups GroupSource
}

// Validator verifies Entra ID access tokens and resolves the caller's groups.
type Validator struct {
	oauth2   *config.OAuth2
	tenants  map[string]*TenantRuntime
	allowed  []string // allow-listed group references, canonicalised
	aliases  *graph.Aliases
	loginRe  *regexp.Regexp
	loginSub string
	logger   *slog.Logger
}

// NewValidator builds a validator. tenants maps a lower-cased tenant id to its
// runtime; allowGroups holds the canonicalised allow-listed group references.
// aliases, which may be nil, translates display-name references on first use.
func NewValidator(oauth2 *config.OAuth2, tenants map[string]*TenantRuntime, allowGroups []string, aliases *graph.Aliases, logger *slog.Logger) (*Validator, error) {
	v := &Validator{
		oauth2:  oauth2,
		tenants: tenants,
		aliases: aliases,
		logger:  logger,
	}
	for _, g := range allowGroups {
		v.allowed = append(v.allowed, strings.ToLower(g))
	}
	t := oauth2.UserLoginTransformer
	if t.MatchRegexp != "" {
		re, err := regexp.Compile(t.MatchRegexp)
		if err != nil {
			return nil, fmt.Errorf("authorization.oauth2.userLoginTransformer.matchRegexp: %w", err)
		}
		v.loginRe, v.loginSub = re, t.ReplaceRegexp
	}
	return v, nil
}

// NewTenantRuntime assembles the per-tenant validation state.
func NewTenantRuntime(cl *config.OAuth2Client, keys *KeySet, groups GroupSource) *TenantRuntime {
	return &TenantRuntime{
		cfg:  cl,
		keys: keys,
		parser: jwt.NewParser(
			jwt.WithValidMethods([]string{"RS256", "RS384", "RS512"}),
			jwt.WithLeeway(cl.ClockSkew),
			jwt.WithExpirationRequired(),
		),
		groups: groups,
	}
}

// BearerToken extracts the credential from an Authorization header value.
func BearerToken(header string) (string, *Error) {
	if header == "" {
		return "", &Error{Code: CodeInvalidRequest, Description: "missing Authorization header", Status: 401}
	}
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "bearer") {
		return "", &Error{Code: CodeInvalidRequest, Description: "Authorization header must use the Bearer scheme", Status: 401}
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", &Error{Code: CodeInvalidRequest, Description: "empty bearer token", Status: 401}
	}
	return token, nil
}

// Validate fully verifies a raw access token and resolves the caller's groups.
//
// The token signature, issuer, tenant and audience are always checked locally
// against the tenant's JWKS. Microsoft Graph is consulted only to resolve group
// membership; it is never used as a substitute for verifying the token.
func (v *Validator) Validate(ctx context.Context, raw string) (*Principal, *Error) {
	// The tenant selects the signing keys, so read tid from the unverified
	// token first. Nothing from this parse is trusted: the claims are parsed
	// again below and the signature is verified against that tenant's keys.
	tid, err := unverifiedTenant(raw)
	if err != nil {
		return nil, invalidToken("the access token is malformed", err)
	}
	rt, ok := v.tenants[strings.ToLower(tid)]
	if !ok {
		return nil, invalidToken("the access token was issued by an untrusted tenant", fmt.Errorf("tid=%q", tid))
	}

	claims := &entraClaims{}
	token, parseErr := rt.parser.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("token header has no kid")
		}
		return rt.keys.Key(ctx, kid)
	})
	if parseErr != nil {
		switch {
		case errors.Is(parseErr, jwt.ErrTokenExpired):
			return nil, invalidToken("the access token has expired", parseErr)
		case errors.Is(parseErr, jwt.ErrTokenNotValidYet):
			return nil, invalidToken("the access token is not valid yet", parseErr)
		case errors.Is(parseErr, ErrUnknownKey):
			return nil, invalidToken("the access token was signed by an unknown key", parseErr)
		default:
			return nil, invalidToken("the access token could not be verified", parseErr)
		}
	}
	if !token.Valid {
		return nil, invalidToken("the access token is not valid", nil)
	}
	// Guard against a token whose tid differs from the one used to pick the keys.
	if !strings.EqualFold(claims.TenantID, tid) {
		return nil, invalidToken("the access token tenant claim is inconsistent", nil)
	}

	if authErr := rt.checkIssuer(claims); authErr != nil {
		return nil, authErr
	}
	if authErr := rt.checkAudience(claims); authErr != nil {
		return nil, authErr
	}
	if authErr := rt.checkClient(claims); authErr != nil {
		return nil, authErr
	}

	p := v.principalFrom(rt, claims)

	if p.AppOnly {
		if authErr := v.authorizeAppOnly(p); authErr != nil {
			return nil, authErr
		}
		return p, nil
	}
	if authErr := v.resolveGroups(ctx, rt, p, raw); authErr != nil {
		return nil, authErr
	}
	if authErr := v.applyAliases(ctx, p, raw); authErr != nil {
		return nil, authErr
	}
	if authErr := v.checkAllowGroups(p); authErr != nil {
		return nil, authErr
	}
	return p, nil
}

// applyAliases attaches the display-name labels the caller is entitled to, so
// that a rule written as "name:mcp-operators" matches.
//
// The label is derived from the object id the name resolves to in the
// directory, never from the display names the caller's own groups happen to
// carry. A user who creates a group of their own named "mcp-operators" in a
// tenant with self-service group creation therefore gains nothing.
func (v *Validator) applyAliases(ctx context.Context, p *Principal, raw string) *Error {
	if v.aliases == nil {
		return nil
	}
	labels, err := v.aliases.Labels(ctx, graph.Caller{
		TenantID:  p.TenantID,
		UserID:    p.ObjectID,
		Assertion: raw,
	}, p.Groups)
	if err != nil {
		// Failing closed here is deliberate: a name that cannot be resolved
		// must not quietly stop matching, which would silently widen or narrow
		// the policy depending on where it was used.
		var ae *graph.AliasError
		if errors.As(err, &ae) {
			desc := fmt.Sprintf("the group %q named in this server's configuration could not be resolved: %s",
				ae.Name, ae.Reason)
			if ae.Permanent {
				return misconfigured(desc, err)
			}
			return unavailable(desc, err)
		}
		return unavailable(
			"a group named in the configuration could not be resolved to an object id; the request was not authorized",
			err,
		)
	}
	p.Groups = append(p.Groups, labels...)
	return nil
}

// unverifiedTenant reads the tid claim without verifying the signature, purely
// to select which tenant's signing keys the token is then verified against.
// Nothing else is taken from this parse.
func unverifiedTenant(raw string) (string, error) {
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(raw, claims); err != nil {
		return "", err
	}
	tid, _ := claims["tid"].(string)
	if tid == "" {
		return "", errors.New("token has no tid claim")
	}
	return tid, nil
}

// checkIssuer pins the issuer to the tenant that minted the token.
func (rt *TenantRuntime) checkIssuer(c *entraClaims) *Error {
	iss := strings.TrimRight(c.Issuer, "/")
	if iss == "" {
		return invalidToken("the access token has no issuer", nil)
	}
	expected := []string{fmt.Sprintf("%s/%s/v2.0", rt.cfg.Authority, c.TenantID)}
	if rt.cfg.AcceptV1Tokens != nil && *rt.cfg.AcceptV1Tokens {
		expected = append(expected, fmt.Sprintf("https://sts.windows.net/%s", c.TenantID))
	}
	for _, e := range expected {
		if strings.EqualFold(iss, strings.TrimRight(e, "/")) {
			return nil
		}
	}
	return invalidToken("the access token issuer is not trusted", fmt.Errorf("iss=%q", c.Issuer))
}

// checkAudience enforces RFC 8707 audience binding. Dropping delegated scopes
// from the authorization model does not relax this: the audience check is what
// stops a token minted for another API in the same tenant being replayed here.
func (rt *TenantRuntime) checkAudience(c *entraClaims) *Error {
	if len(c.Audience) == 0 {
		return invalidToken("the access token has no audience", nil)
	}
	for _, aud := range c.Audience {
		if containsFold(rt.cfg.Audience, aud) {
			return nil
		}
	}
	return invalidToken(
		"the access token was not issued for this MCP server; request a token for "+rt.cfg.Audience[0],
		fmt.Errorf("aud=%v", []string(c.Audience)),
	)
}

func (rt *TenantRuntime) checkClient(c *entraClaims) *Error {
	if len(rt.cfg.AllowedClientIDs) == 0 {
		return nil
	}
	for _, id := range []string{c.Authorized, c.AppID} {
		if id != "" && containsFold(rt.cfg.AllowedClientIDs, id) {
			return nil
		}
	}
	return forbidden("the calling application is not permitted to access this MCP server", nil)
}

// resolveGroups populates the principal's group object ids. raw is the caller's
// own access token, needed only by the On-Behalf-Of flow, which exchanges it
// for a Graph token rather than calling Graph as the proxy itself.
func (v *Validator) resolveGroups(ctx context.Context, rt *TenantRuntime, p *Principal, raw string) *Error {
	if rt.cfg.GroupsSource == config.GroupsSourceJWT {
		// The groups claim already carries object ids.
		return nil
	}
	if rt.groups == nil {
		return unavailable("group membership cannot be resolved: no directory client is configured", nil)
	}
	groups, err := rt.groups.Groups(ctx, graph.Caller{
		TenantID:  p.TenantID,
		UserID:    p.ObjectID,
		Assertion: raw,
	})
	if err != nil {
		return unavailable(
			"group membership could not be resolved from the directory; the request was not authorized",
			err,
		)
	}
	p.Groups = make([]string, 0, len(groups))
	p.GroupNames = make([]string, 0, len(groups))
	for _, g := range groups {
		p.Groups = append(p.Groups, strings.ToLower(g.ID))
		if g.DisplayName != "" {
			p.GroupNames = append(p.GroupNames, g.DisplayName)
		}
	}
	return nil
}

// checkAllowGroups applies the mandatory coarse gate. It is the only thing
// standing between an authenticated tenant user and the MCP server, so an empty
// allow list is rejected at configuration load rather than treated as "allow all".
func (v *Validator) checkAllowGroups(p *Principal) *Error {
	for _, want := range v.allowed {
		if p.HasGroup(want) {
			p.MatchedGroup = want
			return nil
		}
	}
	return forbidden(
		fmt.Sprintf("user %s is not a member of any group permitted to access this MCP server", p.Identity()),
		nil,
	)
}

// authorizeAppOnly admits daemon callers, which have no user and therefore no
// group membership, on the strength of an application role instead.
func (v *Validator) authorizeAppOnly(p *Principal) *Error {
	if !v.oauth2.AllowAppOnly {
		return forbidden(
			"app-only tokens are not accepted by this MCP server; authenticate as a user so group membership can be resolved",
			nil,
		)
	}
	for _, want := range v.oauth2.AllowRoles {
		if p.HasRole(want) {
			return nil
		}
	}
	return forbidden(
		"the calling application is missing a required app role: "+strings.Join(v.oauth2.AllowRoles, ", "),
		nil,
	)
}

func (v *Validator) principalFrom(rt *TenantRuntime, c *entraClaims) *Principal {
	username := firstNonEmpty(c.Username, c.UPN, c.UniqueName)
	if claimed := c.stringClaim(rt.cfg.UserLoginClaim); claimed != "" {
		username = claimed
	}
	username = v.transformLogin(username)

	p := &Principal{
		Subject:     c.Subject,
		ObjectID:    c.ObjectID,
		TenantID:    c.TenantID,
		ClientID:    firstNonEmpty(c.Authorized, c.AppID),
		Username:    username,
		DisplayName: c.Name,
		Roles:       c.Roles,
		Issuer:      c.Issuer,
		TokenID:     c.ID,
	}
	if rt.cfg.GroupsSource == config.GroupsSourceJWT {
		for _, g := range c.stringsClaim(rt.cfg.GroupsClaim) {
			p.Groups = append(p.Groups, strings.ToLower(g))
		}
	}
	if len(c.Audience) > 0 {
		p.Audience = c.Audience[0]
	}
	if c.ExpiresAt != nil {
		p.ExpiresAt = c.ExpiresAt.Time
	}
	// An access token with no user identity and no delegated scope is app-only.
	p.AppOnly = strings.EqualFold(c.IDType, "app") ||
		(c.ObjectID == "" && username == "") ||
		(c.Scope == "" && username == "")
	return p
}

// transformLogin applies the optional userLoginTransformer, which lets the
// login carried in the token be rewritten to the form downstream systems expect.
func (v *Validator) transformLogin(login string) string {
	if login == "" || v.loginRe == nil || !v.loginRe.MatchString(login) {
		return login
	}
	return v.loginRe.ReplaceAllString(login, v.loginSub)
}

func containsFold(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
