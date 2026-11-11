package graph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/example/mcp-oauth-proxy/internal/config"
)

// Group is an Entra ID security or Microsoft 365 group.
type Group struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

// HTTPError is a non-2xx response from Entra ID or Microsoft Graph.
type HTTPError struct {
	Status     int
	RetryAfter time.Duration
	Message    string
}

func (e *HTTPError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("graph returned HTTP %d", e.Status)
	}
	return fmt.Sprintf("graph returned HTTP %d: %s", e.Status, e.Message)
}

// Throttled reports whether Graph asked the caller to back off.
func (e *HTTPError) Throttled() bool {
	return e.Status == http.StatusTooManyRequests || e.Status == http.StatusServiceUnavailable
}

// Caller identifies the user whose membership is being read. Assertion carries
// the caller's own access token and is used only by the On-Behalf-Of flow.
type Caller struct {
	TenantID  string
	UserID    string
	Assertion string
}

// Client is a minimal Microsoft Graph client scoped to directory reads.
type Client struct {
	flow       string
	authority  string
	baseURL    string
	tokens     *tokenSource
	httpClient *http.Client
	now        func() time.Time
	// maxPages bounds pagination so a pathological directory cannot pin the
	// request to Graph indefinitely.
	maxPages int
}

// NewClient builds the Graph client. authority is the Entra ID login host the
// credential authenticates against. Under the application-permission flow the
// credential is shared by every application registration, because the proxy
// calls Graph as itself; under On-Behalf-Of it is the application the inbound
// token was issued for.
func NewClient(authority string, g *config.Graph) *Client {
	hc := &http.Client{Timeout: g.Timeout}
	cred := &g.Credential
	authority = strings.TrimRight(authority, "/")
	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token", authority, cred.TenantID)
	return &Client{
		flow:       g.Flow,
		authority:  authority,
		baseURL:    g.BaseURL,
		tokens:     newTokenSource(endpoint, cred, hc, time.Now),
		httpClient: hc,
		now:        time.Now,
		maxPages:   50,
	}
}

// TransitiveMemberOf returns every group the user is a member of, directly or
// through nesting. Transitive membership matters: a user granted access through
// a parent group would be invisible to the direct /memberOf endpoint.
//
// The result is filtered to microsoft.graph.group so that directory roles and
// administrative units, which the memberOf endpoints also return, can never be
// mistaken for a group in a policy rule.
func (c *Client) TransitiveMemberOf(ctx context.Context, caller Caller) ([]Group, error) {
	var next string
	if c.flow == config.GraphFlowOBO {
		// The exchanged token already identifies the user, so /me is both
		// sufficient and the only form the caller's own rights permit.
		next = c.baseURL + "/v1.0/me/transitiveMemberOf/microsoft.graph.group?$select=id,displayName&$top=999"
	} else {
		if caller.UserID == "" {
			return nil, errors.New("user object id is empty")
		}
		next = fmt.Sprintf("%s/v1.0/users/%s/transitiveMemberOf/microsoft.graph.group?$select=id,displayName&$top=999",
			c.baseURL, url.PathEscape(caller.UserID))
	}

	var out []Group
	for page := 0; next != "" && page < c.maxPages; page++ {
		body, err := c.get(ctx, next, caller)
		if err != nil {
			return nil, err
		}
		var resp struct {
			Value    []Group `json:"value"`
			NextLink string  `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("parse graph response: %w", err)
		}
		for _, g := range resp.Value {
			if g.ID != "" {
				out = append(out, g)
			}
		}
		next = resp.NextLink
	}
	if next != "" {
		return nil, fmt.Errorf("group membership exceeded %d pages", c.maxPages)
	}
	return out, nil
}

// GroupsByDisplayName looks up groups with an exact display name. Display names
// are neither unique nor immutable in Entra ID, so this only ever translates an
// operator-friendly alias into the object id that authorization is keyed on.
//
// Under app_permission the lookup uses the proxy's own token and caller is
// ignored. Under obo it is made with the caller's exchanged token, which is why
// aliases resolve on first use rather than at startup.
func (c *Client) GroupsByDisplayName(ctx context.Context, caller Caller, name string) ([]Group, error) {
	// OData string literals escape a single quote by doubling it.
	literal := strings.ReplaceAll(name, "'", "''")
	q := url.Values{
		"$select": {"id,displayName"},
		"$filter": {fmt.Sprintf("displayName eq '%s'", literal)},
		"$top":    {"10"},
	}
	if c.flow != config.GraphFlowOBO {
		caller = Caller{}
	} else if caller.Assertion == "" {
		return nil, fmt.Errorf("looking a group up by display name under graph.flow: %s needs a caller's "+
			"token to exchange, and none was supplied", config.GraphFlowOBO)
	}
	body, err := c.get(ctx, c.baseURL+"/v1.0/groups?"+q.Encode(), caller)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Value []Group `json:"value"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse graph response: %w", err)
	}
	return resp.Value, nil
}

func (c *Client) get(ctx context.Context, uri string, caller Caller) ([]byte, error) {
	body, err := c.doAuthorized(ctx, uri, caller)
	var he *HTTPError
	// A 401 after a credential rotation is recoverable: drop the cached
	// application token and retry exactly once. On-Behalf-Of tokens are not
	// cached, so there is nothing to retry there.
	if c.flow != config.GraphFlowOBO && errors.As(err, &he) && he.Status == http.StatusUnauthorized {
		c.tokens.forget()
		return c.doAuthorized(ctx, uri, caller)
	}
	return body, err
}

// graphToken obtains the token used to read the directory: the proxy's own
// application token, or one exchanged for the caller's.
func (c *Client) graphToken(ctx context.Context, caller Caller) (string, error) {
	if c.flow != config.GraphFlowOBO {
		return c.tokens.Token(ctx)
	}
	// The exchange runs against the caller's own tenant, which is what lets
	// this flow serve tenants the proxy's credential could not read.
	tenant := caller.TenantID
	if tenant == "" {
		tenant = c.tokens.cred.TenantID
	}
	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token", c.authority, tenant)
	return c.tokens.exchange(ctx, endpoint, caller.Assertion)
}

func (c *Client) doAuthorized(ctx context.Context, uri string, caller Caller) ([]byte, error) {
	token, err := c.graphToken(ctx, caller)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	// ConsistencyLevel is required for advanced directory queries and is
	// harmless for the simple ones.
	req.Header.Set("ConsistencyLevel", "eventual")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call graph: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("read graph response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPError{
			Status:     resp.StatusCode,
			RetryAfter: retryAfter(resp.Header, c.now()),
			Message:    graphErrorMessage(body),
		}
	}
	return body, nil
}

// retryAfter interprets the Retry-After header, which Graph sends as either a
// delay in seconds or an HTTP date.
func retryAfter(h http.Header, now time.Time) time.Duration {
	raw := strings.TrimSpace(h.Get("Retry-After"))
	if raw == "" {
		return 0
	}
	if secs, err := strconv.Atoi(raw); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if when, err := http.ParseTime(raw); err == nil {
		if d := when.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

func graphErrorMessage(body []byte) string {
	var e struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error.Code != "" {
		return e.Error.Code + ": " + e.Error.Message
	}
	return strings.TrimSpace(string(body))
}
