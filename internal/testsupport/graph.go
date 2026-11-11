package testsupport

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/example/mcp-oauth-proxy/internal/graph"
)

// Well-known group object ids used across the test suites.
const (
	GroupAdmins   = "aaaaaaaa-0000-0000-0000-000000000001"
	GroupReaders  = "aaaaaaaa-0000-0000-0000-000000000002"
	GroupOutsider = "aaaaaaaa-0000-0000-0000-000000000003"
	UserObjectID  = "user-object-id"
)

// Directory is an in-memory stand-in for Microsoft Graph. It records call
// counts so tests can assert that caching and request coalescing work.
type Directory struct {
	mu sync.Mutex

	// Members maps a user object id to that user's transitive groups.
	Members map[string][]graph.Group
	// ByName maps a display name to the groups that carry it, so ambiguity and
	// absence can both be exercised.
	ByName map[string][]graph.Group

	// Err, when set, is returned by TransitiveMemberOf instead of a result.
	Err error
	// Delay blocks TransitiveMemberOf until the channel is closed, which lets a
	// test hold a lookup open while other callers pile up behind it.
	Delay chan struct{}

	Calls       int
	NameCalls   int
	NameCallers []graph.Caller
	NameErr     error
}

// NewDirectory builds a directory where the standard test user is a member of
// the admins and readers groups.
func NewDirectory() *Directory {
	return &Directory{
		Members: map[string][]graph.Group{
			UserObjectID: {
				{ID: GroupAdmins, DisplayName: "mcp-admins"},
				{ID: GroupReaders, DisplayName: "mcp-readers"},
			},
		},
		ByName: map[string][]graph.Group{
			"mcp-admins":  {{ID: GroupAdmins, DisplayName: "mcp-admins"}},
			"mcp-readers": {{ID: GroupReaders, DisplayName: "mcp-readers"}},
			"ambiguous": {
				{ID: GroupOutsider, DisplayName: "ambiguous"},
				{ID: GroupAdmins, DisplayName: "ambiguous"},
			},
		},
	}
}

// TransitiveMemberOf implements graph.GroupLister.
func (d *Directory) TransitiveMemberOf(ctx context.Context, caller graph.Caller) ([]graph.Group, error) {
	userID := caller.UserID
	d.mu.Lock()
	delay, err := d.Delay, d.Err
	d.Calls++
	d.mu.Unlock()

	if delay != nil {
		select {
		case <-delay:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	groups, ok := d.Members[userID]
	if !ok {
		return nil, nil
	}
	return append([]graph.Group(nil), groups...), nil
}

// GroupsByDisplayName implements graph.GroupLister. The caller is recorded so
// tests can assert that the On-Behalf-Of flow supplies one.
func (d *Directory) GroupsByDisplayName(_ context.Context, caller graph.Caller, name string) ([]graph.Group, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.NameCalls++
	d.NameCallers = append(d.NameCallers, caller)
	if d.NameErr != nil {
		return nil, d.NameErr
	}
	return append([]graph.Group(nil), d.ByName[name]...), nil
}

// NameCallCount returns how many display-name lookups have been made.
func (d *Directory) NameCallCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.NameCalls
}

// LastNameCaller returns the caller supplied to the most recent display-name
// lookup, and whether there was one.
func (d *Directory) LastNameCaller() (graph.Caller, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.NameCallers) == 0 {
		return graph.Caller{}, false
	}
	return d.NameCallers[len(d.NameCallers)-1], true
}

// SetNameError makes subsequent display-name lookups fail.
func (d *Directory) SetNameError(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.NameErr = err
}

// CallCount returns how many membership lookups have been made.
func (d *Directory) CallCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.Calls
}

// SetError makes subsequent membership lookups fail.
func (d *Directory) SetError(err error) {
	d.mu.Lock()
	d.Err = err
	d.mu.Unlock()
}

// SetMembers replaces a user's group membership.
func (d *Directory) SetMembers(userID string, groups ...graph.Group) {
	d.mu.Lock()
	d.Members[userID] = groups
	d.mu.Unlock()
}

// GraphServer is a fake Microsoft Graph HTTP endpoint, including the Entra ID
// token endpoint used by the client credentials grant. It exists so the real
// graph.Client, with its pagination and throttling handling, can be exercised.
type GraphServer struct {
	mu sync.Mutex

	// Pages is the sequence of membership pages returned, in order. More than
	// one entry exercises @odata.nextLink pagination.
	Pages [][]graph.Group
	// Status, when non-zero, is returned instead of a result.
	Status int
	// RetryAfter is sent with a throttled response.
	RetryAfter string

	TokenCalls int
	DataCalls  int
}

// Handler returns the HTTP handler for the fake Graph and token endpoints.
func (g *GraphServer) Handler(tenant string) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /"+tenant+"/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.TokenCalls++
		g.mu.Unlock()
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "client_credentials" {
			http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"token_type":"Bearer","expires_in":3600,"access_token":"graph-app-token"}`)
	})

	mux.HandleFunc("GET /v1.0/users/{id}/transitiveMemberOf/microsoft.graph.group", func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.DataCalls++
		status, retryAfter, pages := g.Status, g.RetryAfter, g.Pages
		g.mu.Unlock()

		if r.Header.Get("Authorization") != "Bearer graph-app-token" {
			http.Error(w, `{"error":{"code":"InvalidAuthenticationToken","message":"bad token"}}`, http.StatusUnauthorized)
			return
		}
		if status != 0 {
			if retryAfter != "" {
				w.Header().Set("Retry-After", retryAfter)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			fmt.Fprint(w, `{"error":{"code":"throttled","message":"slow down"}}`)
			return
		}

		page := 0
		if p := r.URL.Query().Get("page"); p != "" {
			fmt.Sscanf(p, "%d", &page)
		}
		if page >= len(pages) {
			writeGroupPage(w, nil, "")
			return
		}
		next := ""
		if page+1 < len(pages) {
			u := *r.URL
			q := u.Query()
			q.Set("page", fmt.Sprint(page+1))
			u.RawQuery = q.Encode()
			next = "http://" + r.Host + u.String()
		}
		writeGroupPage(w, pages[page], next)
	})

	mux.HandleFunc("GET /v1.0/groups", func(w http.ResponseWriter, r *http.Request) {
		filter := r.URL.Query().Get("$filter")
		name := strings.Trim(strings.TrimPrefix(filter, "displayName eq "), "'")
		var found []graph.Group
		for _, page := range g.Pages {
			for _, grp := range page {
				if grp.DisplayName == name {
					found = append(found, grp)
				}
			}
		}
		writeGroupPage(w, found, "")
	})

	return mux
}

func writeGroupPage(w http.ResponseWriter, groups []graph.Group, next string) {
	w.Header().Set("Content-Type", "application/json")
	parts := make([]string, 0, len(groups))
	for _, g := range groups {
		parts = append(parts, fmt.Sprintf(`{"id":%q,"displayName":%q}`, g.ID, g.DisplayName))
	}
	body := fmt.Sprintf(`{"value":[%s]`, strings.Join(parts, ","))
	if next != "" {
		body += fmt.Sprintf(`,"@odata.nextLink":%q`, next)
	}
	body += "}"
	fmt.Fprint(w, body)
}

// Counts returns the number of token and data requests served.
func (g *GraphServer) Counts() (tokens, data int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.TokenCalls, g.DataCalls
}

// SetStatus makes subsequent membership requests fail with status.
func (g *GraphServer) SetStatus(status int, retryAfter string) {
	g.mu.Lock()
	g.Status, g.RetryAfter = status, retryAfter
	g.mu.Unlock()
}
