package graph

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// AliasPrefix marks a group reference written as a display name rather than an
// object id, for example "name:platform-admins".
const AliasPrefix = "name:"

var guidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// IsGUID reports whether s is a group object id.
func IsGUID(s string) bool { return guidRE.MatchString(s) }

// IsAlias reports whether s is a display-name alias.
func IsAlias(s string) bool { return strings.HasPrefix(s, AliasPrefix) }

// AliasName returns the display name carried by an alias reference.
func AliasName(s string) string { return strings.TrimSpace(strings.TrimPrefix(s, AliasPrefix)) }

// CanonicalRefs validates every configured group reference and maps it to the
// token the policy engine matches on: an object id is lower-cased, and an alias
// keeps its "name:<displayName>" form.
//
// No directory call happens here. An alias is a label for exactly one object
// id, and that id is looked up lazily by Aliases; the label is only ever
// attached to a caller who was found to hold the id, so authorization still
// rests on object ids rather than on a mutable display name.
func CanonicalRefs(refs []string) (map[string]string, error) {
	out := make(map[string]string, len(refs))
	// Group matching is case-insensitive, so two aliases differing only in case
	// would be indistinguishable at request time while resolving to different
	// groups in the directory.
	folded := map[string]string{}

	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		switch {
		case ref == "":
			continue
		case IsAlias(ref):
			name := AliasName(ref)
			if name == "" {
				return nil, fmt.Errorf("group reference %q has an empty display name", ref)
			}
			if prev, ok := folded[strings.ToLower(name)]; ok && prev != name {
				return nil, fmt.Errorf("group names %q and %q differ only in case, which group matching cannot "+
					"distinguish; use object ids for these groups", prev, name)
			}
			folded[strings.ToLower(name)] = name
			out[ref] = AliasPrefix + name
		case IsGUID(ref):
			out[ref] = strings.ToLower(ref)
		default:
			return nil, fmt.Errorf("group reference %q must be a group object id (GUID) or %q followed by a display name",
				ref, AliasPrefix)
		}
	}
	return out, nil
}

// AliasNames returns the distinct display names referenced by refs, sorted.
func AliasNames(refs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if !IsAlias(ref) {
			continue
		}
		if name := AliasName(ref); name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// AliasError reports that a display-name alias could not be translated into a
// group object id.
//
// Permanent distinguishes "an operator must change something" from "the
// directory was briefly unreachable". The two deserve different HTTP statuses:
// retrying a misspelled group name will never succeed, and telling a client to
// retry it forever only hides the mistake.
type AliasError struct {
	Name      string
	Reason    string // concise and safe to show the caller
	Permanent bool
	Err       error
}

func (e *AliasError) Error() string {
	return fmt.Sprintf("resolve group %q: %v", e.Name, e.Err)
}

func (e *AliasError) Unwrap() error { return e.Err }

// Aliases translates display-name aliases into the object ids they denote, on
// first use rather than at startup.
//
// Resolving lazily is what lets aliases work under the On-Behalf-Of flow, which
// has no application token at startup and must borrow a caller's. A resolved
// name is cached for the lifetime of the process, matching the old startup
// behaviour: a display name that is reassigned to a different group in the
// directory only takes effect on restart.
type Aliases struct {
	client       GroupLister
	names        []string
	flight       *flight
	negativeTTL  time.Duration
	callerScoped bool
	now          func() time.Time

	mu      sync.RWMutex
	byName  map[string]string
	failed  map[string]aliasFailure
	flagged map[string]bool
	logger  *slog.Logger
}

// aliasFailure remembers a permanent resolution failure, so that a misspelled
// group name costs one directory call per negativeCacheTTL rather than one per
// request. It expires so that creating the missing group takes effect without a
// restart.
type aliasFailure struct {
	err     *AliasError
	expires time.Time
}

// AliasOptions configures alias resolution.
type AliasOptions struct {
	// NegativeTTL is how long a failure that the operator must fix is
	// remembered, so that one bad name cannot become sustained Graph load.
	NegativeTTL time.Duration

	// CallerScoped records that lookups run with the caller's own rights, as
	// they do under the On-Behalf-Of flow. Graph then returns only the groups
	// that caller is allowed to see, so "no such group" is a statement about
	// that caller's view of the directory and not about the directory itself.
	CallerScoped bool

	Logger *slog.Logger
}

// NewAliases builds the resolver for the aliases used by refs. It returns nil
// when no alias is configured, which is the common case and keeps the directory
// entirely out of the request path.
func NewAliases(client GroupLister, refs []string, opts AliasOptions) *Aliases {
	names := AliasNames(refs)
	if len(names) == 0 || client == nil {
		return nil
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Aliases{
		client:       client,
		names:        names,
		flight:       newFlight(),
		negativeTTL:  opts.NegativeTTL,
		callerScoped: opts.CallerScoped,
		now:          time.Now,
		byName:       map[string]string{},
		failed:       map[string]aliasFailure{},
		flagged:      map[string]bool{},
		logger:       logger,
	}
}

// failureKey scopes a remembered failure. A caller-scoped lookup failed for one
// caller's view of the directory, so caching it under the name alone would let
// a guest, or any user with restricted directory access, deny the group to
// everyone else for the lifetime of the entry.
func (a *Aliases) failureKey(caller Caller, name string) string {
	if !a.callerScoped {
		return name
	}
	return name + "\x00" + strings.ToLower(caller.TenantID) + "\x00" + strings.ToLower(caller.UserID)
}

// Labels returns the alias tokens the caller is entitled to, given the group
// object ids they were found to hold. A caller gains "name:x" only by holding
// the object id that "x" resolves to.
func (a *Aliases) Labels(ctx context.Context, caller Caller, ids []string) ([]string, error) {
	if a == nil || len(a.names) == 0 {
		return nil, nil
	}
	held := make(map[string]bool, len(ids))
	for _, id := range ids {
		held[strings.ToLower(strings.TrimSpace(id))] = true
	}

	var out []string
	for _, name := range a.names {
		id, err := a.idFor(ctx, caller, name)
		if err != nil {
			return nil, err
		}
		if held[id] {
			out = append(out, AliasPrefix+name)
		}
	}
	return out, nil
}

func (a *Aliases) idFor(ctx context.Context, caller Caller, name string) (string, error) {
	key := a.failureKey(caller, name)

	a.mu.RLock()
	// A successful resolution is a fact about the directory rather than about
	// whoever happened to trigger it, so it is shared by every caller.
	id, ok := a.byName[name]
	fail, failed := a.failed[key]
	a.mu.RUnlock()
	if ok {
		return id, nil
	}
	if failed && a.now().Before(fail.expires) {
		return "", fail.err
	}

	// Collapse the stampede the first request would otherwise cause, and share
	// one lookup between every caller that arrives while it is in flight.
	found, err := a.flight.do(AliasPrefix+key, func() ([]Group, error) {
		// Re-check inside the flight: a lookup that completed between the read
		// above and acquiring the slot has already stored the answer.
		a.mu.RLock()
		cached, ok := a.byName[name]
		a.mu.RUnlock()
		if ok {
			return []Group{{ID: cached}}, nil
		}

		g, err := a.lookup(ctx, caller, name)
		if err != nil {
			a.remember(key, name, err)
			return nil, err
		}
		a.mu.Lock()
		first := a.byName[name] == ""
		a.byName[name] = strings.ToLower(g.ID)
		delete(a.failed, key)
		delete(a.flagged, name)
		a.mu.Unlock()
		if first {
			// Record what the name resolved to. Under a caller-scoped lookup
			// this is the one decision an operator cannot otherwise audit.
			a.logger.Info("resolved a group display name to an object id",
				"group", name, "groupID", strings.ToLower(g.ID))
		}
		return []Group{g}, nil
	})
	if err != nil {
		return "", err
	}
	return strings.ToLower(found[0].ID), nil
}

// remember caches a permanent failure and logs it once, so that a group name
// that will never resolve is reported loudly but does not flood the log or the
// directory.
func (a *Aliases) remember(key, name string, err *AliasError) {
	if !err.Permanent {
		return
	}
	a.mu.Lock()
	// Dedupe the log by name, not by key: a caller-scoped failure would
	// otherwise log once per user.
	first := !a.flagged[name]
	a.flagged[name] = true
	a.failed[key] = aliasFailure{err: err, expires: a.now().Add(a.negativeTTL)}
	a.mu.Unlock()

	if first {
		a.logger.Error("a group name in the configuration cannot be resolved; every request that depends on it will fail",
			"group", name, "reason", err.Reason, "error", err.Err)
	}
}

// lookup finds the single group named name, treating anything else as fatal.
func (a *Aliases) lookup(ctx context.Context, caller Caller, name string) (Group, *AliasError) {
	found, err := a.client.GroupsByDisplayName(ctx, caller, name)
	if err != nil {
		// Looking a group up by display name reads the directory's group
		// objects, which is a broader operation than reading one user's
		// membership. A credential that can do the latter may still be refused
		// here, so say what to do about it.
		var he *HTTPError
		if errors.As(err, &he) && he.Status == http.StatusForbidden {
			return Group{}, &AliasError{
				Name:      name,
				Reason:    "the directory refused the lookup; the proxy lacks permission to read group objects",
				Permanent: true,
				Err: fmt.Errorf("%w\n"+
					"  Looking up a group by display name calls GET /v1.0/groups, which needs Group.Read.All or "+
					"GroupMember.Read.All with admin consent granted: as an application permission under "+
					"graph.flow: app_permission, where the `roles` claim of the proxy's own token must show it, "+
					"or as a delegated permission under graph.flow: obo, where the caller's `scp` claim must.\n"+
					"  Replacing %q with the group's object id avoids this call entirely: object ids are "+
					"resolved from the caller's own membership, which needs no directory-wide read.",
					err, AliasPrefix+name),
			}
		}
		// Anything else is assumed transient: a timeout, a 5xx, throttling.
		// Retrying may well succeed, so it must not be cached or reported as a
		// configuration error.
		return Group{}, &AliasError{
			Name:   name,
			Reason: "the directory could not be reached",
			Err:    err,
		}
	}

	var exact []Group
	for _, g := range found {
		// Graph's `eq` filter on displayName is case-insensitive; require an
		// exact match so "Admins" cannot silently resolve to "admins".
		if g.DisplayName == name {
			exact = append(exact, g)
		}
	}
	switch len(exact) {
	case 0:
		if a.callerScoped {
			// Delegated permissions are the intersection of the application's
			// grant and the signed-in user's own privileges, so Graph returned
			// only what this caller may see. An empty result therefore cannot
			// distinguish "no such group" from "not visible to this user",
			// which is the case for guests and in tenants that restrict
			// directory reads.
			return Group{}, &AliasError{
				Name:      name,
				Reason:    "no group with this display name is visible to the calling user; it may not exist, or this user may not be allowed to see it",
				Permanent: true,
				Err: fmt.Errorf("no group named %q was returned for this caller. Under graph.flow: obo the "+
					"directory is read with the caller's own rights, so this means either that no such group "+
					"exists, or that this user cannot see it - guests and members of tenants that restrict "+
					"directory reads routinely cannot. Check the spelling and exact case first; using the "+
					"group's object id removes the ambiguity entirely", name),
			}
		}
		return Group{}, &AliasError{
			Name:      name,
			Reason:    "no group with this display name exists in the directory",
			Permanent: true,
			Err: fmt.Errorf("no group named %q exists in the directory; check the spelling and the exact case, "+
				"or use the group's object id", name),
		}
	case 1:
		return exact[0], nil
	default:
		ids := make([]string, 0, len(exact))
		for _, g := range exact {
			ids = append(ids, g.ID)
		}
		return Group{}, &AliasError{
			Name:      name,
			Reason:    "the display name matches more than one group, so it does not identify one",
			Permanent: true,
			Err: fmt.Errorf("group name %q is ambiguous: it matches %d groups (%s); use the object id instead",
				name, len(exact), strings.Join(ids, ", ")),
		}
	}
}
