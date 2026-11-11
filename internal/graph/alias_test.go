package graph

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	adminsID = "aaaaaaaa-1111-2222-3333-444444444444"
	otherID  = "bbbbbbbb-1111-2222-3333-444444444444"
)

// newTestAliases keeps the negative-cache window short enough that expiry can
// be exercised without a clock.
func newTestAliases(client GroupLister, refs []string) *Aliases {
	return NewAliases(client, refs, AliasOptions{NegativeTTL: 30 * time.Second})
}

// newCallerScopedAliases mimics the On-Behalf-Of flow, where the directory is
// read with each caller's own rights.
func newCallerScopedAliases(client GroupLister, refs []string) *Aliases {
	return NewAliases(client, refs, AliasOptions{NegativeTTL: 30 * time.Second, CallerScoped: true})
}

func aliasLister() *fakeLister {
	return &fakeLister{groups: []Group{
		{ID: adminsID, DisplayName: "mcp-admins"},
		{ID: otherID, DisplayName: "mcp-readers"},
	}}
}

func TestCanonicalRefsKeepsAliasesAndLowerCasesObjectIDs(t *testing.T) {
	got, err := CanonicalRefs([]string{"name:mcp-admins", strings.ToUpper(otherID), "  name:mcp-admins  "})
	if err != nil {
		t.Fatalf("CanonicalRefs: %v", err)
	}
	if got["name:mcp-admins"] != "name:mcp-admins" {
		t.Errorf("alias canonicalised to %q", got["name:mcp-admins"])
	}
	if got[strings.ToUpper(otherID)] != otherID {
		t.Errorf("object id canonicalised to %q, want %q", got[strings.ToUpper(otherID)], otherID)
	}
}

// A bare display name must be rejected outright, so that a name is only ever
// matched after having been resolved against the directory.
func TestBareDisplayNameIsRejected(t *testing.T) {
	_, err := CanonicalRefs([]string{"mcp-admins"})
	if err == nil {
		t.Fatal("expected a bare display name to be rejected")
	}
	if !strings.Contains(err.Error(), "object id") {
		t.Errorf("error = %v, want it to point at object ids", err)
	}
}

// Group matching is case-insensitive, so two names differing only in case would
// be indistinguishable at request time while naming different groups.
func TestCanonicalRefsRejectsNamesDifferingOnlyInCase(t *testing.T) {
	_, err := CanonicalRefs([]string{"name:mcp-admins", "name:MCP-Admins"})
	if err == nil {
		t.Fatal("expected names differing only in case to be rejected")
	}
	if !strings.Contains(err.Error(), "differ only in case") {
		t.Errorf("error = %v", err)
	}
}

// The whole point of resolving a name: the label is attached because the caller
// holds the object id the name resolved to, not because a group they belong to
// happens to carry that display name. Otherwise a user able to create a group
// could name it after a privileged one and self-grant.
func TestAliasLabelsFollowTheResolvedObjectID(t *testing.T) {
	a := newTestAliases(aliasLister(), []string{"name:mcp-admins"})

	labels, err := a.Labels(context.Background(), Caller{}, []string{adminsID})
	if err != nil {
		t.Fatalf("Labels: %v", err)
	}
	if len(labels) != 1 || labels[0] != "name:mcp-admins" {
		t.Errorf("labels = %v, want [name:mcp-admins]", labels)
	}

	// A member of a different group gets nothing, even though an impostor group
	// could carry the same display name.
	labels, err = a.Labels(context.Background(), Caller{}, []string{"cccccccc-1111-2222-3333-444444444444"})
	if err != nil {
		t.Fatalf("Labels: %v", err)
	}
	if len(labels) != 0 {
		t.Errorf("labels = %v, want none", labels)
	}
}

func TestAliasLookupHappensOnceAndIsCached(t *testing.T) {
	lister := aliasLister()
	a := newTestAliases(lister, []string{"name:mcp-admins"})

	for i := 0; i < 3; i++ {
		if _, err := a.Labels(context.Background(), Caller{}, []string{adminsID}); err != nil {
			t.Fatalf("Labels: %v", err)
		}
	}
	if got := lister.callCount(); got != 1 {
		t.Errorf("directory calls = %d, want 1; a resolved name must be cached", got)
	}
}

// Concurrent first requests must collapse into a single directory call rather
// than each issuing their own.
func TestConcurrentAliasLookupsCollapse(t *testing.T) {
	lister := aliasLister()
	a := newTestAliases(lister, []string{"name:mcp-admins"})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := a.Labels(context.Background(), Caller{}, []string{adminsID}); err != nil {
				t.Errorf("Labels: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := lister.callCount(); got != 1 {
		t.Errorf("directory calls = %d, want 1", got)
	}
}

// With no alias configured the directory must stay out of the request path
// entirely.
func TestNoAliasesMeansNoResolver(t *testing.T) {
	if a := newTestAliases(aliasLister(), []string{adminsID}); a != nil {
		t.Error("expected no resolver when only object ids are configured")
	}
	var nilAliases *Aliases
	labels, err := nilAliases.Labels(context.Background(), Caller{}, []string{adminsID})
	if err != nil || labels != nil {
		t.Errorf("nil resolver returned (%v, %v)", labels, err)
	}
}

func TestAmbiguousDisplayNameIsFatal(t *testing.T) {
	lister := &fakeLister{groups: []Group{
		{ID: adminsID, DisplayName: "duplicate"},
		{ID: otherID, DisplayName: "duplicate"},
	}}
	a := newTestAliases(lister, []string{"name:duplicate"})

	_, err := a.Labels(context.Background(), Caller{}, []string{adminsID})
	if err == nil {
		t.Fatal("expected an ambiguous group name to be an error")
	}
	if !strings.Contains(err.Error(), "ambiguous") {
		t.Errorf("error = %v, want it to mention ambiguity", err)
	}
}

func TestUnknownDisplayNameIsFatal(t *testing.T) {
	a := newTestAliases(aliasLister(), []string{"name:does-not-exist"})

	_, err := a.Labels(context.Background(), Caller{}, []string{adminsID})
	if err == nil {
		t.Fatal("expected an unknown group name to be an error")
	}
	if !strings.Contains(err.Error(), "no group named") {
		t.Errorf("error = %v", err)
	}
}

// Graph's `eq` filter on displayName is case-insensitive, so the exact-match
// check has to be applied locally.
func TestAliasMatchIsCaseSensitive(t *testing.T) {
	lister := &fakeLister{groups: []Group{{ID: adminsID, DisplayName: "mcp-admins"}}}
	a := newTestAliases(lister, []string{"name:MCP-Admins"})

	_, err := a.Labels(context.Background(), Caller{}, []string{adminsID})
	if err == nil {
		t.Fatal("expected a case mismatch to be rejected; Graph would have returned the lower-case group")
	}
	if !strings.Contains(err.Error(), "no group named") {
		t.Errorf("error = %v", err)
	}
}

// The caller's token has to reach the lookup, because under the On-Behalf-Of
// flow it is the only thing that can authorize the directory read.
func TestAliasLookupReceivesTheCaller(t *testing.T) {
	lister := aliasLister()
	a := newTestAliases(lister, []string{"name:mcp-admins"})

	want := Caller{TenantID: "tenant", UserID: "user", Assertion: "caller-token"}
	if _, err := a.Labels(context.Background(), want, []string{adminsID}); err != nil {
		t.Fatalf("Labels: %v", err)
	}
	lister.mu.Lock()
	defer lister.mu.Unlock()
	if len(lister.nameCallers) != 1 || lister.nameCallers[0] != want {
		t.Errorf("lookup saw callers %v, want [%v]", lister.nameCallers, want)
	}
}

func TestIsGUID(t *testing.T) {
	cases := map[string]bool{
		adminsID:         true,
		"not-a-guid":     false,
		"":               false,
		adminsID + "-xx": false,
	}
	for in, want := range cases {
		if got := IsGUID(in); got != want {
			t.Errorf("IsGUID(%q) = %v, want %v", in, got, want)
		}
	}
}

// A credential that can read one user's membership may still be refused the
// directory-wide group read that a display-name lookup requires, so the error
// has to say what to change.
func TestAliasLookupExplainsForbidden(t *testing.T) {
	a := newTestAliases(forbiddenLister{}, []string{"name:ng-it-rancher-engsup"})

	_, err := a.Labels(context.Background(), Caller{}, []string{adminsID})
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{
		"Group.Read.All",
		"admin consent",
		"application permission",
		"delegated permission",
		"roles",
		"scp",
		"object id",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}
}

type forbiddenLister struct{}

func (forbiddenLister) GroupsByDisplayName(context.Context, Caller, string) ([]Group, error) {
	return nil, &HTTPError{Status: http.StatusForbidden, Message: "Authorization_RequestDenied: Insufficient privileges to complete the operation."}
}

func (forbiddenLister) TransitiveMemberOf(context.Context, Caller) ([]Group, error) {
	return nil, nil
}

// A permanent failure is remembered, but not forever: creating the missing
// group must take effect without restarting the proxy.
func TestPermanentFailureExpiresFromTheNegativeCache(t *testing.T) {
	lister := &fakeLister{}
	a := newTestAliases(lister, []string{"name:mcp-admins"})
	now := time.Now()
	a.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if _, err := a.Labels(context.Background(), Caller{}, []string{adminsID}); err == nil {
			t.Fatal("expected an error for a group that does not exist")
		}
	}
	if got := lister.callCount(); got != 1 {
		t.Errorf("directory calls = %d, want 1 while the failure is cached", got)
	}

	// The group is created, and the cached failure expires.
	lister.mu.Lock()
	lister.groups = []Group{{ID: adminsID, DisplayName: "mcp-admins"}}
	lister.mu.Unlock()
	now = now.Add(time.Minute)

	labels, err := a.Labels(context.Background(), Caller{}, []string{adminsID})
	if err != nil {
		t.Fatalf("Labels after the group was created: %v", err)
	}
	if len(labels) != 1 {
		t.Errorf("labels = %v, want the alias to resolve once the group exists", labels)
	}
}

// An unreachable directory may well work on the next request, so it must not be
// cached as a failure nor reported as a configuration error.
func TestTransientFailureIsNeitherCachedNorPermanent(t *testing.T) {
	lister := &fakeLister{err: errors.New("dial tcp: connection refused")}
	a := newTestAliases(lister, []string{"name:mcp-admins"})

	for i := 0; i < 3; i++ {
		_, err := a.Labels(context.Background(), Caller{}, []string{adminsID})
		var ae *AliasError
		if !errors.As(err, &ae) {
			t.Fatalf("error = %v, want an *AliasError", err)
		}
		if ae.Permanent {
			t.Error("an unreachable directory must not be reported as a configuration error")
		}
	}
	if got := lister.callCount(); got != 3 {
		t.Errorf("directory calls = %d, want 3; a transient failure must be retried", got)
	}
}

func TestAliasErrorsAreClassified(t *testing.T) {
	cases := []struct {
		name      string
		lister    GroupLister
		alias     string
		permanent bool
		reason    string
	}{
		{"unknown", aliasLister(), "name:nope", true, "no group with this display name"},
		{"ambiguous", &fakeLister{groups: []Group{
			{ID: adminsID, DisplayName: "dup"}, {ID: otherID, DisplayName: "dup"},
		}}, "name:dup", true, "more than one group"},
		{"forbidden", forbiddenLister{}, "name:nope", true, "lacks permission"},
		{"unreachable", &fakeLister{err: errors.New("boom")}, "name:nope", false, "could not be reached"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newTestAliases(tc.lister, []string{tc.alias})
			_, err := a.Labels(context.Background(), Caller{}, []string{adminsID})

			var ae *AliasError
			if !errors.As(err, &ae) {
				t.Fatalf("error = %v, want an *AliasError", err)
			}
			if ae.Permanent != tc.permanent {
				t.Errorf("Permanent = %v, want %v", ae.Permanent, tc.permanent)
			}
			if !strings.Contains(ae.Reason, tc.reason) {
				t.Errorf("Reason = %q, want it to contain %q", ae.Reason, tc.reason)
			}
			if ae.Name != AliasName(tc.alias) {
				t.Errorf("Name = %q, want %q", ae.Name, AliasName(tc.alias))
			}
		})
	}
}

// visibilityLister models delegated permissions: Graph returns only the groups
// the signed-in user is allowed to see, so the same query answers differently
// for different callers.
type visibilityLister struct {
	mu      sync.Mutex
	calls   int
	visible map[string][]Group // user object id -> groups that user can see
}

func (v *visibilityLister) GroupsByDisplayName(_ context.Context, caller Caller, name string) ([]Group, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.calls++
	var out []Group
	for _, g := range v.visible[caller.UserID] {
		if strings.EqualFold(g.DisplayName, name) {
			out = append(out, g)
		}
	}
	return out, nil
}

func (v *visibilityLister) TransitiveMemberOf(context.Context, Caller) ([]Group, error) {
	return nil, nil
}

// Under delegated permissions an empty result means "not visible to this
// caller", which is not the same as "does not exist". Caching that under the
// group name alone would let one restricted user - a guest, say - deny the
// group to everyone else until the entry expired.
func TestCallerScopedMissIsNotCachedAcrossCallers(t *testing.T) {
	lister := &visibilityLister{visible: map[string][]Group{
		"member": {{ID: adminsID, DisplayName: "mcp-admins"}},
		"guest":  nil,
	}}
	a := newCallerScopedAliases(lister, []string{"name:mcp-admins"})

	guest := Caller{TenantID: "t", UserID: "guest", Assertion: "g"}
	if _, err := a.Labels(context.Background(), guest, []string{adminsID}); err == nil {
		t.Fatal("expected the guest's restricted view to fail")
	}

	// The next caller can see the group and must not inherit the guest's answer.
	member := Caller{TenantID: "t", UserID: "member", Assertion: "m"}
	labels, err := a.Labels(context.Background(), member, []string{adminsID})
	if err != nil {
		t.Fatalf("a caller who can see the group must still resolve it: %v", err)
	}
	if len(labels) != 1 {
		t.Errorf("labels = %v, want the alias to resolve for this caller", labels)
	}
}

// The error has to admit that an empty result under delegated permissions is
// ambiguous, rather than asserting the group does not exist.
func TestCallerScopedMissSaysItMayBeAVisibilityProblem(t *testing.T) {
	a := newCallerScopedAliases(&visibilityLister{}, []string{"name:mcp-admins"})

	_, err := a.Labels(context.Background(), Caller{TenantID: "t", UserID: "guest"}, []string{adminsID})
	var ae *AliasError
	if !errors.As(err, &ae) {
		t.Fatalf("error = %v, want an *AliasError", err)
	}
	if !strings.Contains(ae.Reason, "visible to the calling user") {
		t.Errorf("Reason = %q, want it to allow for a visibility problem", ae.Reason)
	}
	if !strings.Contains(ae.Err.Error(), "object id") {
		t.Errorf("error should suggest the object id, got: %v", ae.Err)
	}
}

// A resolution that did succeed is a fact about the directory, so every caller
// may share it and it must not cost a lookup per user.
func TestCallerScopedHitIsSharedAcrossCallers(t *testing.T) {
	lister := &visibilityLister{visible: map[string][]Group{
		"a": {{ID: adminsID, DisplayName: "mcp-admins"}},
		"b": {{ID: adminsID, DisplayName: "mcp-admins"}},
	}}
	a := newCallerScopedAliases(lister, []string{"name:mcp-admins"})

	for _, user := range []string{"a", "b"} {
		if _, err := a.Labels(context.Background(), Caller{TenantID: "t", UserID: user}, []string{adminsID}); err != nil {
			t.Fatalf("user %s: %v", user, err)
		}
	}
	lister.mu.Lock()
	defer lister.mu.Unlock()
	if lister.calls != 1 {
		t.Errorf("directory calls = %d, want 1; a resolved name is shared", lister.calls)
	}
}
