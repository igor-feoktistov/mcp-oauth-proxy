package graph

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/example/mcp-oauth-proxy/internal/config"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeLister is a minimal GroupLister that counts calls and can be blocked.
type fakeLister struct {
	mu     sync.Mutex
	calls  int
	groups []Group
	err    error
	block  chan struct{}

	nameCallers []Caller
}

func (f *fakeLister) TransitiveMemberOf(ctx context.Context, _ Caller) ([]Group, error) {
	f.mu.Lock()
	f.calls++
	block, err, groups := f.block, f.err, f.groups
	f.mu.Unlock()

	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return groups, err
}

func (f *fakeLister) GroupsByDisplayName(_ context.Context, caller Caller, name string) ([]Group, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.nameCallers = append(f.nameCallers, caller)
	// Graph's `eq` filter on displayName is case-insensitive; emulate that so
	// the exact-match check on the result is actually exercised.
	var out []Group
	for _, g := range f.groups {
		if strings.EqualFold(g.DisplayName, name) {
			out = append(out, g)
		}
	}
	return out, f.err
}

func (f *fakeLister) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func testGraphConfig() config.Graph {
	g := config.Graph{}
	g.CacheTTL = time.Minute
	g.NegativeCacheTTL = 30 * time.Second
	g.MaxCacheEntries = 100
	g.FailureMode = config.FailureModeClosed
	g.StaleGracePeriod = time.Hour
	return g
}

func TestResolverCachesMembership(t *testing.T) {
	lister := &fakeLister{groups: []Group{{ID: "G1", DisplayName: "admins"}}}
	r := NewResolver(lister, testGraphConfig(), discardLogger())

	for i := 0; i < 3; i++ {
		groups, err := r.Groups(context.Background(), Caller{TenantID: "tenant", UserID: "user"})
		if err != nil {
			t.Fatalf("lookup %d: %v", i, err)
		}
		if len(groups) != 1 || groups[0].ID != "G1" {
			t.Fatalf("groups = %v", groups)
		}
	}
	if got := lister.callCount(); got != 1 {
		t.Errorf("directory calls = %d, want 1; the membership should be cached", got)
	}
}

// A burst of requests from one user must collapse into a single directory
// lookup, otherwise a cold cache turns every new user into a thundering herd.
func TestResolverCoalescesConcurrentLookups(t *testing.T) {
	block := make(chan struct{})
	lister := &fakeLister{groups: []Group{{ID: "G1"}}, block: block}
	r := NewResolver(lister, testGraphConfig(), discardLogger())

	const callers = 20
	var wg sync.WaitGroup
	errs := make([]error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = r.Groups(context.Background(), Caller{TenantID: "tenant", UserID: "user"})
		}(i)
	}

	// Give the goroutines time to queue behind the in-flight call.
	time.Sleep(50 * time.Millisecond)
	close(block)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
	}
	if got := lister.callCount(); got != 1 {
		t.Errorf("directory calls = %d, want 1", got)
	}
}

func TestResolverExpiresEntries(t *testing.T) {
	lister := &fakeLister{groups: []Group{{ID: "G1"}}}
	cfg := testGraphConfig()
	cfg.CacheTTL = time.Minute
	r := NewResolver(lister, cfg, discardLogger())

	now := time.Now()
	r.now = func() time.Time { return now }

	if _, err := r.Groups(context.Background(), Caller{TenantID: "t", UserID: "u"}); err != nil {
		t.Fatal(err)
	}
	// Still inside the TTL.
	now = now.Add(30 * time.Second)
	if _, err := r.Groups(context.Background(), Caller{TenantID: "t", UserID: "u"}); err != nil {
		t.Fatal(err)
	}
	if got := lister.callCount(); got != 1 {
		t.Fatalf("calls = %d, want 1 before the TTL expires", got)
	}

	// Past the TTL, a group removal must become visible.
	now = now.Add(2 * time.Minute)
	if _, err := r.Groups(context.Background(), Caller{TenantID: "t", UserID: "u"}); err != nil {
		t.Fatal(err)
	}
	if got := lister.callCount(); got != 2 {
		t.Errorf("calls = %d, want 2 after the TTL expires", got)
	}
}

// A directory outage must deny, never allow, and must not be retried on every
// request while it lasts.
func TestResolverFailsClosedAndCachesFailure(t *testing.T) {
	lister := &fakeLister{err: errors.New("graph is down")}
	r := NewResolver(lister, testGraphConfig(), discardLogger())

	for i := 0; i < 5; i++ {
		_, err := r.Groups(context.Background(), Caller{TenantID: "t", UserID: "u"})
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("call %d: error = %v, want ErrUnavailable", i, err)
		}
	}
	if got := lister.callCount(); got != 1 {
		t.Errorf("directory calls = %d, want 1; failures should be negatively cached", got)
	}
}

func TestResolverStaleFallback(t *testing.T) {
	lister := &fakeLister{groups: []Group{{ID: "G1"}}}
	cfg := testGraphConfig()
	cfg.FailureMode = config.FailureModeStale
	r := NewResolver(lister, cfg, discardLogger())

	now := time.Now()
	r.now = func() time.Time { return now }

	if _, err := r.Groups(context.Background(), Caller{TenantID: "t", UserID: "u"}); err != nil {
		t.Fatal(err)
	}

	lister.mu.Lock()
	lister.err = errors.New("graph is down")
	lister.mu.Unlock()

	now = now.Add(2 * time.Minute) // past CacheTTL, inside StaleGracePeriod
	groups, err := r.Groups(context.Background(), Caller{TenantID: "t", UserID: "u"})
	if err != nil {
		t.Fatalf("expected the stale entry to be served, got %v", err)
	}
	if len(groups) != 1 || groups[0].ID != "G1" {
		t.Errorf("groups = %v", groups)
	}

	// Beyond the grace period the stale entry must no longer be trusted.
	now = now.Add(2 * time.Hour)
	if _, err := r.Groups(context.Background(), Caller{TenantID: "t", UserID: "u"}); !errors.Is(err, ErrUnavailable) {
		t.Errorf("error = %v, want ErrUnavailable once the grace period lapses", err)
	}
}

// Graph's own Retry-After must extend the negative cache, so the proxy backs
// off instead of amplifying a throttling event.
func TestResolverHonoursRetryAfter(t *testing.T) {
	lister := &fakeLister{err: &HTTPError{Status: http.StatusTooManyRequests, RetryAfter: 5 * time.Minute}}
	r := NewResolver(lister, testGraphConfig(), discardLogger())

	now := time.Now()
	r.now = func() time.Time { return now }

	if _, err := r.Groups(context.Background(), Caller{TenantID: "t", UserID: "u"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error = %v", err)
	}
	// The default negative TTL is 30s; Retry-After should win.
	now = now.Add(time.Minute)
	if _, err := r.Groups(context.Background(), Caller{TenantID: "t", UserID: "u"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error = %v", err)
	}
	if got := lister.callCount(); got != 1 {
		t.Errorf("calls = %d, want 1; Retry-After should still be in force", got)
	}

	now = now.Add(10 * time.Minute)
	_, _ = r.Groups(context.Background(), Caller{TenantID: "t", UserID: "u"})
	if got := lister.callCount(); got != 2 {
		t.Errorf("calls = %d, want 2 once Retry-After has elapsed", got)
	}
}

func TestResolverRequiresObjectID(t *testing.T) {
	r := NewResolver(&fakeLister{}, testGraphConfig(), discardLogger())
	if _, err := r.Groups(context.Background(), Caller{TenantID: "t", UserID: ""}); !errors.Is(err, ErrUnavailable) {
		t.Errorf("error = %v, want ErrUnavailable for a token with no oid", err)
	}
}

func TestLRUEvictsOldestEntries(t *testing.T) {
	lister := &fakeLister{groups: []Group{{ID: "G1"}}}
	cfg := testGraphConfig()
	cfg.MaxCacheEntries = 2
	r := NewResolver(lister, cfg, discardLogger())

	for _, user := range []string{"u1", "u2", "u3"} {
		if _, err := r.Groups(context.Background(), Caller{TenantID: "t", UserID: user}); err != nil {
			t.Fatal(err)
		}
	}
	if got := r.Stats().Entries; got != 2 {
		t.Errorf("cache entries = %d, want 2; the cache must stay bounded", got)
	}
	// u1 was evicted, so looking it up again must hit the directory.
	if _, err := r.Groups(context.Background(), Caller{TenantID: "t", UserID: "u1"}); err != nil {
		t.Fatal(err)
	}
	if got := lister.callCount(); got != 4 {
		t.Errorf("calls = %d, want 4", got)
	}
}

// A cancelled client request is not a directory failure and must not poison the
// cache for every other caller.
func TestCancelledRequestDoesNotPoisonCache(t *testing.T) {
	block := make(chan struct{})
	lister := &fakeLister{groups: []Group{{ID: "G1"}}, block: block}
	r := NewResolver(lister, testGraphConfig(), discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Groups(ctx, Caller{TenantID: "t", UserID: "u"}); err == nil {
		t.Fatal("expected an error for a cancelled context")
	}
	close(block)

	if _, err := r.Groups(context.Background(), Caller{TenantID: "t", UserID: "u"}); err != nil {
		t.Errorf("second lookup failed: %v; the cancellation should not have been cached", err)
	}
}
