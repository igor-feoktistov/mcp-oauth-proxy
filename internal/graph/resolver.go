package graph

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/example/mcp-oauth-proxy/internal/config"
)

// ErrUnavailable indicates group membership could not be determined. Callers
// must treat it as a denial: failing open here would grant access to anyone.
var ErrUnavailable = errors.New("group membership could not be resolved")

// GroupLister is the subset of the Graph API the resolver depends on, so tests
// can substitute a fake directory.
type GroupLister interface {
	TransitiveMemberOf(ctx context.Context, caller Caller) ([]Group, error)
	GroupsByDisplayName(ctx context.Context, caller Caller, name string) ([]Group, error)
}

// Stats reports resolver cache behaviour for metrics and tests.
type Stats struct {
	Hits    int64
	Misses  int64
	Stale   int64
	Errors  int64
	Entries int
}

// Resolver caches Microsoft Graph group membership per user.
type Resolver struct {
	client GroupLister
	cfg    config.Graph
	cache  *lruCache
	flight *flight
	logger *slog.Logger
	now    func() time.Time

	stats struct {
		hits, misses, stale, errors int64
		mu                          chan struct{}
	}
}

// NewResolver builds a resolver over a Graph client.
func NewResolver(client GroupLister, cfg config.Graph, logger *slog.Logger) *Resolver {
	r := &Resolver{
		client: client,
		cfg:    cfg,
		cache:  newLRU(cfg.MaxCacheEntries),
		flight: newFlight(),
		logger: logger,
		now:    time.Now,
	}
	r.stats.mu = make(chan struct{}, 1)
	r.stats.mu <- struct{}{}
	return r
}

// Groups returns the user's transitive group membership, using the cache when
// it is fresh. The caller's tenant scopes the cache key so that two tenants can
// never share an entry for the same object id.
//
// The cache key deliberately ignores caller.Assertion: the membership belongs
// to the user, not to the token that happened to carry the request, so two
// tokens for the same user share one entry.
func (r *Resolver) Groups(ctx context.Context, caller Caller) ([]Group, error) {
	if caller.UserID == "" {
		return nil, fmt.Errorf("%w: token carries no oid claim", ErrUnavailable)
	}
	key := strings.ToLower(caller.TenantID + "|" + caller.UserID)
	now := r.now()

	if e, ok := r.cache.get(key); ok && e.fresh(now) {
		r.record(&r.stats.hits)
		if e.err != nil {
			return nil, e.err
		}
		return e.groups, nil
	}

	return r.flight.do(key, func() ([]Group, error) {
		// Re-check: a concurrent caller may have refreshed the entry while we
		// were queued behind it.
		now := r.now()
		if e, ok := r.cache.get(key); ok && e.fresh(now) {
			r.record(&r.stats.hits)
			if e.err != nil {
				return nil, e.err
			}
			return e.groups, nil
		}

		r.record(&r.stats.misses)
		groups, err := r.client.TransitiveMemberOf(ctx, caller)
		if err == nil {
			r.cache.put(key, &entry{
				groups:    groups,
				fetchedAt: now,
				expiresAt: now.Add(r.cfg.CacheTTL),
			})
			return groups, nil
		}

		r.record(&r.stats.errors)
		// A cancelled request is the client's doing, not a Graph failure, and
		// must not poison the cache for everyone else.
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}

		if stale, ok := r.staleFallback(key, now); ok {
			r.record(&r.stats.stale)
			r.logger.Warn("serving stale group membership because Microsoft Graph is unavailable",
				"user_id", caller.UserID, "tenant", caller.TenantID, "error", err)
			return stale, nil
		}

		wrapped := fmt.Errorf("%w: %v", ErrUnavailable, err)
		ttl := r.cfg.NegativeCacheTTL
		// Honour Graph's own back-off hint so we do not keep hammering it.
		var he *HTTPError
		if errors.As(err, &he) && he.Throttled() && he.RetryAfter > ttl {
			ttl = he.RetryAfter
		}
		r.cache.put(key, &entry{
			err:       wrapped,
			fetchedAt: now,
			expiresAt: now.Add(ttl),
		})
		r.logger.Error("group membership lookup failed",
			"user_id", caller.UserID, "tenant", caller.TenantID, "error", err, "negative_cache_ttl", ttl)
		return nil, wrapped
	})
}

// staleFallback returns an expired-but-recent successful entry when the
// configured failure mode permits trading freshness for availability.
func (r *Resolver) staleFallback(key string, now time.Time) ([]Group, bool) {
	if r.cfg.FailureMode != config.FailureModeStale {
		return nil, false
	}
	e, ok := r.cache.get(key)
	if !ok || e.err != nil {
		return nil, false
	}
	if now.Sub(e.fetchedAt) > r.cfg.CacheTTL+r.cfg.StaleGracePeriod {
		return nil, false
	}
	return e.groups, true
}

// Forget drops a cached membership, so an operator can force a refresh.
func (r *Resolver) Forget(tenantID, userID string) {
	r.cache.delete(strings.ToLower(tenantID + "|" + userID))
}

// Stats returns a snapshot of cache counters.
func (r *Resolver) Stats() Stats {
	<-r.stats.mu
	s := Stats{Hits: r.stats.hits, Misses: r.stats.misses, Stale: r.stats.stale, Errors: r.stats.errors}
	r.stats.mu <- struct{}{}
	s.Entries = r.cache.len()
	return s
}

func (r *Resolver) record(counter *int64) {
	<-r.stats.mu
	*counter++
	r.stats.mu <- struct{}{}
}
