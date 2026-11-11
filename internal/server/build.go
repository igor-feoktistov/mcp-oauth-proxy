package server

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/example/mcp-oauth-proxy/internal/auth"
	"github.com/example/mcp-oauth-proxy/internal/authz"
	"github.com/example/mcp-oauth-proxy/internal/config"
	"github.com/example/mcp-oauth-proxy/internal/graph"
)

// directory is the per-tenant Graph plumbing: the client used to resolve
// display-name aliases at startup, and the caching resolver used per request.
type directory struct {
	client   graph.GroupLister
	resolver *graph.Resolver
}

// GraphFactory builds the Graph client. Tests substitute a fake directory
// through it.
type GraphFactory func(authority string, g *config.Graph) graph.GroupLister

func defaultGraphFactory(authority string, g *config.Graph) graph.GroupLister {
	return graph.NewClient(authority, g)
}

// buildDirectory creates the single Graph client and resolver shared by every
// application that resolves groups from the directory. There is one credential
// because the proxy calls Graph as itself, never on behalf of the caller, and
// an app-only credential can only read its own tenant.
func buildDirectory(cfg *config.Config, factory GraphFactory, logger *slog.Logger) *directory {
	o := &cfg.Authorization.OAuth2
	if !o.UsesGraph() {
		return nil
	}
	// Every application has an authority after defaults are applied, and the
	// credential is pinned to one tenant, so the first one is the right one.
	client := factory(o.OAuth2Clients[0].Authority, &o.Graph)
	return &directory{
		client:   client,
		resolver: graph.NewResolver(client, o.Graph, logger.With("tenant", o.Graph.Credential.TenantID)),
	}
}

// groupRefs validates every group reference in the configuration and maps it to
// the token the policy engine matches on.
//
// Display names are not looked up here. They are resolved on first use instead,
// because the On-Behalf-Of flow has no token of its own at startup and must
// borrow a caller's; see graph.Aliases.
func groupRefs(cfg *config.Config, policy config.Policy, dir *directory, logger *slog.Logger) (map[string]string, *graph.Aliases, error) {
	refs := append([]string{}, cfg.Authorization.OAuth2.AllowGroups...)
	refs = append(refs, authz.GroupRefs(policy)...)

	var client graph.GroupLister
	if dir != nil {
		client = dir.client
	}

	if client == nil {
		// No directory is configured (every client uses groupsSource: jwt), so
		// there is nothing that could translate a name into an object id.
		for _, ref := range refs {
			if graph.IsAlias(strings.TrimSpace(ref)) {
				return nil, nil, fmt.Errorf("group reference %q uses a display-name alias, "+
					"which requires at least one oauth2Client with groupsSource: %s", ref, config.GroupsSourceGraph)
			}
		}
	}

	canonical, err := graph.CanonicalRefs(refs)
	if err != nil {
		return nil, nil, err
	}
	aliases := graph.NewAliases(client, refs, graph.AliasOptions{
		NegativeTTL: cfg.Authorization.OAuth2.Graph.NegativeCacheTTL,
		// Under On-Behalf-Of the directory is read with the caller's own
		// rights, so what a lookup returns depends on who asked.
		CallerScoped: cfg.Authorization.OAuth2.Graph.Flow == config.GraphFlowOBO,
		Logger:       logger,
	})
	return canonical, aliases, nil
}

// buildValidator assembles the token validator for every configured tenant.
func buildValidator(cfg *config.Config, dir *directory, allowGroups []string, aliases *graph.Aliases, logger *slog.Logger) (*auth.Validator, map[string]*auth.KeySet, error) {
	tenants := map[string]*auth.TenantRuntime{}
	keySets := map[string]*auth.KeySet{}

	for i := range cfg.Authorization.OAuth2.OAuth2Clients {
		cl := &cfg.Authorization.OAuth2.OAuth2Clients[i]
		key := strings.ToLower(cl.TenantID)
		keys := auth.NewKeySet(cl.OpenIDConfigurationURL(), cl.JWKSTimeout, cl.JWKSRefresh, logger.With("tenant", cl.TenantID))
		keySets[key] = keys

		var src auth.GroupSource
		if dir != nil && cl.GroupsSource == config.GroupsSourceGraph {
			src = dir.resolver
		}
		tenants[key] = auth.NewTenantRuntime(cl, keys, src)
	}

	v, err := auth.NewValidator(&cfg.Authorization.OAuth2, tenants, allowGroups, aliases, logger)
	if err != nil {
		return nil, nil, err
	}
	return v, keySets, nil
}
