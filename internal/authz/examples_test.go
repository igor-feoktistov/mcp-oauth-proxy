package authz_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/example/mcp-oauth-proxy/internal/authz"
	"github.com/example/mcp-oauth-proxy/internal/config"
	"github.com/example/mcp-oauth-proxy/internal/graph"
)

// The shipped example is the first thing an operator copies, so it has to stay
// loadable as the configuration schema evolves.
func TestExampleConfigLoadsAndCompiles(t *testing.T) {
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "/var/run/secrets/azure/tokens/azure-identity-token")

	path := filepath.Join("..", "..", "examples", "config.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	cfg, err := config.Parse(raw, filepath.Dir(path))
	if err != nil {
		t.Fatalf("parse example config: %v", err)
	}

	policy, err := authz.LoadRules(cfg)
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}

	// Aliases are resolved against the directory at startup; stand each
	// reference in for itself so the rules can be compiled offline.
	aliases := map[string]string{}
	for _, ref := range append(authz.GroupRefs(policy), cfg.Authorization.OAuth2.AllowGroups...) {
		aliases[strings.TrimSpace(ref)] = strings.TrimSpace(ref)
	}
	if _, err := authz.Compile(policy, aliases); err != nil {
		t.Fatalf("compile example policy: %v", err)
	}

	// The example must keep demonstrating the mandatory gate, and must keep
	// using object ids, since that is the practice the documentation argues for.
	if len(cfg.Authorization.OAuth2.AllowGroups) == 0 {
		t.Fatal("the example no longer sets allowGroups")
	}
	var guids int
	for _, g := range cfg.Authorization.OAuth2.AllowGroups {
		if graph.IsGUID(g) {
			guids++
		}
	}
	if guids == 0 {
		t.Error("the example only uses display-name aliases; it should lead with object ids")
	}
}
