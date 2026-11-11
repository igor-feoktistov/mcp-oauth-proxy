package authz_test

import (
	"strings"
	"testing"

	"github.com/example/mcp-oauth-proxy/internal/auth"
	"github.com/example/mcp-oauth-proxy/internal/authz"
	"github.com/example/mcp-oauth-proxy/internal/config"
)

const (
	admins  = "aaaaaaaa-0000-0000-0000-000000000001"
	readers = "aaaaaaaa-0000-0000-0000-000000000002"
)

var aliases = map[string]string{
	admins:         admins,
	readers:        readers,
	"name:admins":  admins,
	"name:readers": readers,
}

func compile(t *testing.T, p config.Policy) *authz.Policy {
	t.Helper()
	compiled, err := authz.Compile(p, aliases)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	return compiled
}

func user(groups ...string) *auth.Principal {
	return &auth.Principal{Username: "igor@contoso.com", ObjectID: "oid", Groups: groups}
}

func daemon(roles ...string) *auth.Principal {
	return &auth.Principal{ClientID: "client", AppOnly: true, Roles: roles}
}

func testPolicy() config.Policy {
	return config.Policy{
		DefaultEffect: "deny",
		Rules: []config.Rule{
			{Name: "deny-dangerous", Effect: "deny", Methods: []string{"tools/call"}, Tools: []string{"admin_*"}, Groups: []string{readers}},
			{Name: "admins-everything", Effect: "allow", Methods: []string{"*"}, Groups: []string{admins}},
			{Name: "readers-read-only", Effect: "allow", Methods: []string{"tools/list", "resources/*"}, Groups: []string{readers}},
			{Name: "handshake", Effect: "allow", Methods: []string{"initialize", "ping", "notifications/*"}},
		},
	}
}

func TestGroupMembershipGrantsAccess(t *testing.T) {
	p := compile(t, testPolicy())

	if d := p.Evaluate(user(admins), authz.Request{Method: "tools/call", Tool: "reboot"}); !d.Allowed {
		t.Errorf("admin denied: %+v", d)
	}
	if d := p.Evaluate(user(readers), authz.Request{Method: "tools/list"}); !d.Allowed {
		t.Errorf("reader denied tools/list: %+v", d)
	}
	if d := p.Evaluate(user(readers), authz.Request{Method: "tools/call", Tool: "reboot"}); d.Allowed {
		t.Errorf("reader allowed tools/call: %+v", d)
	}
}

func TestUnknownGroupFallsToDefaultDeny(t *testing.T) {
	p := compile(t, testPolicy())

	d := p.Evaluate(user("cccccccc-0000-0000-0000-000000000009"), authz.Request{Method: "tools/list"})
	if d.Allowed {
		t.Errorf("a user in no configured group should be denied: %+v", d)
	}
	if d.Rule != "default" {
		t.Errorf("rule = %q, want default", d.Rule)
	}
}

// Rules are evaluated in file order, so the decision must not depend on the
// order in which the directory happened to return the user's groups.
func TestDecisionIsIndependentOfGroupOrder(t *testing.T) {
	p := compile(t, testPolicy())
	req := authz.Request{Method: "tools/call", Tool: "admin_wipe"}

	first := p.Evaluate(user(admins, readers), req)
	second := p.Evaluate(user(readers, admins), req)

	if first.Allowed != second.Allowed || first.Rule != second.Rule {
		t.Errorf("decision changed with group order: %+v vs %+v", first, second)
	}
	if first.Allowed {
		t.Errorf("the earlier deny rule should win: %+v", first)
	}
}

func TestHandshakeRuleMatchesEveryUser(t *testing.T) {
	p := compile(t, testPolicy())

	if d := p.Evaluate(user("some-other-group"), authz.Request{Method: "initialize"}); !d.Allowed {
		t.Errorf("initialize denied: %+v", d)
	}
	if d := p.Evaluate(user(), authz.Request{Method: "notifications/initialized"}); !d.Allowed {
		t.Errorf("notification denied: %+v", d)
	}
}

// A rule written for users must never match a daemon, and vice versa, so a
// deny rule aimed at one population cannot silently lock out the other.
func TestAppOnlyAndUserRulesDoNotCross(t *testing.T) {
	p := compile(t, config.Policy{
		DefaultEffect: "deny",
		Rules: []config.Rule{
			{Name: "daemons", Effect: "allow", Methods: []string{"tools/call"}, Roles: []string{"Mcp.Invoke"}, AppOnly: true},
			{Name: "humans", Effect: "allow", Methods: []string{"tools/call"}, Groups: []string{admins}},
		},
	})

	if d := p.Evaluate(daemon("Mcp.Invoke"), authz.Request{Method: "tools/call", Tool: "x"}); !d.Allowed {
		t.Errorf("daemon with the role denied: %+v", d)
	}
	if d := p.Evaluate(daemon("Other.Role"), authz.Request{Method: "tools/call", Tool: "x"}); d.Allowed {
		t.Errorf("daemon without the role allowed: %+v", d)
	}
	if d := p.Evaluate(user(admins), authz.Request{Method: "tools/call", Tool: "x"}); d.Rule != "humans" {
		t.Errorf("user matched %q, want the humans rule", d.Rule)
	}
}

func TestToolPatternsOnlyConstrainToolCalls(t *testing.T) {
	p := compile(t, config.Policy{
		DefaultEffect: "deny",
		Rules: []config.Rule{
			{Name: "tools", Effect: "allow", Methods: []string{"*"}, Tools: []string{"safe_*"}, Groups: []string{admins}},
		},
	})

	if d := p.Evaluate(user(admins), authz.Request{Method: "tools/call", Tool: "safe_read"}); !d.Allowed {
		t.Errorf("matching tool denied: %+v", d)
	}
	if d := p.Evaluate(user(admins), authz.Request{Method: "tools/call", Tool: "danger"}); d.Allowed {
		t.Errorf("non-matching tool allowed: %+v", d)
	}
	// A method that names no tool cannot satisfy a rule that filters on tools.
	if d := p.Evaluate(user(admins), authz.Request{Method: "tools/list"}); d.Allowed {
		t.Errorf("tools/list allowed by a tool-scoped rule: %+v", d)
	}
}

func TestCompileRejectsUnresolvedGroup(t *testing.T) {
	_, err := authz.Compile(config.Policy{
		DefaultEffect: "deny",
		Rules:         []config.Rule{{Name: "r", Effect: "allow", Methods: []string{"*"}, Groups: []string{"name:missing"}}},
	}, aliases)
	if err == nil {
		t.Fatal("expected an unresolved group reference to be an error")
	}
}

func TestCompileRejectsRolesOnUserRule(t *testing.T) {
	_, err := authz.Compile(config.Policy{
		DefaultEffect: "deny",
		Rules:         []config.Rule{{Name: "r", Effect: "allow", Methods: []string{"*"}, Roles: []string{"Some.Role"}}},
	}, aliases)
	if err == nil || !strings.Contains(err.Error(), "appOnly") {
		t.Fatalf("err = %v, want it to point at appOnly", err)
	}
}

func TestCompileRejectsRuleWithoutMethods(t *testing.T) {
	_, err := authz.Compile(config.Policy{
		DefaultEffect: "deny",
		Rules:         []config.Rule{{Name: "r", Effect: "allow", Groups: []string{admins}}},
	}, aliases)
	if err == nil {
		t.Fatal("expected a rule with no methods to be rejected")
	}
}

func TestCompileRejectsDuplicateRuleNames(t *testing.T) {
	_, err := authz.Compile(config.Policy{
		DefaultEffect: "deny",
		Rules: []config.Rule{
			{Name: "dup", Effect: "allow", Methods: []string{"a"}},
			{Name: "dup", Effect: "deny", Methods: []string{"b"}},
		},
	}, aliases)
	if err == nil {
		t.Fatal("expected duplicate rule names to be rejected")
	}
}

func TestGroupRefsCollectsEveryReference(t *testing.T) {
	refs := authz.GroupRefs(testPolicy())
	found := map[string]bool{}
	for _, r := range refs {
		found[r] = true
	}
	if !found[admins] || !found[readers] {
		t.Errorf("GroupRefs = %v, want both group references", refs)
	}
}

func TestParseRequests(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []authz.Request
	}{
		{"single", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, []authz.Request{{Method: "tools/list"}}},
		{"tool call", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"reboot"}}`,
			[]authz.Request{{Method: "tools/call", Tool: "reboot"}}},
		{"resource", `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///x"}}`,
			[]authz.Request{{Method: "resources/read", Tool: "file:///x"}}},
		{"batch", `[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","id":2,"method":"ping"}]`,
			[]authz.Request{{Method: "tools/list"}, {Method: "ping"}}},
		{"response has no method", `{"jsonrpc":"2.0","id":1,"result":{}}`, nil},
		{"empty", "", nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := authz.ParseRequests([]byte(tc.body))
			if err != nil {
				t.Fatalf("ParseRequests: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %d requests, want %d: %v", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("request %d = %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestParseRequestsRejectsNonJSON(t *testing.T) {
	if _, err := authz.ParseRequests([]byte("not json")); err == nil {
		t.Error("expected an error for a non JSON-RPC body")
	}
}
