// Package authz applies MCP-aware authorization rules to JSON-RPC requests.
//
// Authorization is driven entirely by directory group membership. Rules name
// group object ids; delegated scopes play no part in the decision. Rules are
// evaluated in file order, first match wins, so the outcome never depends on
// the order in which the directory happened to return a user's groups.
package authz

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/example/mcp-oauth-proxy/internal/auth"
	"github.com/example/mcp-oauth-proxy/internal/config"
	"github.com/example/mcp-oauth-proxy/internal/graph"
)

// Policy is a compiled, ordered rule list.
type Policy struct {
	defaultEffect string
	rules         []compiledRule
}

type compiledRule struct {
	name    string
	allow   bool
	methods []string
	tools   []string
	groups  []string
	roles   []string
	appOnly bool
}

// Decision is the outcome of evaluating a policy against one JSON-RPC request.
type Decision struct {
	Allowed bool
	Rule    string
	Reason  string
}

// Request is the MCP call being authorized.
type Request struct {
	Method string
	Tool   string
}

// rulesDocument is the schema of a standalone policy rules file.
type rulesDocument struct {
	DefaultEffect string        `yaml:"defaultEffect"`
	Rules         []config.Rule `yaml:"rules"`
}

// LoadRules reads policy rules from the main configuration or, when
// authorization.policy.rulesFile is set, from that separate document.
func LoadRules(cfg *config.Config) (config.Policy, error) {
	p := cfg.Authorization.Policy
	path := cfg.RulesPath()
	if path == "" {
		return p, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return p, fmt.Errorf("read policy rules file: %w", err)
	}
	var doc rulesDocument
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		return p, fmt.Errorf("parse policy rules file %s: %w", path, err)
	}
	if doc.DefaultEffect != "" {
		p.DefaultEffect = strings.ToLower(doc.DefaultEffect)
	}
	p.Rules = doc.Rules
	for i := range p.Rules {
		if p.Rules[i].Effect == "" {
			p.Rules[i].Effect = "allow"
		}
		p.Rules[i].Effect = strings.ToLower(p.Rules[i].Effect)
	}
	return p, nil
}

// GroupRefs returns every group reference used by the policy, so they can be
// resolved to object ids alongside authorization.oauth2.allowGroups.
func GroupRefs(p config.Policy) []string {
	var refs []string
	for _, r := range p.Rules {
		refs = append(refs, r.Groups...)
	}
	return refs
}

// Compile validates the policy and replaces every group reference with the
// object id it resolved to at startup.
func Compile(p config.Policy, aliases map[string]string) (*Policy, error) {
	effect := strings.ToLower(p.DefaultEffect)
	if effect != "allow" && effect != "deny" {
		return nil, fmt.Errorf("authorization.policy.defaultEffect must be allow or deny, got %q", p.DefaultEffect)
	}

	out := &Policy{defaultEffect: effect}
	names := map[string]bool{}
	for i, r := range p.Rules {
		name := r.Name
		if name == "" {
			name = fmt.Sprintf("rule-%d", i)
		}
		if names[name] {
			return nil, fmt.Errorf("duplicate policy rule name %q", name)
		}
		names[name] = true

		if r.Effect != "allow" && r.Effect != "deny" {
			return nil, fmt.Errorf("rule %q: effect must be allow or deny, got %q", name, r.Effect)
		}
		if len(r.Methods) == 0 {
			return nil, fmt.Errorf("rule %q: at least one method pattern is required", name)
		}
		if r.AppOnly && len(r.Groups) > 0 {
			return nil, fmt.Errorf("rule %q: appOnly rules cannot match groups, because app-only tokens have no user", name)
		}
		if !r.AppOnly && len(r.Roles) > 0 {
			return nil, fmt.Errorf("rule %q: roles only apply to app-only callers, set appOnly: true", name)
		}

		cr := compiledRule{
			name:    name,
			allow:   r.Effect == "allow",
			methods: r.Methods,
			tools:   r.Tools,
			roles:   r.Roles,
			appOnly: r.AppOnly,
		}
		for _, ref := range r.Groups {
			id, ok := aliases[strings.TrimSpace(ref)]
			if !ok {
				return nil, fmt.Errorf("rule %q: group reference %q was not resolved to an object id", name, ref)
			}
			cr.groups = append(cr.groups, id)
		}
		out.rules = append(out.rules, cr)
	}
	return out, nil
}

// Evaluate returns the decision for a single MCP request made by a principal.
func (p *Policy) Evaluate(principal *auth.Principal, req Request) Decision {
	for _, r := range p.rules {
		if !r.matches(principal, req) {
			continue
		}
		return Decision{
			Allowed: r.allow,
			Rule:    r.name,
			Reason:  fmt.Sprintf("rule %q", r.name),
		}
	}
	return Decision{
		Allowed: p.defaultEffect == "allow",
		Rule:    "default",
		Reason:  fmt.Sprintf("default effect %q", p.defaultEffect),
	}
}

func (r compiledRule) matches(p *auth.Principal, req Request) bool {
	if !matchAny(r.methods, req.Method) {
		return false
	}
	if len(r.tools) > 0 {
		// Tool patterns only constrain calls that actually name a tool.
		if req.Tool == "" || !matchAny(r.tools, req.Tool) {
			return false
		}
	}
	// An appOnly rule never applies to a user, and vice versa, so a deny rule
	// written for daemons cannot accidentally lock out interactive callers.
	if r.appOnly != p.AppOnly {
		return false
	}
	if r.appOnly {
		if len(r.roles) == 0 {
			return true
		}
		for _, role := range r.roles {
			if p.HasRole(role) {
				return true
			}
		}
		return false
	}
	// A rule with no groups matches every authenticated user, which makes
	// blanket deny rules easy to express.
	if len(r.groups) == 0 {
		return true
	}
	for _, g := range r.groups {
		if p.HasGroup(g) {
			return true
		}
	}
	return false
}

// matchAny supports exact matches and a single trailing `*` wildcard.
func matchAny(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if pattern == "*" {
			return true
		}
		if strings.HasSuffix(pattern, "*") {
			if strings.HasPrefix(strings.ToLower(value), strings.ToLower(strings.TrimSuffix(pattern, "*"))) {
				return true
			}
			continue
		}
		if strings.EqualFold(pattern, value) {
			return true
		}
	}
	return false
}

// ResolveGroupRefs maps every group reference used by the configuration to a
// group object id, looking display-name aliases up in the directory once at
// startup. Request-time matching is always on object ids.
func ResolveGroupRefs(refs []string, lookup func(string) ([]string, error)) (map[string]string, error) {
	out := map[string]string{}
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref == "" || out[ref] != "" {
			continue
		}
		if graph.IsGUID(ref) {
			out[ref] = strings.ToLower(ref)
			continue
		}
		if !graph.IsAlias(ref) {
			return nil, fmt.Errorf("group reference %q must be a group object id (GUID) or %q followed by a display name",
				ref, graph.AliasPrefix)
		}
		ids, err := lookup(graph.AliasName(ref))
		if err != nil {
			return nil, err
		}
		if len(ids) != 1 {
			return nil, fmt.Errorf("group reference %q resolved to %d groups", ref, len(ids))
		}
		out[ref] = strings.ToLower(ids[0])
	}
	return out, nil
}

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	ID      json.RawMessage `json:"id"`
	Params  struct {
		Name string `json:"name"`
		URI  string `json:"uri"`
	} `json:"params"`
}

// ParseRequests extracts the MCP calls from a JSON-RPC body, transparently
// handling both single messages and batches. A body that is not JSON-RPC (for
// example an SSE GET with no body) yields no requests and no error.
func ParseRequests(body []byte) ([]Request, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil, nil
	}

	decode := func(raw []byte) (Request, bool) {
		var msg jsonRPCRequest
		if err := json.Unmarshal(raw, &msg); err != nil {
			return Request{}, false
		}
		if msg.Method == "" {
			// Responses and errors carry no method and need no authorization.
			return Request{}, false
		}
		tool := msg.Params.Name
		if tool == "" {
			tool = msg.Params.URI
		}
		return Request{Method: msg.Method, Tool: tool}, true
	}

	if trimmed[0] == '[' {
		var batch []json.RawMessage
		if err := json.Unmarshal([]byte(trimmed), &batch); err != nil {
			return nil, fmt.Errorf("malformed JSON-RPC batch: %w", err)
		}
		out := make([]Request, 0, len(batch))
		for _, raw := range batch {
			if req, ok := decode(raw); ok {
				out = append(out, req)
			}
		}
		return out, nil
	}

	if trimmed[0] != '{' {
		return nil, fmt.Errorf("body is not a JSON-RPC message")
	}
	req, ok := decode([]byte(trimmed))
	if !ok {
		return nil, nil
	}
	return []Request{req}, nil
}
