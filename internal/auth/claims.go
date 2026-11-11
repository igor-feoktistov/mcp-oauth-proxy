package auth

import (
	"encoding/json"
	"fmt"
)

// UnmarshalJSON decodes the well-known Entra ID claims into typed fields while
// retaining every claim in Extra, so that a configurable userLoginClaim or
// groupsClaim can name a claim this struct does not model.
func (c *entraClaims) UnmarshalJSON(data []byte) error {
	type alias entraClaims
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*c = entraClaims(a)
	if err := json.Unmarshal(data, &c.Extra); err != nil {
		return fmt.Errorf("decode token claims: %w", err)
	}
	return nil
}

// stringClaim returns a claim as a string, or "" when it is absent or not a string.
func (c *entraClaims) stringClaim(name string) string {
	if name == "" {
		return ""
	}
	s, _ := c.Extra[name].(string)
	return s
}

// stringsClaim returns a claim as a string slice, accepting both a JSON array
// and a single string value.
func (c *entraClaims) stringsClaim(name string) []string {
	if name == "" {
		return nil
	}
	switch v := c.Extra[name].(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	default:
		return nil
	}
}
