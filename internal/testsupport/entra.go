// Package testsupport provides a fake Microsoft Entra ID tenant (discovery
// document, JWKS and token signing) for use in tests.
package testsupport

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Well-known identifiers used across the test suites.
const (
	Tenant   = "11111111-1111-1111-1111-111111111111"
	Kid      = "test-key-1"
	Audience = "api://22222222-2222-2222-2222-222222222222"
	ClientID = "33333333-3333-3333-3333-333333333333"
)

// Entra is a throwaway OpenID Connect provider that mimics the endpoints the
// proxy consumes from login.microsoftonline.com.
type Entra struct {
	*httptest.Server
	Key *rsa.PrivateKey
}

// NewEntra starts a fake tenant and registers cleanup with t.
func NewEntra(t *testing.T) *Entra {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	e := &Entra{Key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/"+Tenant+"/v2.0/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                e.URL + "/" + Tenant + "/v2.0",
			"jwks_uri":                              e.URL + "/" + Tenant + "/discovery/v2.0/keys",
			"token_endpoint":                        e.URL + "/" + Tenant + "/oauth2/v2.0/token",
			"authorization_endpoint":                e.URL + "/" + Tenant + "/oauth2/v2.0/authorize",
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
			"code_challenge_methods_supported":      []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_post", "none"},
		})
	})
	mux.HandleFunc("/"+Tenant+"/discovery/v2.0/keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": Kid,
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	})

	e.Server = httptest.NewServer(mux)
	t.Cleanup(e.Close)
	return e
}

// Issuer is the v2.0 issuer identifier of the fake tenant.
func (e *Entra) Issuer() string { return e.URL + "/" + Tenant + "/v2.0" }

// Claims builds a valid delegated-access-token claim set, applying any mutators.
func (e *Entra) Claims(mutate ...func(jwt.MapClaims)) jwt.MapClaims {
	c := jwt.MapClaims{
		"iss":                e.Issuer(),
		"aud":                Audience,
		"tid":                Tenant,
		"oid":                "user-object-id",
		"sub":                "subject-123",
		"scp":                "mcp.read mcp.invoke",
		"preferred_username": "igor@contoso.com",
		"name":               "Igor F",
		"azp":                ClientID,
		"ver":                "2.0",
		"iat":                time.Now().Add(-time.Minute).Unix(),
		"nbf":                time.Now().Add(-time.Minute).Unix(),
		"exp":                time.Now().Add(time.Hour).Unix(),
	}
	for _, m := range mutate {
		m(c)
	}
	return c
}

// Sign issues an RS256 access token with the tenant's signing key.
func (e *Entra) Sign(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = Kid
	signed, err := tok.SignedString(e.Key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

// Token is a shorthand for signing the default claim set with mutators applied.
func (e *Entra) Token(t *testing.T, mutate ...func(jwt.MapClaims)) string {
	t.Helper()
	return e.Sign(t, e.Claims(mutate...))
}
