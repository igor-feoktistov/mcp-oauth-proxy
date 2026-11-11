package auth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// ErrUnknownKey is returned when no cached JWKS entry matches the token's kid.
var ErrUnknownKey = errors.New("no signing key matches the token key id")

// DiscoveryDocument is the subset of the OpenID Connect discovery metadata we use.
type DiscoveryDocument struct {
	Issuer                 string          `json:"issuer"`
	JWKSURI                string          `json:"jwks_uri"`
	AuthorizationEndpoint  string          `json:"authorization_endpoint"`
	TokenEndpoint          string          `json:"token_endpoint"`
	ScopesSupported        []string        `json:"scopes_supported"`
	ResponseTypesSupported []string        `json:"response_types_supported"`
	GrantTypesSupported    []string        `json:"grant_types_supported"`
	CodeChallengeMethods   []string        `json:"code_challenge_methods_supported"`
	RawJSON                json.RawMessage `json:"-"`
}

type jsonWebKey struct {
	Kid string   `json:"kid"`
	Kty string   `json:"kty"`
	Use string   `json:"use"`
	Alg string   `json:"alg"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

type jsonWebKeySet struct {
	Keys []jsonWebKey `json:"keys"`
}

// KeySet fetches and caches the Entra ID signing keys for a tenant and keeps the
// discovery document (needed for the issuer template) alongside them.
type KeySet struct {
	discoveryURL string
	httpClient   *http.Client
	refresh      time.Duration
	logger       *slog.Logger

	mu          sync.RWMutex
	keys        map[string]crypto.PublicKey
	discovery   *DiscoveryDocument
	lastRefresh time.Time

	// single-flight guard for on-demand refreshes triggered by an unknown kid
	refreshMu   sync.Mutex
	lastForced  time.Time
	minInterval time.Duration
}

// NewKeySet creates a key set bound to an OpenID Connect discovery document.
func NewKeySet(discoveryURL string, httpTimeout, refresh time.Duration, logger *slog.Logger) *KeySet {
	return &KeySet{
		discoveryURL: discoveryURL,
		httpClient:   &http.Client{Timeout: httpTimeout},
		refresh:      refresh,
		logger:       logger,
		keys:         map[string]crypto.PublicKey{},
		minInterval:  30 * time.Second,
	}
}

// Prime performs the initial fetch. It is separate from StartRefresh so that a
// short startup deadline does not also bound the background refresh loop.
func (k *KeySet) Prime(ctx context.Context) error {
	return k.fetch(ctx)
}

// StartRefresh refreshes the signing keys in the background until ctx ends.
func (k *KeySet) StartRefresh(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(k.refresh)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := k.fetch(ctx); err != nil {
					k.logger.Error("jwks refresh failed, serving cached keys", "error", err)
				}
			}
		}
	}()
}

// Key returns the cached public key for kid, refreshing once if it is unknown.
// Key rotation at the IdP therefore does not require a proxy restart.
func (k *KeySet) Key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	k.mu.RLock()
	key, ok := k.keys[kid]
	k.mu.RUnlock()
	if ok {
		return key, nil
	}

	k.refreshMu.Lock()
	if time.Since(k.lastForced) < k.minInterval {
		k.refreshMu.Unlock()
		return nil, ErrUnknownKey
	}
	k.lastForced = time.Now()
	k.refreshMu.Unlock()

	if err := k.fetch(ctx); err != nil {
		return nil, fmt.Errorf("%w: refresh failed: %v", ErrUnknownKey, err)
	}

	k.mu.RLock()
	defer k.mu.RUnlock()
	if key, ok := k.keys[kid]; ok {
		return key, nil
	}
	return nil, ErrUnknownKey
}

// Discovery returns the cached discovery document, or nil before the first fetch.
func (k *KeySet) Discovery() *DiscoveryDocument {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.discovery
}

// Healthy reports whether at least one signing key is cached.
func (k *KeySet) Healthy() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return len(k.keys) > 0
}

func (k *KeySet) fetch(ctx context.Context) error {
	doc, err := k.fetchDiscovery(ctx)
	if err != nil {
		return err
	}
	keys, err := k.fetchJWKS(ctx, doc.JWKSURI)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return errors.New("jwks document contained no usable keys")
	}

	k.mu.Lock()
	k.keys = keys
	k.discovery = doc
	k.lastRefresh = time.Now()
	k.mu.Unlock()

	k.logger.Debug("refreshed signing keys", "count", len(keys), "issuer", doc.Issuer)
	return nil
}

func (k *KeySet) fetchDiscovery(ctx context.Context) (*DiscoveryDocument, error) {
	body, err := k.get(ctx, k.discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("fetch discovery document: %w", err)
	}
	var doc DiscoveryDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse discovery document: %w", err)
	}
	if doc.Issuer == "" || doc.JWKSURI == "" {
		return nil, errors.New("discovery document is missing issuer or jwks_uri")
	}
	doc.RawJSON = body
	return &doc, nil
}

func (k *KeySet) fetchJWKS(ctx context.Context, uri string) (map[string]crypto.PublicKey, error) {
	body, err := k.get(ctx, uri)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	var set jsonWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("parse jwks: %w", err)
	}

	out := make(map[string]crypto.PublicKey, len(set.Keys))
	for _, jwk := range set.Keys {
		if jwk.Kid == "" || (jwk.Use != "" && jwk.Use != "sig") {
			continue
		}
		pub, err := jwk.publicKey()
		if err != nil {
			k.logger.Warn("skipping unusable jwk", "kid", jwk.Kid, "error", err)
			continue
		}
		out[jwk.Kid] = pub
	}
	return out, nil
}

func (k *KeySet) get(ctx context.Context, uri string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := k.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s from %s", resp.Status, uri)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func (j jsonWebKey) publicKey() (crypto.PublicKey, error) {
	if j.Kty != "RSA" {
		return nil, fmt.Errorf("unsupported key type %q", j.Kty)
	}
	if j.N != "" && j.E != "" {
		nBytes, err := base64.RawURLEncoding.DecodeString(j.N)
		if err != nil {
			return nil, fmt.Errorf("decode modulus: %w", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(j.E)
		if err != nil {
			return nil, fmt.Errorf("decode exponent: %w", err)
		}
		if len(eBytes) == 0 || len(eBytes) > 8 {
			return nil, errors.New("invalid exponent length")
		}
		padded := make([]byte, 8)
		copy(padded[8-len(eBytes):], eBytes)
		exp := binary.BigEndian.Uint64(padded)
		if exp == 0 || exp > 1<<31-1 {
			return nil, errors.New("exponent out of range")
		}
		key := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(exp)}
		if key.N.Sign() <= 0 {
			return nil, errors.New("invalid modulus")
		}
		return key, nil
	}
	if len(j.X5c) > 0 {
		der, err := base64.StdEncoding.DecodeString(j.X5c[0])
		if err != nil {
			return nil, fmt.Errorf("decode x5c: %w", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parse x5c certificate: %w", err)
		}
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("x5c certificate does not carry an RSA key")
		}
		return pub, nil
	}
	return nil, errors.New("jwk has neither n/e nor x5c")
}
