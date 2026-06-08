package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// jwk is a single JSON Web Key (subset: RSA and EC public keys).
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	// RSA
	N string `json:"n"`
	E string `json:"e"`
	// EC
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// JWKSClient fetches and caches public keys from a JWKS endpoint, supporting
// transparent key rotation. On a cache miss (unknown kid) it refreshes, but
// no more often than minRefreshInterval to resist forced-refresh DoS.
type JWKSClient struct {
	url        string
	httpClient *http.Client

	mu                sync.RWMutex
	keys              map[string]any // kid -> *rsa.PublicKey | *ecdsa.PublicKey
	lastRefresh       time.Time
	cacheTTL          time.Duration
	minRefreshInterval time.Duration
}

// JWKSOption customises the client.
type JWKSOption func(*JWKSClient)

// WithHTTPClient overrides the HTTP client (e.g. to enforce mTLS to the IdP).
func WithHTTPClient(c *http.Client) JWKSOption {
	return func(j *JWKSClient) { j.httpClient = c }
}

// WithCacheTTL sets how long keys are considered fresh.
func WithCacheTTL(d time.Duration) JWKSOption {
	return func(j *JWKSClient) { j.cacheTTL = d }
}

// NewJWKSClient constructs a JWKS client.
func NewJWKSClient(jwksURL string, opts ...JWKSOption) *JWKSClient {
	c := &JWKSClient{
		url:                jwksURL,
		httpClient:         &http.Client{Timeout: 5 * time.Second},
		keys:               map[string]any{},
		cacheTTL:           15 * time.Minute,
		minRefreshInterval: 1 * time.Minute,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// keyByID returns the cached key for kid, refreshing once if missing or stale.
func (c *JWKSClient) keyByID(ctx context.Context, kid string) (any, error) {
	c.mu.RLock()
	key, ok := c.keys[kid]
	fresh := time.Since(c.lastRefresh) < c.cacheTTL
	c.mu.RUnlock()
	if ok && fresh {
		return key, nil
	}

	if err := c.refresh(ctx); err != nil && !ok {
		return nil, err
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	if key, ok := c.keys[kid]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("%w: unknown kid %q", ErrInvalidToken, kid)
}

// Refresh forces a key reload (used on startup to fail fast).
func (c *JWKSClient) Refresh(ctx context.Context) error { return c.refresh(ctx) }

func (c *JWKSClient) refresh(ctx context.Context) error {
	c.mu.Lock()
	if time.Since(c.lastRefresh) < c.minRefreshInterval && len(c.keys) > 0 {
		c.mu.Unlock()
		return nil // rate-limit refreshes
	}
	c.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return fmt.Errorf("jwks request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("jwks fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks fetch: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("jwks read: %w", err)
	}
	var set jwkSet
	if err := json.Unmarshal(body, &set); err != nil {
		return fmt.Errorf("jwks decode: %w", err)
	}

	parsed := make(map[string]any, len(set.Keys))
	for _, k := range set.Keys {
		pub, err := k.publicKey()
		if err != nil {
			continue // skip unsupported/invalid keys, don't fail the whole set
		}
		parsed[k.Kid] = pub
	}
	if len(parsed) == 0 {
		return errors.New("jwks: no usable keys")
	}

	c.mu.Lock()
	c.keys = parsed
	c.lastRefresh = time.Now()
	c.mu.Unlock()
	return nil
}

// publicKey converts a JWK into a crypto public key.
func (k jwk) publicKey() (any, error) {
	switch k.Kty {
	case "RSA":
		return k.rsaPublicKey()
	case "EC":
		return k.ecPublicKey()
	default:
		return nil, fmt.Errorf("unsupported kty %q", k.Kty)
	}
}

func (k jwk) rsaPublicKey() (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}
	// Pad exponent to 8 bytes for binary.BigEndian.
	var eBuf [8]byte
	copy(eBuf[8-len(eBytes):], eBytes)
	e := int(binary.BigEndian.Uint64(eBuf[:]))
	if e == 0 {
		return nil, errors.New("invalid rsa exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

func (k jwk) ecPublicKey() (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch k.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve %q", k.Crv)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("decode x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("decode y: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}
