package auth

import (
	"context"
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

// testIDP spins up an in-memory identity provider: a JWKS endpoint backed by a
// freshly generated RSA key, plus a token minting helper.
type testIDP struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string
}

func newTestIDP(t *testing.T) *testIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &testIDP{key: key, kid: "test-key-1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		pub := key.Public().(*rsa.PublicKey)
		n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{
				{"kty": "RSA", "kid": idp.kid, "use": "sig", "alg": "RS256", "n": n, "e": e},
			},
		})
	})
	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

func (idp *testIDP) jwksURL() string { return idp.server.URL + "/jwks.json" }

func (idp *testIDP) mint(t *testing.T, claims Claims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = idp.kid
	signed, err := token.SignedString(idp.key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func baseClaims() Claims {
	now := time.Now()
	return Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "https://idp.example.com",
			Audience:  jwt.ClaimStrings{"order-service"},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
		Roles: []string{"customer"},
	}
}

func newVerifier(t *testing.T, idp *testIDP) *Verifier {
	jwks := NewJWKSClient(idp.jwksURL())
	v := NewVerifier(jwks, Config{
		JWKSURL:  idp.jwksURL(),
		Issuer:   "https://idp.example.com",
		Audience: "order-service",
	})
	if err := v.WarmUp(context.Background()); err != nil {
		t.Fatalf("warmup: %v", err)
	}
	return v
}

func TestVerify_ValidToken(t *testing.T) {
	t.Parallel()
	idp := newTestIDP(t)
	v := newVerifier(t, idp)

	tok := idp.mint(t, baseClaims())
	p, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if p.Subject != "user-123" {
		t.Fatalf("subject = %q", p.Subject)
	}
	if !p.Has(PermOrdersCreate) {
		t.Fatal("customer role should grant orders.create")
	}
	if p.Has(PermOrdersReadAny) {
		t.Fatal("customer must NOT have orders.read.any")
	}
}

func TestVerify_Expired(t *testing.T) {
	t.Parallel()
	idp := newTestIDP(t)
	v := newVerifier(t, idp)

	c := baseClaims()
	c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Minute))
	c.IssuedAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
	tok := idp.mint(t, c)

	if _, err := v.Verify(context.Background(), tok); err != ErrTokenExpired {
		t.Fatalf("want ErrTokenExpired, got %v", err)
	}
}

func TestVerify_WrongAudience(t *testing.T) {
	t.Parallel()
	idp := newTestIDP(t)
	v := newVerifier(t, idp)

	c := baseClaims()
	c.Audience = jwt.ClaimStrings{"some-other-service"}
	tok := idp.mint(t, c)

	if _, err := v.Verify(context.Background(), tok); err != ErrInvalidAudience {
		t.Fatalf("want ErrInvalidAudience, got %v", err)
	}
}

func TestVerify_WrongIssuer(t *testing.T) {
	t.Parallel()
	idp := newTestIDP(t)
	v := newVerifier(t, idp)

	c := baseClaims()
	c.Issuer = "https://evil.example.com"
	tok := idp.mint(t, c)

	if _, err := v.Verify(context.Background(), tok); err != ErrInvalidIssuer {
		t.Fatalf("want ErrInvalidIssuer, got %v", err)
	}
}

func TestVerify_AlgConfusionRejected(t *testing.T) {
	t.Parallel()
	idp := newTestIDP(t)
	v := newVerifier(t, idp)

	// Attacker forges an HS256 token using the (public) modulus as the secret.
	c := baseClaims()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	token.Header["kid"] = idp.kid
	pub := idp.key.Public().(*rsa.PublicKey)
	forged, err := token.SignedString(pub.N.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), forged); err == nil {
		t.Fatal("alg-confusion token must be rejected")
	}
}

func TestVerify_UnknownKid(t *testing.T) {
	t.Parallel()
	idp := newTestIDP(t)
	v := newVerifier(t, idp)

	c := baseClaims()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	token.Header["kid"] = "nonexistent"
	signed, _ := token.SignedString(idp.key)

	if _, err := v.Verify(context.Background(), signed); err == nil {
		t.Fatal("unknown kid must fail")
	}
}

func TestVerify_AdminRoleExpandsPermissions(t *testing.T) {
	t.Parallel()
	idp := newTestIDP(t)
	v := newVerifier(t, idp)

	c := baseClaims()
	c.Roles = []string{"admin"}
	tok := idp.mint(t, c)
	p, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	if !p.HasAny(PermOrdersReadAny, PermOrdersUpdateAny, PermOrdersListAny) {
		t.Fatal("admin should have broad permissions")
	}
}
