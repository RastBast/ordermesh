package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// Verifier validates JWTs: asymmetric signature via JWKS, issuer, audience,
// expiry and not-before, then expands claims into a Principal.
type Verifier struct {
	jwks     *JWKSClient
	issuer   string
	audience string
	parser   *jwt.Parser
}

// Config configures the verifier.
type Config struct {
	JWKSURL  string
	Issuer   string
	Audience string
}

// NewVerifier builds a verifier with a strict algorithm allowlist (asymmetric
// only — HMAC is rejected to prevent alg-confusion / key-substitution attacks).
func NewVerifier(jwks *JWKSClient, cfg Config) *Verifier {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}),
		jwt.WithIssuer(cfg.Issuer),
		jwt.WithAudience(cfg.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(0),
	)
	return &Verifier{jwks: jwks, issuer: cfg.Issuer, audience: cfg.Audience, parser: parser}
}

// WarmUp pre-loads JWKS so the service fails fast if the IdP is unreachable.
func (v *Verifier) WarmUp(ctx context.Context) error {
	return v.jwks.Refresh(ctx)
}

// Verify parses and fully validates the token string, returning a Principal.
func (v *Verifier) Verify(ctx context.Context, tokenString string) (*Principal, error) {
	if tokenString == "" {
		return nil, ErrNoToken
	}

	claims := &Claims{}
	keyFunc := func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing kid header")
		}
		return v.jwks.keyByID(ctx, kid)
	}

	token, err := v.parser.ParseWithClaims(tokenString, claims, keyFunc)
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			return nil, ErrTokenExpired
		case errors.Is(err, jwt.ErrTokenInvalidAudience):
			return nil, ErrInvalidAudience
		case errors.Is(err, jwt.ErrTokenInvalidIssuer):
			return nil, ErrInvalidIssuer
		default:
			return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
		}
	}
	if !token.Valid {
		return nil, ErrInvalidToken
	}
	if claims.Subject == "" {
		return nil, ErrSubjectMissing
	}

	return buildPrincipal(claims), nil
}
