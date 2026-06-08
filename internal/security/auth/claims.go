// Package auth implements Zero-Trust authentication and authorization:
// asymmetric JWT verification via a remote JWKS endpoint, a principal model
// carrying scopes/roles, and RBAC/ABAC permission checks.
package auth

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

// Permission is a fine-grained capability, e.g. "orders.create" or
// "orders.read.own". Authorization is expressed in terms of these, never in
// terms of "is authenticated".
type Permission string

const (
	PermOrdersCreate   Permission = "orders.create"
	PermOrdersReadOwn  Permission = "orders.read.own"
	PermOrdersReadAny  Permission = "orders.read.any"
	PermOrdersUpdateOwn Permission = "orders.update.own"
	PermOrdersUpdateAny Permission = "orders.update.any"
	PermOrdersListAny  Permission = "orders.list.any"
)

var (
	ErrNoToken          = errors.New("auth: missing bearer token")
	ErrInvalidToken     = errors.New("auth: invalid token")
	ErrTokenExpired     = errors.New("auth: token expired")
	ErrInvalidAudience  = errors.New("auth: invalid audience")
	ErrInvalidIssuer    = errors.New("auth: invalid issuer")
	ErrForbidden        = errors.New("auth: insufficient permissions")
	ErrSubjectMissing   = errors.New("auth: subject missing")
)

// Claims is the validated JWT body. We use registered claims plus scopes and
// roles. Scopes map directly to Permissions; roles are expanded via RBAC.
type Claims struct {
	jwt.RegisteredClaims
	Scope string   `json:"scope,omitempty"` // space-delimited OAuth2 scopes
	Roles []string `json:"roles,omitempty"`
	Email string   `json:"email,omitempty"` // treated as PII; never logged raw
}

// Principal is the authenticated caller derived from validated claims. It is
// the ABAC subject — handlers make decisions against it.
type Principal struct {
	Subject     string
	Roles       []string
	permissions map[Permission]struct{}
}

// NewPrincipal builds a principal with an explicit permission set. Useful for
// programmatic callers (service accounts) and tests.
func NewPrincipal(subject string, perms ...Permission) *Principal {
	m := make(map[Permission]struct{}, len(perms))
	for _, p := range perms {
		m[p] = struct{}{}
	}
	return &Principal{Subject: subject, permissions: m}
}

// Has reports whether the principal holds the permission.
func (p *Principal) Has(perm Permission) bool {
	if p == nil {
		return false
	}
	_, ok := p.permissions[perm]
	return ok
}

// HasAny reports whether the principal holds at least one of the permissions.
func (p *Principal) HasAny(perms ...Permission) bool {
	for _, perm := range perms {
		if p.Has(perm) {
			return true
		}
	}
	return false
}
