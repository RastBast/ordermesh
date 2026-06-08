package auth

import "strings"

// rolePermissions is the RBAC model: a role grants a set of permissions.
// In a larger system this would come from a policy service (OPA) — here it is
// a static, auditable map. ABAC checks (".own" vs ".any") are enforced at the
// handler level using the request's resource owner.
var rolePermissions = map[string][]Permission{
	"customer": {
		PermOrdersCreate,
		PermOrdersReadOwn,
		PermOrdersUpdateOwn,
	},
	"support": {
		PermOrdersReadAny,
		PermOrdersListAny,
	},
	"admin": {
		PermOrdersCreate,
		PermOrdersReadOwn,
		PermOrdersReadAny,
		PermOrdersUpdateOwn,
		PermOrdersUpdateAny,
		PermOrdersListAny,
	},
}

// buildPrincipal expands roles into permissions and unions them with any
// explicit OAuth2 scopes present on the token.
func buildPrincipal(c *Claims) *Principal {
	perms := make(map[Permission]struct{})

	for _, role := range c.Roles {
		for _, p := range rolePermissions[strings.ToLower(role)] {
			perms[p] = struct{}{}
		}
	}

	// Explicit scopes augment role-derived permissions.
	for _, s := range strings.Fields(c.Scope) {
		perms[Permission(s)] = struct{}{}
	}

	return &Principal{
		Subject:     c.Subject,
		Roles:       c.Roles,
		permissions: perms,
	}
}
