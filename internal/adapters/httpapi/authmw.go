package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/RastBast/ordermesh-/internal/security/auth"
	"github.com/RastBast/ordermesh-/internal/security/ratelimit"
)

// TokenVerifier is the auth dependency (satisfied by *auth.Verifier).
type TokenVerifier interface {
	Verify(ctx context.Context, token string) (*auth.Principal, error)
}

// AuthMiddleware enforces authentication: every request must carry a valid
// Bearer JWT verified against JWKS. Per Zero Trust, there is no implicit trust
// from network location — even intra-mesh calls present a token.
func AuthMiddleware(v TokenVerifier, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := bearerToken(r)
			if raw == "" {
				writeError(w, http.StatusUnauthorized, "unauthorized", "missing bearer token")
				return
			}
			principal, err := v.Verify(r.Context(), raw)
			if err != nil {
				// Do not leak which check failed in detail to the client.
				log.WarnContext(r.Context(), "token verification failed", slog.Any("err", err))
				writeError(w, http.StatusUnauthorized, "unauthorized", "invalid or expired token")
				return
			}
			ctx := auth.WithPrincipal(r.Context(), principal)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// DevAuthMiddleware injects a full-permission principal when authentication is
// disabled (local dev only). It grants every order permission, including
// *.any, so the request body's customer_id is honoured and ownership checks
// pass. Production never uses this — config validation forbids AUTH_ENABLED=false
// in prod.
func DevAuthMiddleware(log *slog.Logger) func(http.Handler) http.Handler {
	principal := auth.NewPrincipal(
		"dev",
		auth.PermOrdersCreate,
		auth.PermOrdersReadOwn,
		auth.PermOrdersReadAny,
		auth.PermOrdersUpdateOwn,
		auth.PermOrdersUpdateAny,
		auth.PermOrdersListAny,
	)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := auth.WithPrincipal(r.Context(), principal)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequirePermission is a per-route guard for coarse RBAC. Fine-grained ABAC
// (".own" ownership) is enforced inside handlers where the resource is known.
func RequirePermission(perms ...auth.Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := auth.FromContext(r.Context())
			if p == nil || !p.HasAny(perms...) {
				writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// PerPrincipalRateLimit applies a local token bucket then a distributed quota,
// keyed by the authenticated subject (falling back to client IP). Layered
// limiting protects against both single-caller bursts and global overload.
func PerPrincipalRateLimit(local *ratelimit.Local, dist ratelimit.DistributedLimiter, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := rateKey(r)

			if !local.Allow(key) {
				w.Header().Set("Retry-After", "1")
				writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
				return
			}

			if dist != nil {
				ctx, cancel := context.WithTimeout(r.Context(), 100*time.Millisecond)
				allowed, retry, err := dist.Allow(ctx, key)
				cancel()
				if err != nil {
					// Fail open on limiter outage, but log it — availability over
					// strictness for a best-effort secondary control.
					log.WarnContext(r.Context(), "distributed rate limiter error", slog.Any("err", err))
				} else if !allowed {
					w.Header().Set("Retry-After", retryAfterSeconds(retry))
					writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

func rateKey(r *http.Request) string {
	if p := auth.FromContext(r.Context()); p != nil && p.Subject != "" {
		return "sub:" + p.Subject
	}
	return "ip:" + clientIP(r)
}

func clientIP(r *http.Request) string {
	// RealIP middleware has already normalised RemoteAddr from XFF when trusted.
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	return host
}

func retryAfterSeconds(d time.Duration) string {
	s := int(d.Seconds())
	if s < 1 {
		s = 1
	}
	return strconvItoa(s)
}

func strconvItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
